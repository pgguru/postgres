/*-------------------------------------------------------------------------
 *
 * bufenc.c
 *
 * Copyright (c) 2020, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/crypto/bufenc.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "miscadmin.h"
#include "lib/stringinfo.h"

#include "access/gist.h"
#include "access/xlog.h"
#include "crypto/bufenc.h"
#include "storage/bufpage.h"
#include "storage/fd.h"

extern XLogRecPtr LSNForEncryption(bool use_wal_lsn);

/*
 * We use the page LSN, page number, and permanent-bit to indicate if a fake
 * LSN was used to create a nonce for each page.
 */
#define BUFENC_IV_SIZE		16

static unsigned char buf_encryption_iv[BUFENC_IV_SIZE];
static int file_encryption_tag_size = 0;
static int file_encryption_page_size = 0;
static int file_encryption_method = DISABLED_ENCRYPTION_METHOD;

/* this private struct is used to store additional info about the page used to validate specific other pages */
typedef struct AdditionalAuthenticatedData {
	unsigned char data[PageEncryptOffset]; /* copy the unencrypted page header info */
	RelFileNumber fileno;
	BlockNumber blkNo;
} AdditionalAuthenticatedData;

StaticAssertDecl((MAXALIGN(sizeof(AdditionalAuthenticatedData)) == sizeof(AdditionalAuthenticatedData)),
				 "AdditionalAuthenticatedData must be fully padded");

AdditionalAuthenticatedData auth_data;

PgCipherCtx *BufEncCtx = NULL;
PgCipherCtx *BufDecCtx = NULL;

static void set_buffer_encryption_iv(Page page, BlockNumber blkno,
									 bool relation_is_permanent);
static void
setup_additional_authenticated_data(Page page, BlockNumber blkno,
									bool relation_is_permanent, RelFileNumber fileno);


void
InitializeBufferEncryption(int init_file_encryption_method)
{
	const CryptoKey *key;

#ifndef FRONTEND
	if (init_file_encryption_method == DISABLED_ENCRYPTION_METHOD)
		return;

	key = KmgrGetKey(KMGR_KEY_ID_REL);
#else
	return;
#endif
	file_encryption_method = init_file_encryption_method;

	BufEncCtx = pg_cipher_ctx_create(EncryptionAlgorithm(file_encryption_method),
									 (unsigned char *) key->key,
									 EncryptionBlockLength(file_encryption_method),
									 true);
	if (!BufEncCtx)
		my_error("cannot initialize encryption context: method: %d; len: %d", file_encryption_method, key->klen);

	BufDecCtx = pg_cipher_ctx_create(EncryptionAlgorithm(file_encryption_method),
									 (unsigned char *) key->key,
									 EncryptionBlockLength(file_encryption_method),
									 false);
	if (!BufDecCtx)
		my_error("cannot initialize decryption context");

	file_encryption_tag_size = SizeOfEncryptionTag(file_encryption_method);
	file_encryption_page_size = SizeOfPageEncryption(file_encryption_method);
}

/* Encrypt the given page with the relation key */
void
EncryptPage(Page page, bool relation_is_permanent, BlockNumber blkno, RelFileNumber fileno)
{
	unsigned char *ptr = (unsigned char *) page + PageEncryptOffset;
	bool		is_gist_page_or_similar;
	int			enclen;
	unsigned char	*tag = NULL, *aad = NULL;
	int			aadlen = 0;

	Assert(BufEncCtx != NULL);

	/*
	 * Permanent pages have valid LSNs, and non-permanent pages usually have
	 * invalid (not set) LSNs.  (One exception are GiST fake LSNs, see below.)
	 * However, we need valid ones on all pages for encryption.  There are too
	 * many places that set the page LSN for permanent pages to do the same
	 * for non-permanent pages, so we just set it here.
	 *
	 * Also, while permanent relations get new LSNs every time the page is
	 * modified, for non-permanent relations do not, so we just update the LSN
	 * here before it is encrypted.
	 *
	 * GiST indexes uses LSNs, which are also stored in NSN fields, to detect
	 * page splits.  Therefore, we allow the GiST code to assign LSNs and we
	 * don't change them here.
	 */

	/* Permanent relations should already have valid LSNs. */
	Assert(!XLogRecPtrIsInvalid(PageGetLSN(page)) || !relation_is_permanent);

	/*
	 * Check if the page has a special size == GISTPageOpaqueData, a valid
	 * GIST_PAGE_ID, no invalid GiST flag bits are set, and a valid LSN.  This
	 * is true for all GiST pages, and perhaps a few pages that are not.  The
	 * only downside of guessing wrong is that we might not update the LSN for
	 * some non-permanent relation page changes, and therefore reuse the IV,
	 * which seems acceptable.
	 */
	is_gist_page_or_similar =
		(PageGetSpecialSize(page) == MAXALIGN(sizeof(GISTPageOpaqueData)) &&
		 GistPageGetOpaque(page)->gist_page_id == GIST_PAGE_ID &&
		 (GistPageGetOpaque(page)->flags & ~GIST_FLAG_BITMASK) == 0 &&
		 !XLogRecPtrIsInvalid(PageGetLSN(page)));

	if (!relation_is_permanent && !is_gist_page_or_similar)
		PageSetLSN(page, LSNForEncryption(relation_is_permanent));

	set_buffer_encryption_iv(page, blkno, relation_is_permanent);

	/* setup tag and AAD */
	if (file_encryption_tag_size > 0)
	{
		tag = (unsigned char*)page + cluster_block_size - file_encryption_tag_size;
		setup_additional_authenticated_data(page, blkno, relation_is_permanent, fileno);
		aad = (unsigned char *)&auth_data;
		aadlen = sizeof(AdditionalAuthenticatedData);
	}

	if (unlikely(!pg_cipher_encrypt(BufEncCtx, EncryptionAlgorithm(file_encryption_method),
									(const unsigned char *) ptr,	/* input  */
									file_encryption_page_size,
									ptr,	/* length */
									&enclen,	/* resulting length */
									buf_encryption_iv,	/* iv */
									BUFENC_IV_SIZE,
									aad, aadlen, /* AAD */
									tag, file_encryption_tag_size)))
		my_error("cannot encrypt page %u", blkno);

	Assert(enclen == file_encryption_page_size);
}

/* Decrypt the given page with the relation key */
void
DecryptPage(Page page, bool relation_is_permanent, BlockNumber blkno, RelFileNumber fileno)
{
	unsigned char *ptr = (unsigned char *) page + PageEncryptOffset;
	int			enclen;
	unsigned char	*tag = NULL, *aad = NULL;
	int			aadlen = 0;

	Assert(BufDecCtx != NULL);

	set_buffer_encryption_iv(page, blkno, relation_is_permanent);

	/* setup tag and AAD */
	if (file_encryption_tag_size > 0)
	{
		tag = (unsigned char*)page + cluster_block_size - file_encryption_tag_size;
		setup_additional_authenticated_data(page, blkno, relation_is_permanent, fileno);
		aad = (unsigned char *)&auth_data;
		aadlen = sizeof(AdditionalAuthenticatedData);
	}

	if (unlikely(!pg_cipher_decrypt(BufDecCtx, EncryptionAlgorithm(file_encryption_method),
									(const unsigned char *) ptr,	/* input  */
									file_encryption_page_size,
									ptr,	/* output */
									&enclen,	/* resulting length */
									buf_encryption_iv,	/* iv */
									BUFENC_IV_SIZE,
									aad, aadlen, /* AAD */
									tag, file_encryption_tag_size)))
		my_error("cannot decrypt page %u", blkno);

	Assert(enclen == file_encryption_page_size);
}

/* Construct iv for the given page */
static void
set_buffer_encryption_iv(Page page, BlockNumber blkno,
						 bool relation_is_permanent)
{
	unsigned char *p = buf_encryption_iv;

	MemSet(buf_encryption_iv, 0, BUFENC_IV_SIZE);

	/* page lsn (8 byte) */
	memcpy(p, &((PageHeader) page)->pd_lsn, sizeof(PageXLogRecPtr));
	p += sizeof(PageXLogRecPtr);

	/* block number (4 byte) */
	memcpy(p, &blkno, sizeof(BlockNumber));
	p += sizeof(BlockNumber);

	/*
	 * Mark use of fake LSNs in IV so if the real and fake LSN counters
	 * overlap, the IV will remain unique.  XXX Is there a better value?
	 */
	if (!relation_is_permanent)
		*p++ = 0x80;

}

/* setup aad for given page; private struct so we don't care */
static void
setup_additional_authenticated_data(Page page, BlockNumber blkno,
									bool relation_is_permanent, RelFileNumber fileno)
{
	/* snarf the existing unencrypted bits of the page header */
	memcpy(&auth_data.data, page, PageEncryptOffset);
	auth_data.fileno = fileno;
	auth_data.blkNo = blkno;
}
