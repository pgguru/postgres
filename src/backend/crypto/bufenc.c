/*-------------------------------------------------------------------------
 *
 * bufenc.c
 *
 * Copyright (c) 2024, PostgreSQL Global Development Group
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
#include "access/xlog_internal.h"
#include "crypto/bufenc.h"
#include "storage/bufpage.h"
#include "storage/fd.h"

/* here we define a local cache of IV counters we can use to track our own
 * internal counter so we don't need to hit pg_control's uint64 atomic value
 * (even though we don't need a lock).  This gets allocated in batches, defined
 * by the number of bits in IV_MASK_BITS, which we also shift when getting a new
 * atomic from pg_control. This has the effect of every backend getting a new
 * batch from a global counter, so each backend now has a private batch which it
 * can increment with no concerns about interfering with other backends or
 * reusing the same number */

#define IV_SIZE 16
#define IV_MASK_BITS 10
#define IV_COUNTER_MASK ((1<<IV_MASK_BITS) - 1)

#ifdef FRONTEND
extern uint64 IncrementIVCounter(void);
uint64 IncrementIVCounter(void) { return 0; };
#else
extern uint64 IncrementIVCounter(void);
#endif

static uint64 _iv_counter = 0;

/* this structure is what is stored on the disk page for encryption */
typedef struct EncryptionPageState
{
	/* This is the IV for the page */
	uint8 iv[IV_SIZE];
	/* Storage for the authtag */
	uint8 authtag[FLEXIBLE_ARRAY_MEMBER];
} EncryptionPageState;

static void PlaceNewIV(uint8 *loc, uint16 size);

/* these vars are initialized at init time but are effectively constants */

/* encryption_offset is both the offset of the page-level storage block, as
 * well as the length of data to be encrypted. */
static uint16 encryption_offset = 0;
/* encryption_size is the size of the block we are using for the
 * encryption-related data. */
static uint16 encryption_size = 0;

static void
PlaceNewIV(uint8 *loc,uint16 size)
{
  Assert(size==IV_SIZE);
  // we want to ensure we are allowed to write on as much space as we're given
  if (!(_iv_counter & IV_COUNTER_MASK))
    {
      // we need to get a new batch from pg_control; we don't care about it being sequential with previous data, we'll just use the value we got and increment from this block
      _iv_counter = IncrementIVCounter() << IV_MASK_BITS;
    }

  // what all do we want as components of this IV in addition to ppid?
  // _iv_counter; checksum_helper?

  // could seed a hash function with the expected output size; pgcrc32 of counter? ppid pgcrc32? that's only 8 bytes of the iv; for now just set the counter in-place directly
  memset(loc, 0, size - sizeof(_iv_counter));
  memcpy(loc + (size - sizeof(_iv_counter)), &_iv_counter, sizeof(_iv_counter));

  // increment the counter for next time
  _iv_counter++;

}


/*
 * We use the page LSN, page number, and permanent-bit to indicate if a fake
 * LSN was used to create a nonce for each page.
 */
#define BUFENC_IV_SIZE		16

static int file_encryption_tag_size = 0;
static int file_encryption_page_size = 0;
static int file_encryption_method = DISABLED_ENCRYPTION_METHOD;

/* this private struct is used to store additional info about the page used to validate specific other pages */
typedef struct AdditionalAuthenticatedData {
#if PageEncryptOffset > 0
	unsigned char data[PageEncryptOffset]; /* copy of the unencrypted page header info */
#endif
	RelFileNumber fileno;
	BlockNumber blkNo;
} AdditionalAuthenticatedData;

StaticAssertDecl((MAXALIGN(sizeof(AdditionalAuthenticatedData)) == sizeof(AdditionalAuthenticatedData)),
				 "AdditionalAuthenticatedData must be fully padded");

AdditionalAuthenticatedData auth_data;

PgCipherCtx *BufEncCtx = NULL;
PgCipherCtx *BufDecCtx = NULL;
PgCipherCtx *XLogEncCtx = NULL;
PgCipherCtx *XLogDecCtx = NULL;

EncryptionHandle encr_state;

static void
setup_additional_authenticated_data(Page page, BlockNumber blkno,
									bool relation_is_permanent, RelFileNumber fileno);

Size EncryptionPageOffset;

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

	/* for pages, these are constants */
	encryption_offset = PageFeatureSetFeatureOffset(cluster_page_features, PF_ENCRYPTION_TAG);
	encryption_size = PageFeatureSetFeatureSize(cluster_page_features, PF_ENCRYPTION_TAG);
	file_encryption_tag_size = encryption_size - BUFENC_IV_SIZE;
	file_encryption_page_size = encryption_offset - PageEncryptOffset;

	key = KmgrGetKey(KMGR_KEY_ID_WAL);

	XLogEncCtx = pg_cipher_ctx_create(PG_CIPHER_AES_GCM,
									  (unsigned char *) key->key,
									  EncryptionBlockLength(file_encryption_method),
									  true);
	if (!XLogEncCtx)
		my_error("cannot initialize xlog encryption context");

	XLogDecCtx = pg_cipher_ctx_create(PG_CIPHER_AES_GCM,
									  (unsigned char *) key->key,
									  EncryptionBlockLength(file_encryption_method),
									  false);
	if (!XLogDecCtx)
		my_error("cannot initialize xlog decryption context");
}


/* Encrypt the given page with the relation key */
void
EncryptPage(Page page, bool relation_is_permanent, BlockNumber blkno, RelFileNumber fileno)
{
	unsigned char *ptr = (unsigned char *) page + PageEncryptOffset;
	int			enclen;
	unsigned char	*aad = NULL;
	int			aadlen = 0;
	EncryptionPageState *encst = (EncryptionPageState*)(page + encryption_offset);

	Assert(BufEncCtx != NULL);

	/* we change the IV every time we encrypt the page */
	PlaceNewIV(encst->iv, BUFENC_IV_SIZE);

	/* setup tag and AAD */
	if (file_encryption_tag_size > 0)
	{
		setup_additional_authenticated_data(page, blkno, relation_is_permanent, fileno);
		aad = (unsigned char *)&auth_data;
		aadlen = sizeof(AdditionalAuthenticatedData);
	}

	if (unlikely(!pg_cipher_encrypt(BufEncCtx, EncryptionAlgorithm(file_encryption_method),
									(const unsigned char *) ptr,	/* input  */
									file_encryption_page_size,
									ptr,	/* length */
									&enclen,	/* resulting length */
									encst->iv,
									BUFENC_IV_SIZE,
									aad, aadlen, /* AAD */
									encst->authtag, file_encryption_tag_size)))
		my_error("cannot encrypt page %u", blkno);

	Assert(enclen == file_encryption_page_size);
}

/* Decrypt the given page with the relation key */
void
DecryptPage(Page page, bool relation_is_permanent, BlockNumber blkno, RelFileNumber fileno)
{
	unsigned char *ptr = (unsigned char *) page + PageEncryptOffset;
	int			enclen;
	unsigned char	*aad = NULL;
	int			aadlen = 0;
	EncryptionPageState *encst = (EncryptionPageState*)(page + encryption_offset);

	Assert(BufDecCtx != NULL);

	/* setup tag and AAD */
	if (file_encryption_tag_size > 0)
	{
		setup_additional_authenticated_data(page, blkno, relation_is_permanent, fileno);
		aad = (unsigned char *)&auth_data;
		aadlen = sizeof(AdditionalAuthenticatedData);
	}

	if (unlikely(!pg_cipher_decrypt(BufDecCtx, EncryptionAlgorithm(file_encryption_method),
									(const unsigned char *) ptr,	/* input  */
									file_encryption_page_size,
									ptr,	/* output */
									&enclen,	/* resulting length */
									encst->iv,	/* iv */
									BUFENC_IV_SIZE,
									aad, aadlen, /* AAD */
									encst->authtag, file_encryption_tag_size)))
		my_error("cannot decrypt page %u", blkno);

	Assert(enclen == file_encryption_page_size);
}

/* setup aad for given page; private struct so we don't care */
static void
setup_additional_authenticated_data(Page page, BlockNumber blkno,
									bool relation_is_permanent, RelFileNumber fileno)
{
	/* snarf the existing unencrypted bits of the page header */
#if PageEncryptOffset > 0
	memcpy(&auth_data.data, page, PageEncryptOffset);
#endif
	auth_data.fileno = fileno;
	auth_data.blkNo = blkno;
}

void
EncryptXLogRecord(XLogRecord *record, XLogRecPtr address, char *dest)
{
	// noop
}
bool
DecryptXLogRecord(XLogRecord *record, XLogRecPtr address)
{
	// noop
	return true;
}


#if 0
/* TODO:
 *
 * - move XLog pieces to the actual xlog source, but expose these encryption
 *   contexts so we can use them there
 *
 * - abstract the incremental Start/Iterate/Finish routines where we are using
 *   openssl directly and move to the crypto/cipher*.c files.
 */

/*
 * Encrypt an initialized XLogRecord with the xlog key, storing auth in the
 * xl_crc field.  Anything before xl_crc is AAD and anything after
 * is encrypted.
 *
 * The *dest field is assumed to be preallocated, reserved space (likely
 * already in the wal_buffers) where we should copy the final assembled
 * records.  It should be record->xl_tot_len bytes in space, and the caller
 * needs to reserve this space ahead of time and take all appropriate locks.
 */

// TODO: this needs to be fixed to work with other-sized authtags and additional AAD checks/changes
void
EncryptXLogRecord(XLogRecord *record, XLogRecPtr address, char *dest)
{
	unsigned char *ptr = (unsigned char*)record + SizeOfXLogRecord;
	int enclen = 0;

	/* sanity check to ensure we are not encrypting an already encrypted record */
	Assert(*(uint64*)record->xl_integrity.authtag== 0);

	/* setup IV based on the xlp_pageaddr field */
	memcpy(xlog_encryption_iv, &address, sizeof(address));

	if (unlikely(!pg_cipher_encrypt(XLogEncCtx, PG_CIPHER_AES_GCM,
									ptr,	/* input */
									record->xl_tot_len - SizeOfXLogRecord,
									ptr,	/* output */
									&enclen,	/* resulting length */
									xlog_encryption_iv,	/* iv */
									BUFENC_IV_SIZE,
									(unsigned char*)record, offsetof(XLogRecord, xl_integrity), /* AAD */
									record->xl_integrity.authtag, sizeof(record->xl_integrity.authtag))))
	{
		my_error("cannot encrypt xlog page %lu", address);
		return;
	}

	Assert(enclen + SizeOfXLogRecord == record->xl_tot_len);
}

/*
 * Decrypt an encrypted XLogRecord with the xlog key, validating against auth
 * in the xl_integrity field.  Anything before xl_integrity is AAD and
 * anything after is encrypted.
 */
bool
DecryptXLogRecord(XLogRecord *record, XLogRecPtr address)
{
	unsigned char *ptr = (unsigned char*)record + SizeOfXLogRecord;
	int declen = 0;

	/* early abort if we are already decrypted */
	if (!*(uint64*)record->xl_integrity.authtag)
		return true;

	/* setup IV based on the xlp_pageaddr field */
	memcpy(xlog_encryption_iv, &address, sizeof(address));

	if (unlikely(!pg_cipher_decrypt(XLogDecCtx, PG_CIPHER_AES_GCM,
									ptr,	/* input */
									record->xl_tot_len - SizeOfXLogRecord,
									ptr,	/* output */
									&declen,	/* resulting length */
									xlog_encryption_iv,	/* iv */
									BUFENC_IV_SIZE,
									(unsigned char*)record, offsetof(XLogRecord, xl_integrity), /* AAD */
									/* NULL, 0))) */
									(unsigned char*)&record->xl_integrity, sizeof(record->xl_integrity))))
		return false;

	/* in-memory decoded records have xl_integrity of 0 when encryption is defined */
	memset(record->xl_integrity.authtag, 0, sizeof(record->xl_integrity.authtag));

	return (declen + SizeOfXLogRecord == record->xl_tot_len);
}

/*
 * Calculate the GCM Authtag for the given XLogRecord and store the 64-bit
 * value in the given address.
 *
 * This calculates the tag in the same way as would be done with the standard
 * encryption, essentially authenticating the XLogRecord header (minus the
 * xl_integrity field) and then processing the rest of the record after this
 * field as one contiguous block.
 *
 * The reason we need a separate routine for this is because the XLogRecord as
 * given here may be in a buffer we cannot encrypt in-place, say if the same
 * memory location were used for the unencrypted streaming replication
 * XLogRecord.  We will still need to update the xl_integrity field in this
 * case.
 *
 * XXX: if we are using the xl_integrity field for CRC replacement, do we in
 * actuality /need/ to leave encrypted so we can have a single code path on
 * streaming rep for decryption?  Otherwise how would we know the end of valid
 * records?  Look into this more.
 */
void
CalculateXLogRecordAuthtag(XLogRecData *recdata, XLogRecPtr address, char *tag)
{
	XLogRecData *rdt;
	XLogRecord *recheader;
	int len;
#define SCRATCH_SIZE 1024
	unsigned char scratch[SCRATCH_SIZE];
	char authtag[XL_AUTHTAG_SIZE];

	/*
	 * Unfortunately, in order to get the right value for the authtag, it is
	 * not sufficient to just EVP_EncryptUpdate() over a NULL buffer, as we do
	 * for AAD, so we need to utilize a "scribble buffer" in order to store
	 * temporarily encrypted results though we don't end up doing anything
	 * with them.
	 *
	 * This does mean that currently we have to effectively encrypt the
	 * XLogRecord twice -- one to pre-calculate the authtag which needs to be
	 * stored in the initial XLogRecData in order to handle these things
	 * incrementally, and once to encrypt as we copy data into
	 * CopyXLogRecordToWAL().  Unfortunately, this is unavoidable as the
	 * contract of GetWALBuffer() indicates that we cannot reference any
	 * earlier buffers, as these may end up flushing the first buffer we need
	 * to store the actual hash into.
	 */

	/* verify we're a sensible chain of data */
	Assert(recdata != NULL && recdata->data != NULL);
	recheader = (XLogRecord*)(recdata->data);

	/* make sure our first block looks like a normal XLogRecord header */
	Assert(recdata->len >= SizeOfXLogRecord);

	/* initialize our context */
	/* setup IV based on the xlp_pageaddr field */
	memcpy(xlog_encryption_iv, &address, sizeof(address));

	/* initialize our IV context */

	encr_state = pg_cipher_incr_init(XLogEncCtx, PG_CIPHER_AES_GCM,
									 xlog_encryption_iv, 16);

	/* initial AAD is not full length, so handle this page separately */
	if (!pg_cipher_incr_add_authenticated_data(
			encr_state,
			(unsigned char*)recheader,
			offsetof(XLogRecord,xl_integrity)))
		my_error("error when trying to update AAD");

	/* also for initial page, anything past SizeOfXLogRecord needs to be
	 * added */
	if (recdata->len > SizeOfXLogRecord)
	{
		int mylen = recdata->len - SizeOfXLogRecord;
		unsigned char *ptr = (unsigned char *)recdata->data + SizeOfXLogRecord;
		int step;

		/* since we have to write to a scribble buffer to get the right answer
		 * (boo), break into chunks of SCRATCH_SIZE */
		do {
			step = mylen > SCRATCH_SIZE ? SCRATCH_SIZE : mylen;

			if (!pg_cipher_incr_encrypt(encr_state, ptr, step, scratch, &len))
				my_error("error when trying to update data");
			ptr += step;
		} while (step > 0 && (mylen -= step) > 0);
	}

	/* progressively update with the data pages for the record, chunking into
	 * SCRATCH_SIZE chunks */
	for (rdt = recdata->next; rdt != NULL; rdt = rdt->next)
	{
		int mylen = rdt->len;
		unsigned char *ptr = (unsigned char*)rdt->data;
		int step;

		do {
			step = mylen > SCRATCH_SIZE ? SCRATCH_SIZE : mylen;

			if (!pg_cipher_incr_encrypt(encr_state, ptr, step, scratch, &len))
				my_error("error when trying to update data");
			ptr += step;
		} while (step > 0 && (mylen -= step) > 0);
	}

    /*
	 * Finalize the encryption, which could add more to output, and extract
	 * our authtag.
	 */
	pg_cipher_incr_finish(encr_state, scratch, &len, (unsigned char*)authtag, XL_AUTHTAG_SIZE);
	memcpy(tag,authtag,XL_AUTHTAG_SIZE);
}

/* Incremental XLog Record Encryption */

/*
 * This routine initializes the machinery for the initial state for encrypting
 * an XLogRecord while moving into the reserved WAL space.  It sets some
 * global variables, assuming nothing else is intervening in subsequent calls
 * here, with the following sequence of events happening:
 *
 * 1. StartEncryptXLogRecord() to initialize state
 * 2. EncryptXLogRecordIncremental() to copy or encrypt some number of bytes
 *    (depending on where in the record we are)
 * 3. FinishEncryptXLogRecord() to
 *    finalize state once all data has been copied or encrypted
 *
 * Since only one XLogRecord can be inserted at a time for a single backend,
 * we do not need to worry about overwriting state here, so use globals for state mgmt
 */

static int bytes_processed;
static int bytes_tot;
static char xrechdr[SizeOfXLogRecord];

void StartEncryptXLogRecord(XLogRecord *record, XLogRecPtr address)
{
	/* setup IV based on the xlp_pageaddr field */
	memcpy(xlog_encryption_iv, &address, sizeof(address));

	/* initialize our IV context */
	encr_state = pg_cipher_incr_init(XLogEncCtx, PG_CIPHER_AES_GCM,
									 xlog_encryption_iv, 16);

	if (!encr_state)
		my_error("Couldn't initialize incremental encryption context");

	/* reset our other state vars */
	bytes_processed = 0;
	bytes_tot = record->xl_tot_len;
}

/* returns the byte offset copied to the output buffer; can be <= input length if we are still filling the header */
int EncryptXLogRecordIncremental(char *plaintext, char *encdest, int len)
{
	/* ensure we're not trying to process too much data */
	Assert(bytes_processed + len <= bytes_tot);

	/* are we just copying data? */
	if (bytes_processed < SizeOfXLogRecord)
	{
		int remaining = SizeOfXLogRecord - bytes_processed;

		if (len >= remaining)
		{
			/* copy remaining bytes into our local XLogRecord header buffer */
			memcpy(xrechdr + bytes_processed, plaintext, remaining);

			/* copy remaining bytes into output stream */
			memcpy(encdest, plaintext, remaining);

			/* adjust counts for what we've done for later encrypted processing in this round */
			bytes_processed += remaining;
			encdest += remaining;
			plaintext += remaining;
			len -= remaining;

			/* initialize our encryption for the record minus the xl_integrity
			 * field, which is calculated in an initial pass without
			 * encrypting the underlying data. */
			pg_cipher_incr_add_authenticated_data(
				encr_state,
				(unsigned char*)xrechdr,
				offsetof(XLogRecord, xl_integrity)
			);

			/* at this point, we're done with the unencrypted header and any
			 * further data will be encrypted incrementally */
		}
		else
		{
			/* only partial bytes available, so let's just copy into our buffer and output buffer */
			memcpy(xrechdr + bytes_processed, plaintext, len);
			memcpy(encdest, plaintext, len);
			bytes_processed += len;
			len = 0;
		}
	}

	/* incrementally encrypt data */
	if (len > 0)
	{
		int enclen;

		pg_cipher_incr_encrypt(
			encr_state,
			(unsigned char*)plaintext,
			len,
			(unsigned char*)encdest,
			&enclen
		);
		bytes_processed += enclen;
	}
	return bytes_processed;
}

void FinishEncryptXLogRecord(char *loc)
{
	int len;
	unsigned char tag[XL_AUTHTAG_SIZE] = {0};

	Assert(bytes_processed <= bytes_tot);

    /* Finalize the encryption, which could add more to output. */
	pg_cipher_incr_finish(encr_state, (unsigned char*)loc, &len, tag, XL_AUTHTAG_SIZE);
	bytes_processed += len;

	/* ensure we copied all the data we expected */
	Assert(bytes_processed == bytes_tot);
}

#endif
