/*-------------------------------------------------------------------------
 *
 * bufenc.h
 *
 * Portions Copyright (c) 2021, PostgreSQL Global Development Group
 *
 * src/include/crypto/bufenc.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef BUFENC_H
#define BUFENC_H

#include "storage/bufmgr.h"
#include "crypto/kmgr.h"

/* Cluster encryption encrypts only main forks */
#define PageNeedsToBeEncrypted(forknum) \
	(FileEncryptionEnabled && (forknum) == MAIN_FORKNUM)


#ifdef FRONTEND
#include "common/logging.h"
#define my_error(...) pg_fatal(__VA_ARGS__)
#define LSNForEncryption(a) InvalidXLogRecPtr
#else
extern XLogRecPtr LSNForEncryption(bool use_wal_lsn);
#define my_error(...) elog(ERROR, __VA_ARGS__)
#endif

extern void InitializeBufferEncryption(int file_encryption_method);
extern void EncryptPage(Page page, bool relation_is_permanent,
						BlockNumber blkno, RelFileNumber fileno);
extern void DecryptPage(Page page, bool relation_is_permanent,
						BlockNumber blkno, RelFileNumber fileno);

#endif							/* BUFENC_H */
