/*-------------------------------------------------------------------------
 *
 * blocksize.c
 *	  This file contains methods to calculate various size constants for variable-sized blocks.
 *
 *
 * Copyright (c) 2023, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/common/clustersizes.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "access/itup.h"
#include "access/nbtree_int.h"
#include "common/blocksize.h"
#ifndef FRONTEND
#include "storage/freespace.h"
#endif

PGDLLIMPORT BlockSizeIdent cluster_block_setting = BLOCK_SIZE_UNSET;
PGDLLIMPORT ReservedBlockSize cluster_reserved_page = RESERVED_NONE;

PGDLLIMPORT int reserved_page_size = 0;
/*
 * This routine will calculate and cache the necessary constants. This should
 * be called once very very early in the process (as soon as the native block
 * size is known, so after reading ControlFile).
 */

void
BlockSizeInit(Size rawblocksize, Size reserved)
{
	uint32 bits = 0;
	Size blocksize = rawblocksize;

	Assert(IsValidBlockSize(rawblocksize));
	Assert(IsValidReservedSize(reserved));

	// calculate max number of bits in the passed-in size
	while (blocksize >>= 1)
		bits++;

	// our smallest block size, 1k, is 2^10, and we want this to be 1 if initialized
	cluster_block_setting = (BlockSizeIdent)(bits - 10) + 1;
	cluster_reserved_page = ReservedBlockForSize(reserved);
	
	// setup additional reserved_page_size data
	reserved_page_size = SizeOfReservedBlock(cluster_reserved_page);

	#ifndef FRONTEND
	/* also setup the FreeSpaceMap internal sizing */
	FreeSpaceMapInit();
	#endif
}
