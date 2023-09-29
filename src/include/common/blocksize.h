/*-------------------------------------------------------------------------
 *
 * blocksize.h
 *	  defintions for cluster-specific limits/structure defs
 *
 *
 * Copyright (c) 2023, PostgreSQL Global Development Group
 *
 * IDENTIFICATION: src/include/clustersizes.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef BLOCKSIZE_H
#define BLOCKSIZE_H

#ifndef DEFAULT_BLOCK_SIZE
#define DEFAULT_BLOCK_SIZE 8192
#endif

#ifndef MIN_BLOCK_SIZE
#define MIN_BLOCK_SIZE 1024
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE 32*1024
#endif

#define IsValidBlockSize(size) ((size) >= MIN_BLOCK_SIZE && \
								(size) <= MAX_BLOCK_SIZE && \
								((size)&((size)-1)) == 0)

/* identifiers only */
typedef enum {
	BLOCK_SIZE_UNSET = 0,
	BLOCK_SIZE_1K,
	BLOCK_SIZE_2K,
	BLOCK_SIZE_4K,
	BLOCK_SIZE_8K,
	BLOCK_SIZE_16K,
	BLOCK_SIZE_32K,
} BlockSizeIdent;

/* The names of these enums are actually unimportant, but just indicate how much space we're reserving in total bytes */
typedef enum {
	RESERVED_NONE = 0,
	RESERVED_8,
	RESERVED_16,
	/* if you add to this, adjust the enum for MAX_RESERVED_SIZE */
} ReservedBlockSize;

/* Reserved page space allocates bins of the given size from the end of the
 * page, up to the max amount supported.  This is 1<<RESERVED_CHUNK_BITS, so
 * by default 8 bit chunks.  If you need to adjust this bin size, just adjust
 * the number of bits for the desired amount. */

#define RESERVED_CHUNK_BITS 3
#define RESERVED_CHUNK_SIZE (1<<RESERVED_CHUNK_BITS)
#define MAX_RESERVED_SIZE SizeOfReservedBlock(RESERVED_16)
#define SizeOfReservedBlock(b) ((b)<<RESERVED_CHUNK_BITS)
#define IsValidReservedSize(s) ((s)>=0 && (s) <= MAX_RESERVED_SIZE)
/* finds the block number for the nearest multiple of RESERVED_CHUNK_SIZE */
#define ReservedBlockForSize(s) ((ReservedBlockSize)((s+(RESERVED_CHUNK_SIZE-1))>>RESERVED_CHUNK_BITS))

extern PGDLLIMPORT BlockSizeIdent cluster_block_setting;
extern PGDLLIMPORT ReservedBlockSize cluster_reserved_page;

void BlockSizeInit(Size rawblocksize, Size reserved);
void BlockSizeInitFromControlFile();

#define cluster_block_bits (cluster_block_setting+9)
#define cluster_block_size (1<<cluster_block_bits)
// TODO: make this calculate using use DEFAULT_BLOCK_SIZE instead?
#define DEFAULT_BLOCK_SIZE_BITS 13 
#define cluster_relseg_size (RELSEG_SIZE << DEFAULT_BLOCK_SIZE_BITS >> cluster_block_bits)

/* originally in heaptoast.h */

#define CalcMaximumBytesPerTuple(blocksize,reserved,tuplesPerPage)	\
	MAXALIGN_DOWN((blocksize - \
				   MAXALIGN(SizeOfPageHeaderData + reserved + (tuplesPerPage) * sizeof(ItemIdData))) \
				  / (tuplesPerPage))

#define CalcToastMaxChunkSize(blocksize,reserved)							\
	(CalcMaximumBytesPerTuple(blocksize,reserved,EXTERN_TUPLES_PER_PAGE) - \
	 MAXALIGN(SizeofHeapTupleHeader) -					\
	 sizeof(Oid) -										\
	 sizeof(int32) -									\
	 VARHDRSZ)

/* originally in htup_details.h */

#define CalcMaxHeapTupleSize(size,reserved)  (size - MAXALIGN(SizeOfPageHeaderData + reserved + sizeof(ItemIdData)))

#define CalcMaxHeapTuplesPerPage(size,reserved)									\
	((int) (((size) - SizeOfPageHeaderData - reserved) /							\
			(MAXALIGN(SizeofHeapTupleHeader) + sizeof(ItemIdData))))

/* originally in itup.h */

#define CalcMaxIndexTuplesPerPage(size,reserved)							  \
	((int) ((size - SizeOfPageHeaderData - reserved) / \
			(MAXALIGN(sizeof(IndexTupleData) + 1) + sizeof(ItemIdData))))

/* originally in nbtree_int.h */

#define CalcMaxTIDsPerBTreePage(size, reserved)									\
	(int) ((size - SizeOfPageHeaderData - reserved - sizeof(BTPageOpaqueData)) / \
		   sizeof(ItemPointerData))

/* originally in bloom.h */
#define CalcFreeBlockNumberElems(size,reserved) (MAXALIGN_DOWN(size - SizeOfPageHeaderData - reserved - MAXALIGN(sizeof(BloomPageOpaqueData)) \
													   - MAXALIGN(sizeof(uint16) * 2 + sizeof(uint32) + sizeof(BloomOptions)) \
									 ) / sizeof(BlockNumber))

#define BlockSizeDecl(calc) \
	static inline unsigned int _block_size_##calc(BlockSizeIdent bsi, ReservedBlockSize reserved) { \
	switch(reserved){													\
	case RESERVED_NONE:													\
	switch(bsi){														\
	case BLOCK_SIZE_1K: return calc(1024,SizeOfReservedBlock(RESERVED_NONE)); break; \
	case BLOCK_SIZE_2K: return calc(2048,SizeOfReservedBlock(RESERVED_NONE)); break; \
	case BLOCK_SIZE_4K: return calc(4096,SizeOfReservedBlock(RESERVED_NONE)); break; \
	case BLOCK_SIZE_8K: return calc(8192,SizeOfReservedBlock(RESERVED_NONE)); break; \
	case BLOCK_SIZE_16K: return calc(16384,SizeOfReservedBlock(RESERVED_NONE)); break; \
	case BLOCK_SIZE_32K: return calc(32768,SizeOfReservedBlock(RESERVED_NONE)); break; \
	default: return 0;}													\
	break;																\
	case RESERVED_8:													\
	switch(bsi){														\
	case BLOCK_SIZE_1K: return calc(1024,SizeOfReservedBlock(RESERVED_8)); break;	\
	case BLOCK_SIZE_2K: return calc(2048,SizeOfReservedBlock(RESERVED_8)); break;	\
	case BLOCK_SIZE_4K: return calc(4096,SizeOfReservedBlock(RESERVED_8)); break;	\
	case BLOCK_SIZE_8K: return calc(8192,SizeOfReservedBlock(RESERVED_8)); break;	\
	case BLOCK_SIZE_16K: return calc(16384,SizeOfReservedBlock(RESERVED_8)); break; \
	case BLOCK_SIZE_32K: return calc(32768,SizeOfReservedBlock(RESERVED_8)); break; \
	default: return 0;}													\
	break;																\
	case RESERVED_16:													\
	switch(bsi){														\
	case BLOCK_SIZE_1K: return calc(1024,SizeOfReservedBlock(RESERVED_16)); break;	\
	case BLOCK_SIZE_2K: return calc(2048,SizeOfReservedBlock(RESERVED_16)); break;	\
	case BLOCK_SIZE_4K: return calc(4096,SizeOfReservedBlock(RESERVED_16)); break;	\
	case BLOCK_SIZE_8K: return calc(8192,SizeOfReservedBlock(RESERVED_16)); break;	\
	case BLOCK_SIZE_16K: return calc(16384,SizeOfReservedBlock(RESERVED_16)); break; \
	case BLOCK_SIZE_32K: return calc(32768,SizeOfReservedBlock(RESERVED_16)); break; \
	default: return 0;}													\
	break;																\
	}; return 0;}

#define BlockSizeDecl2(calc)											\
	static inline unsigned int _block_size_##calc(BlockSizeIdent bsi, ReservedBlockSize reserved, unsigned int arg) { \
	switch(reserved){													\
	case RESERVED_NONE:													\
	switch(bsi){														\
	case BLOCK_SIZE_1K: return calc(1024,SizeOfReservedBlock(RESERVED_NONE),arg); break; \
	case BLOCK_SIZE_2K: return calc(2048,SizeOfReservedBlock(RESERVED_NONE),arg); break; \
	case BLOCK_SIZE_4K: return calc(4096,SizeOfReservedBlock(RESERVED_NONE),arg); break; \
	case BLOCK_SIZE_8K: return calc(8192,SizeOfReservedBlock(RESERVED_NONE),arg); break; \
	case BLOCK_SIZE_16K: return calc(16384,SizeOfReservedBlock(RESERVED_NONE),arg); break; \
	case BLOCK_SIZE_32K: return calc(32768,SizeOfReservedBlock(RESERVED_NONE),arg); break; \
	default: return 0;}													\
	break;																\
	case RESERVED_8:													\
	switch(bsi){														\
	case BLOCK_SIZE_1K: return calc(1024,SizeOfReservedBlock(RESERVED_8),arg); break;	\
	case BLOCK_SIZE_2K: return calc(2048,SizeOfReservedBlock(RESERVED_8),arg); break;	\
	case BLOCK_SIZE_4K: return calc(4096,SizeOfReservedBlock(RESERVED_8),arg); break;	\
	case BLOCK_SIZE_8K: return calc(8192,SizeOfReservedBlock(RESERVED_8),arg); break;	\
	case BLOCK_SIZE_16K: return calc(16384,SizeOfReservedBlock(RESERVED_8),arg); break; \
	case BLOCK_SIZE_32K: return calc(32768,SizeOfReservedBlock(RESERVED_8),arg); break; \
	default: return 0;}													\
	break;																\
	case RESERVED_16:													\
	switch(bsi){														\
	case BLOCK_SIZE_1K: return calc(1024,SizeOfReservedBlock(RESERVED_16),arg); break;	\
	case BLOCK_SIZE_2K: return calc(2048,SizeOfReservedBlock(RESERVED_16),arg); break;	\
	case BLOCK_SIZE_4K: return calc(4096,SizeOfReservedBlock(RESERVED_16),arg); break;	\
	case BLOCK_SIZE_8K: return calc(8192,SizeOfReservedBlock(RESERVED_16),arg); break;	\
	case BLOCK_SIZE_16K: return calc(16384,SizeOfReservedBlock(RESERVED_16),arg); break; \
	case BLOCK_SIZE_32K: return calc(32768,SizeOfReservedBlock(RESERVED_16),arg); break; \
	default: return 0;}													\
	break;																\
	}; return 0;}

#define BlockSizeCalc(bsi,calc) _block_size_##calc(bsi,cluster_reserved_page)

extern PGDLLIMPORT int reserved_page_size;

#endif
