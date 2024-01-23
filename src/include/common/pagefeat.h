/*-------------------------------------------------------------------------
 *
 * pagefeat.h
 *	  POSTGRES page feature support
 *
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/common/pagefeat.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PAGEFEAT_H
#define PAGEFEAT_H

/* arbitrary upper limit of all internal and user-defined page features */
#define MAX_PAGE_FEATURES 20
#define PAGE_FEATURE_NAME_LEN 20

#define HAS_PAGE_FEATURES (cluster_page_features && cluster_page_features->feat_count > 0)

/* builtin features GUC display */
extern PGDLLIMPORT bool page_feature_extended_checksums;

/* forward declaration to avoid circular includes */
typedef Pointer Page;

typedef struct PageFeatureDesc
{
	char name[PAGE_FEATURE_NAME_LEN];
	uint16 size;
} PageFeatureDesc;

typedef struct AllocatedPageFeatureDesc
{
	char name[PAGE_FEATURE_NAME_LEN];
	uint16 offset;
	uint16 size;
	uint16 isbuiltin:1;			/* is this a builtin? */
	uint16 builtin:15;			/* if a builtin, which one */
} AllocatedPageFeatureDesc;

/* storage for persistent Page Feature Set */
typedef struct PageFeatureSetData {
	char name[PAGE_FEATURE_NAME_LEN]; /* name of the set */
	uint16 builtin_bitmap;		/* bitmap flag of the builtin options */
	uint16 bytes_managed;		/* how many bytes are we managing? */
	uint16 bytes_used;			/* how many current bytes are allocated */
	uint16 feat_count;			/* how many current features */
	uint16 feat_capacity;		/* how many features we have space allocated to store */
	bool locked;				/* whether we allow changes to this set */
	AllocatedPageFeatureDesc feats[FLEXIBLE_ARRAY_MEMBER];
} PageFeatureSetData, *PageFeatureSet;

extern PGDLLIMPORT PageFeatureSet cluster_page_features;

/* bit offset for features flags */
typedef enum {
	PF_EXT_CHECKSUMS = 0,  /* must be first */
	PF_MAX_FEATURE /* must be last */
} PageFeature;

/* Limit for total number of features we will support.  Since we are storing
 * two status bytes, we are reserving the top bit here to be set to indicate
 * for whether there are more than 15 features; used for future extensibility.
 * This should not be increased as part of normal feature development, only
 * when adding said mechanisms */

#define PF_MAX_POSSIBLE_FEATURE_CUTOFF 15

StaticAssertDecl(PF_MAX_FEATURE <= PF_MAX_POSSIBLE_FEATURE_CUTOFF,
				 "defined more features than will fit in bitmap");

/* creation */
PageFeatureSet NewPageFeatureSet(char *name, uint16 bytes_capacity, uint16 max_features);

/* io */
PageFeatureSet ReadPageFeatureSet(char *path);
bool WritePageFeatureSet(PageFeatureSet pfs, char *path);

/* add */
bool PageFeatureSetAddFeature(PageFeatureSet pfs, PageFeature feature, uint16 size);
bool PageFeatureSetAddFeatureByName(PageFeatureSet pfs, const char *feat_name, uint16 size);

/* test */
bool PageFeatureSetHasFeature(PageFeatureSet pfs, PageFeature);
bool PageFeatureSetHasNamedFeature(PageFeatureSet pfs, char *feat_name);

/* size */
uint16 PageFeatureSetFeatureSize(PageFeatureSet pfs, PageFeature feature);
uint16 PageFeatureSetNamedFeatureSize(PageFeatureSet pfs, char *feat_name);
uint16 PageFeatureSetCalculateSize(PageFeatureSet pfs);

/* offset */
uint16 PageFeatureSetFeatureOffset(PageFeatureSet pfs, PageFeature feature);
uint16 PageFeatureSetNamedFeatureOffset(PageFeatureSet pfs, char *feat_name);

/* builtin-related utilities */
uint16 PageFeatureBuiltinFeatureSize(PageFeature feature);

/* page-level calls */
uint16 PageGetFeatureOffset(Page page, PageFeature feature);
uint16 PageGetNamedFeatureOffset(Page page, char *feat_name);
uint16 PageGetFeatureSize(Page page, PageFeature feature);
uint16 PageGetNamedFeatureSize(Page page, char *feat_name);
/* no HasFeature -- use Offset = 0 to test */

/* integration pieces */
void ClusterPageFeatureInit(char *datadir, char *setname);
void SetExtendedFeatureConfigOptions(void);

#endif							/* PAGEFEAT_H */
