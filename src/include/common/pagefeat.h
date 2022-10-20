/*-------------------------------------------------------------------------
 *
 * pagefeat.h
 *	  POSTGRES page feature support
 *
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/common/pagefeat.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PAGEFEAT_H
#define PAGEFEAT_H

/* revealed for GUCs */
extern int reserved_page_size;

/* forward declaration to avoid circular includes */
typedef Pointer Page;
typedef uint16 PageFeatureSet;

extern PageFeatureSet cluster_page_features;

#define SizeOfPageReservedSpace reserved_page_size

/* bit offset for features flags */
typedef enum {
	/* TODO: add features here */
	PF_MAX_FEATURE = 0 /* must be last */
} PageFeature;

/* prototypes */
void SetExtendedFeatureConfigOptions(PageFeatureSet features);
char *GetPageFeatureOffset(Page page, PageFeatureSet enabled_features, PageFeature feature);
uint16 CalculateReservedPageSize(PageFeatureSet features);
uint16 GetFeatureLength(PageFeature feature);
PageFeatureSet PageFeatureSetAddFeatureByName(PageFeatureSet features, const char *feat_name);
PageFeatureSet PageFeatureSetAddFeature(PageFeatureSet features, PageFeature feature);

/* macros dealing with the current cluster's page features */
#define PageFeatureSetHasFeature(fs,f) (fs&(1<<f))
#define ClusterPageFeatureOffset(page,feat) GetPageFeatureOffset(page,cluster_page_features,feat)
#define ClusterPageFeatureInit(features) cluster_page_features = features;

#endif							/* PAGEFEAT_H */
