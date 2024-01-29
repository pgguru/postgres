/*-------------------------------------------------------------------------
 *
 * pagefeat.c
 *	  POSTGRES optional page features
 *
 * Copyright (c) 2024, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/common/pagefeat.c
 *
 *-------------------------------------------------------------------------
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "postgres.h"
#include "common/pagefeat.h"
#include "common/logging.h"
#include "storage/fd.h"
#include "utils/guc.h"

/* global variables */
PageFeatureSet cluster_page_features;

/* debugging aid */
#ifdef FRONTEND
#define pg_error(...) pg_fatal(__VA_ARGS__)
#else
#define pg_error(...) elog(ERROR, __VA_ARGS__)
#endif

/* declarations for status GUCs */
bool page_feature_extended_checksums;
bool page_feature_encryption_tags;

/*
 * A "page feature" is an optional cluster-defined additional data field that
 * is stored in the "reserved_page_size" area in the footer of a given Page.
 * These features are set at initdb time and are static for the life of the cluster.
 *
 * Page features are identified by flags, each corresponding to a blob of data
 * with a length and content.  For a given cluster, these features will
 * globally exist or not, and can be queried for feature existence.  You can
 * also get the data/length for a given feature using accessors.
 *
 * Page features are identified by name.  Custom page features can be added to
 * an existing cluster if there is still reserved space available by
 * registering a given name and size.  Page features cannot be resized or
 * removed once added at this time.
 *
 * Each built-in page feature has a default size associated with it, but this
 * may be customized when it is laying out/persisting the feature.
 *
 * A page feature set is created with NewPageFeatureSet, which is an empty set
 * of page features.  This abstraction is used to divvy up the reserved page
 * size into named buckets.
 *
 * A page feature set is unlocked when created, but when it is read or
 * written, it becomes locked in memory; this is because we do not support
 * changing page feature layouts at this time once we have potentially
 * committed data to disk with this layout.
 *
 * On backend startup, after the pg_control page feature set is loaded from
 * disk, individual features should be queried and stored in a variable for
 * later use; the lookup here is not optimized (nor should the size change
 * across the life of the cluster), so cache the value used here.
 */

/* These are the default widths for each feature type, indexed by feature.  This
 * is also used to lookup page features by the bootstrap process and expose
 * the state of this page feature as a readonly boolean GUC, so when adding a
 * named feature here ensure you also update the guc_tables file to add this,
 * or the attempt to set the GUC will fail. */

static PageFeatureDesc builtin_feature_descs[PF_MAX_FEATURE] = {
	/* PF_ENCRYPTION_TAG */
	{ "encryption_tags", 0 },	/* set by InitPageFeatures after we know the encryption method */
	/* PF_EXT_CHECKSUMS */
	{ "extended_checksums", 64 }, /* needs storage for up to 512 bits */
};

static void OptimizePageFeatureSet(PageFeatureSet pfs);
static PageFeatureSet EmptyPageFeatureSet(void);

/* Return the size for a given set of feature flags */
uint16
PageFeatureSetCalculateSize(PageFeatureSet pfs)
{
	return pfs->bytes_used;
}


/* does a specific page have a feature? */
inline
bool PageHasFeature(Page page, PageFeature feature)
{
	Assert(page);

	return ((PageHeader) page)->pd_flags & PD_EXTENDED_FEATS && \
		PageFeatureSetHasFeature(cluster_page_features, feature);
}

/* does a specific feature set have a feature? */
inline
bool PageFeatureSetHasFeature(PageFeatureSet pfs, PageFeature feature)
{
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);
	Assert(pfs);

	return pfs->builtin_bitmap & (1<<feature);
}

/* check feature by name */
inline bool
PageHasNamedFeature(Page page, char *feat_name)
{
	Assert(page);

	return ((PageHeader) page)->pd_flags & PD_EXTENDED_FEATS && \
		PageFeatureSetHasNamedFeature(cluster_page_features, feat_name);
}

/* check feature by name */
inline bool
PageFeatureSetHasNamedFeature(PageFeatureSet pfs, char *feat_name)
{
	Assert(pfs && feat_name);

	for (int i = 0; i < pfs->feat_count; i ++)
		if (!strcmp(pfs->feats[i].name, feat_name))
			return true;

	return false;
}

/* returns the raw size for a given builtin feature */
uint16
PageFeatureBuiltinFeatureSize(PageFeature feature) {
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);
	return builtin_feature_descs[feature].size;
}

/* returns the allocated size of a feature as declared in a PageFeatureSet, or
 * 0 if none */
uint16
PageFeatureSetFeatureSize(PageFeatureSet pfs, PageFeature feature) {
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);
	return PageFeatureSetNamedFeatureSize(pfs,builtin_feature_descs[feature].name);
}

/* return the size for the given named page feature */
uint16
PageFeatureSetNamedFeatureSize(PageFeatureSet pfs, char *feat_name)
{
	/* sanity-check some basic things here*/
	Assert(pfs && feat_name);

	for (int i = 0; i < cluster_page_features->feat_count; i ++)
		if (!strcmp(cluster_page_features->feats[i].name, feat_name))
		{
			return cluster_page_features->feats[i].size;
		}

	return 0;
}

/*
 * Get the index offset for the given feature given the page, and builtin feature.
 *
 * This routine is not expected to be called regularly; you should call it
 * once and cache the result once the backend has started up.  It should never
 * change once initially loaded.
 */
uint16
PageGetFeatureOffset(Page page, PageFeature feature)
{
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);

	return PageGetNamedFeatureOffset(page, builtin_feature_descs[feature].name);
}

/*
 * Get the index offset for the given feature given the page, flags, and
 * feature id.  Returns 0 if the feature is not enabled.
 *
 * This routine is not expected to be called regularly; you should call it
 * once and cache the result once the backend has started up.  It should never
 * change once initially loaded.
 */

uint16
PageGetNamedFeatureOffset(Page page, char *feat_name)
{
	/* sanity-check some basic things here*/
	Assert(cluster_page_features != NULL);

	/* with no page or page features, this is 0, so early abort */
	if (!page || !(((PageHeader) page)->pd_flags & PD_EXTENDED_FEATS) || !((PageHeader) page)->pd_feat.features)
		return 0;

	/* we potentially can lift this in the future for page-specific features, but for now we are using cluster_page_features exclusively. */
	Assert(((PageHeader) page)->pd_feat.features == cluster_page_features->builtin_bitmap);

	return PageFeatureSetNamedFeatureOffset(cluster_page_features, feat_name);
}

/* lookup the offset in the page feature set */
uint16
PageFeatureSetFeatureOffset(PageFeatureSet pfs, PageFeature feature)
{
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);
	return PageFeatureSetNamedFeatureOffset(pfs, builtin_feature_descs[feature].name);
}

/* return the offset for the given page feature by name */
uint16
PageFeatureSetNamedFeatureOffset(PageFeatureSet pfs, char *feat_name)
{
	Assert(pfs && feat_name);

	/*
	 * The offset, as stored in our page feature set, is different relative to
	 * what we expect as a caller of this routine.  These values are stored
	 * relative to the end of the page, but the consumer expects the offset
	 * *into* the page.  This just converts from the expected value to this
	 * one.
	 */

	for (int i = 0; i < pfs->feat_count; i ++)
		if (!strcmp(pfs->feats[i].name, feat_name))
		{
			return BLCKSZ - pfs->feats[i].offset - pfs->feats[i].size;
		}

	return 0;
}


/*
 * Get the feature size for the given builtin feature on the given page.
 *
 * This routine is not expected to be called regularly; you should call it
 * once and cache the result once the backend has started up.  It should never
 * change once initially loaded.
 */
uint16
PageGetFeatureSize(Page page, PageFeature feature)
{
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);

	return PageGetNamedFeatureSize(page, builtin_feature_descs[feature].name);
}

/*
 * Get the feature size for the given feature given the page and name.
 * Returns 0 if the feature is not enabled.
 *
 * This routine is not expected to be called regularly; you should call it
 * once and cache the result once the backend has started up.  It should never
 * change once initially loaded.
 */

uint16
PageGetNamedFeatureSize(Page page, char *feat_name)
{
	/* sanity-check some basic things here*/
	Assert(cluster_page_features != NULL);

	/* with no page or page features, this is 0, so early abort */
	if (!page || !(((PageHeader) page)->pd_flags & PD_EXTENDED_FEATS) || !((PageHeader) page)->pd_feat.features)
		return 0;

	/* we potentially can lift this in the future for page-specific features, but for now we are using cluster_page_features exclusively. */
	Assert(((PageHeader) page)->pd_feat.features == cluster_page_features->builtin_bitmap);

	for (int i = 0; i < cluster_page_features->feat_count; i ++)
		if (!strcmp(cluster_page_features->feats[i].name, feat_name))
		{
			return cluster_page_features->feats[i].size;
		}

	return 0;
}

/*
 * this routine reorders the columns in the page feature set to the following priority:
 *
 * builtin bitmap, lowest bit first, so 0 offset is first column
 * user-defined vars, preserving order
 *
 * the idea here is that internal page features are likely to be more
 * position-dependent (say an encryption IV or authtag, which needs to be
 * addressible in a consistent position and predictable), whereas user-defined
 * ones just care about some specific amount of space, not where it is on the
 * page.
 */
static void
OptimizePageFeatureSet(PageFeatureSet pfs)
{
	int cur_feat = 0, cur_off = 0;
	AllocatedPageFeatureDesc descs[MAX_PAGE_FEATURES];

	/* sanity-checking */
	Assert(pfs);

	/* early exit conditions: if we are locked, we have no builtins, or there
	 * are not enough elements to consider we don't need to do anything */
	if (pfs->locked || !pfs->builtin_bitmap || pfs->feat_count <= 1)
		return;

	/* iterate over the builtins, assigning our slots as needed */
 	for (int i = 0; i < PF_MAX_FEATURE; i++)
		if (pfs->builtin_bitmap & (1<<i))
		{
			/* look through existing feats for matching */
			for (int j = 0; j < pfs->feat_count; j++)
			{
				/* check for matching builtin */
				if (pfs->feats[j].isbuiltin && pfs->feats[j].builtin == i)
				{
					/* got it, copy into location and adjust offset */
					memcpy(&descs[cur_feat], &pfs->feats[j], sizeof(AllocatedPageFeatureDesc));
					descs[cur_feat].offset = cur_off;
					cur_off += descs[cur_feat].size;
					cur_feat++;
					break;		/* inner loop, will continue at outer for loop */
				}
			}
			/* this shouldn't be reached, or there is corruption in the bitmap/feat table */
		}

	/* at this point our builtins should be copied into place in definition
	 * order; simple check for user-defined features before looping again */
	if (cur_feat < pfs->feat_count)
	{
		for (int j = 0; j < pfs->feat_count; j++)
		{
			if (!pfs->feats[j].isbuiltin)
			{
				/* got it, copy into location and adjust offset */
				memcpy(&descs[cur_feat], &pfs->feats[j], sizeof(AllocatedPageFeatureDesc));
				descs[cur_feat].offset = cur_off;
				cur_off += descs[cur_feat].size;
				cur_feat++;
			}
		}
	}

	/* sanity checks */
	Assert(cur_off == pfs->bytes_used && cur_feat == pfs->feat_count);

	/* copy our new ordered features into place */
	memcpy(pfs->feats, descs, sizeof(AllocatedPageFeatureDesc) * pfs->feat_count);
}

/* expose the builtin cluster_page_features feature flags as boolean yes/no GUCs */
void
SetExtendedFeatureConfigOptions()
{
#ifndef FRONTEND
	int i;

	for (i = 0; i < PF_MAX_FEATURE; i++)
		SetConfigOption(builtin_feature_descs[i].name, (cluster_page_features->builtin_bitmap & (1<<i)) ? "yes" : "no",
						PGC_INTERNAL, PGC_S_DYNAMIC_DEFAULT);
#endif
}

/*
 * Add a builtin feature to the feature set
 */
bool
PageFeatureSetAddFeature(PageFeatureSet pfs, PageFeature feature, uint16 size)
{
	Assert(feature >= 0 && feature < PF_MAX_FEATURE);

	return PageFeatureSetAddFeatureByName(pfs, builtin_feature_descs[feature].name, size);
}


/*
 * Add a named feature to the feature set
 *
 * If the named feature is one of the builtin set and size is 0 then use the
 * default size in the table.
 *
 * TODO: expand error handling for frontend/backend
 *
 * Using linear searches for now as most of this is done on startup and should
 * be small numbers of items.
 */
bool
PageFeatureSetAddFeatureByName(PageFeatureSet pfs, const char *name, uint16 size)
{
	int i;
	int builtin = -1;

	/* sanity check */
	Assert(pfs);

	/* check for available feature space; >= is overly cautious */
	if (pfs->feat_count >= pfs->feat_capacity)
		return false;

	/* round size up to nearest multiple of 8; XXX do we want this to be 4
	 * instead?  Don't think want to do MAXALIGN here, but maybe we should? */
	size = (size + 7) & ~7;

	/* check for available bytes space */
	if (size > pfs->bytes_managed - pfs->bytes_used)
		return false;

	/* next check for repeat of existing feature set; return error if found */
	/* TODO: do we want to instead refresh the internal size if it already
	 * exists and isn't locked? */
	for (i = 0; i < pfs->feat_count; i++)
		if (!strcmp(name, pfs->feats[i].name))
			return false;

	/* check for a builtin feature */
	for (i = 0; i < PF_MAX_FEATURE; i++)
		if (!strcmp(name, builtin_feature_descs[i].name))
		{
			/* a locked set can have additional user columns added, but no
			 * additional built-ins, so we need to return at this point */
			if (pfs->locked)
				return false;

			/* found a builtin feature, let's adjust the builtin_bitmap */
			pfs->builtin_bitmap |= (1<<i);

			builtin = i;

			if (!size)
				size = builtin_feature_descs[i].size;
			break;
		}

	/* we do not support 0-length page features; could only get here if
	 * it was a non-builtin feature with an explicit zero size. */
	if (size == 0)
		return false;

	/* now actually add this to the structure */
	strncpy(pfs->feats[pfs->feat_count].name, name, PAGE_FEATURE_NAME_LEN - 1);
	pfs->feats[pfs->feat_count].size = size;
	/* offsets are tightly packed; our offset is based on the last column's bytes */
	pfs->feats[pfs->feat_count].offset = pfs->bytes_used;
	/* record which builtin this corresponds to */
	if (builtin != -1)
	{
		pfs->feats[pfs->feat_count].isbuiltin = 1;
		pfs->feats[pfs->feat_count].builtin = builtin;
	}
	pfs->bytes_used += size;
	pfs->feat_count++;

	/* passed all checks and notes */
	return true;
}

/* read in an persistent PageFeatureSet */
PageFeatureSet
ReadPageFeatureSet(char *path)
{
	char feat_name[21];
	char *msg, *name = last_dir_separator(path);
	FILE *fp = fopen(path, "r");
	int count, size, feat_off, feat_size, tot_size, tot_cnt;
	PageFeatureSet pfs = NULL;

	// first line is "features <n> <size>"
	if (fscanf(fp, "features %d %d\n", &count, &size) != 2)
	{
		msg = "corrupted feature set file";
		goto error;
	}

	if (count < 0 || count > MAX_PAGE_FEATURES)
	{
		msg = "invalid feature count";
		goto error;
	}

	if (size < 0 || size > MaxReservedPageSize)
	{
		msg = "invalid feature total size";
		goto error;
	}

	/* we have enough to allocate our space and continue */
	/* by definition, this set will be locked, so we don't need any additional
	 * sizing capacity then we already had. */
	pfs = NewPageFeatureSet(name, size, count);

	if (!pfs)
	{
		msg = "couldn't create page feature set";
		goto error;
	}

	tot_cnt = tot_size = 0;

	/* now go line-by-line to read the feature name, offset, and length */
	while (fscanf(fp, "%20[^=]=%d,%d\n", feat_name, &feat_off, &feat_size ) == 3)
	{
		if (!strlen(feat_name))
		{
			msg = "empty feature name";
			goto error;
		}

		/* validate sanity for individual offsets/lengths; we know these are
		 * gated at least by total size, so check that now, will validate
		 * totals later */
		if (feat_off < 0 || feat_off > size || feat_size <= 0 || feat_size > size)
		{
			msg = "invalid feature offset or size";
			goto error;
		}

		/* verify that our offset matches our total size so far */
		if (feat_off != tot_size)
		{
			msg = "feature offsets do not line up";
			goto error;
		}

		/* things look good, try to add the feature to the set now */
		if (!PageFeatureSetAddFeatureByName(pfs, feat_name, feat_size))
		{
			msg = "error adding feature to set";
			goto error;
		}
		tot_size += feat_size;
		tot_cnt++;
	}

	/* end of file; validate that the count and size match our expectations */
	if (tot_cnt != count)
	{
		msg = "read different count of features than in header line";
		goto error;
	}
	if (tot_size != size)
	{
		msg = "read different byte total than in header line";
		goto error;
	}

	fclose(fp);

	/* everything passed, yay! */

	pfs->locked = true;
	return pfs;

 error:
	pg_error("error in ReadPageFeatureSet: %s", msg);
	if (pfs)
		pfree(pfs);
	if (fp)
		fclose(fp);
	return NULL;
}

/* write out persistent PageFeatureSet */
bool
WritePageFeatureSet(PageFeatureSet pfs, char *path)
{
	char *msg;
	FILE *fp;
	int tot_offset, tot_size, tot_cnt;

	/* sanity checking */
	Assert(pfs && path);

	/* ensure we have the layout we want */
	OptimizePageFeatureSet(pfs);

	/* ensure file does not already exist, we don't want to overwrite an existing page feature set */
	fp = fopen(path, "wx");		/* C11ism, probably not valid :( */

	if (!fp)
	{
		msg = "couldn't open path for writing";
		goto error;
	}

	/* XXX do we want to pre-scan our features for sanity and for counting, or
	 * just trust the structure? for now let's trust. */

	/* first line is "features <n> <size>" */
	if (fprintf(fp, "features %d %d\n", pfs->feat_count, pfs->bytes_used) < 0)
	{
		msg = "couldn't write header line";
		goto error;
	}

	tot_size = tot_cnt = tot_offset = 0;

	for (int i = 0; i < pfs->feat_count; i++)
	{
		AllocatedPageFeatureDesc *pf = &pfs->feats[i];

		if (pf->offset != tot_size || pf->size == 0)
		{
			msg = "data structure has bad data";
			goto error;
		}

		if (fprintf(fp, "%.20s=%d,%d\n", pf->name, pf->offset, pf->size) < 0)
		{
			msg = "couldn't write feature line";
			goto error;
		}
		tot_cnt++;
		tot_size += pf->size;
	}

	if (tot_size != pfs->bytes_used || tot_cnt != pfs->feat_count)
	{
		msg = "data structure doesn't match computed totals";
		goto error;
	}
	fsync(fileno(fp));
	fclose(fp);

	/* now that we've written, don't allow further modification of this structure */
	pfs->locked = true;
	return true;

 error:
	pg_error("error in WritePageFeatureSet: %s", msg);
	if (fp)
		fclose(fp);
	return false;
}

/* create new feature set with capacity */
PageFeatureSet
NewPageFeatureSet(char *name, uint16 bytes_capacity, uint16 max_features)
{
	PageFeatureSet pfs;

	/* TODO: verify unique name? */
	Assert(name);
	Assert(bytes_capacity > 0);
	Assert(max_features > 0);

	/* using malloc due to needing to run before memory manager is initialized */
	pfs = malloc(sizeof(PageFeatureSetData) + sizeof(AllocatedPageFeatureDesc) * max_features);
	strncpy(pfs->name, name, PAGE_FEATURE_NAME_LEN - 1);
	pfs->builtin_bitmap = 0;
	pfs->bytes_managed = bytes_capacity;
	pfs->bytes_used = 0;
	pfs->feat_count = 0;
	pfs->feat_capacity = max_features;
	pfs->locked = false;
	return pfs;
}

/* returns an empty locked page feature set used when no features are enabled */
static PageFeatureSet
EmptyPageFeatureSet()
{
	PageFeatureSet pfs;
	/* using malloc due to needing to run before memory manager is initialized */
	pfs = malloc(sizeof(PageFeatureSetData));
	strncpy(pfs->name, "empty", PAGE_FEATURE_NAME_LEN - 1);
	pfs->builtin_bitmap = 0;
	pfs->bytes_managed = 0;
	pfs->bytes_used = 0;
	pfs->feat_count = 0;
	pfs->feat_capacity = 0;
	pfs->locked = true;
	return pfs;
}

/* initialize everything based on a cluster name */
void
ClusterPageFeatureInit(char *data_dir, char *name)
{
	char path[MAXPGPATH];

	/* check for empty page features */
	if (!name || name[0] == '\0')
	{
		/* in memory dummy set only */
		cluster_page_features = EmptyPageFeatureSet();
		return;
	}

	sprintf(path, "%s/pg_pagefeat/%s", data_dir, name);
	cluster_page_features = ReadPageFeatureSet(path);

	if (cluster_page_features == NULL)
#ifdef FRONTEND
		pg_fatal("could't load page features from path '%s'", path);
#else
		elog(PANIC, "could't load page features from path '%s'", path);
#endif
}
