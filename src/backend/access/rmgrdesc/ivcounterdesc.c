/*-------------------------------------------------------------------------
 *
 * ivcounterdesc.c
 *	  rmgr descriptor routines for IV Counters
 *
 * Copyright (c) 2024, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/ivcounterdesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xlog.h"
#include "access/xlogreader.h"

void
ivcounter_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;
	uint64	   *data = (uint64 *) rec;

	if (info == XL_IVCOUNTER_LOG)
		appendStringInfo(buf, "setcnt " UINT64_FORMAT, *data);
}

const char *
ivcounter_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XL_IVCOUNTER_LOG:
			id = "LOG";
			break;
	}

	return id;
}
