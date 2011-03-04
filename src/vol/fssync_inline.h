/*
 * Copyright 2010, Sine Nomine Associates.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef AFS_VOL_FSSYNC_INLINE_H
#define AFS_VOL_FSSYNC_INLINE_H

#include "fssync.h"

#define FSYNC_ENUMCASE(en) \
    case en: return #en

static_inline char *
FSYNC_com2string(afs_int32 command)
{
    switch (command) {
	FSYNC_ENUMCASE(SYNC_COM_CHANNEL_CLOSE);
	FSYNC_ENUMCASE(FSYNC_VOL_ON);
	FSYNC_ENUMCASE(FSYNC_VOL_OFF);
	FSYNC_ENUMCASE(FSYNC_VOL_LISTVOLUMES);
	FSYNC_ENUMCASE(FSYNC_VOL_NEEDVOLUME);
	FSYNC_ENUMCASE(FSYNC_VOL_MOVE);
	FSYNC_ENUMCASE(FSYNC_VOL_BREAKCBKS);
	FSYNC_ENUMCASE(FSYNC_VOL_DONE);
	FSYNC_ENUMCASE(FSYNC_VOL_QUERY);
	FSYNC_ENUMCASE(FSYNC_VOL_QUERY_HDR);
	FSYNC_ENUMCASE(FSYNC_VOL_QUERY_VOP);
	FSYNC_ENUMCASE(FSYNC_VOL_STATS_GENERAL);
	FSYNC_ENUMCASE(FSYNC_VOL_STATS_VICEP);
	FSYNC_ENUMCASE(FSYNC_VOL_STATS_HASH);
	FSYNC_ENUMCASE(FSYNC_VOL_STATS_HDR);
	FSYNC_ENUMCASE(FSYNC_VOL_STATS_VLRU);
	FSYNC_ENUMCASE(FSYNC_VOL_ATTACH);
	FSYNC_ENUMCASE(FSYNC_VOL_FORCE_ERROR);
	FSYNC_ENUMCASE(FSYNC_VOL_LEAVE_OFF);
	FSYNC_ENUMCASE(FSYNC_VOL_QUERY_VNODE);
	FSYNC_ENUMCASE(FSYNC_VG_QUERY);
	FSYNC_ENUMCASE(FSYNC_VG_ADD);
	FSYNC_ENUMCASE(FSYNC_VG_DEL);
	FSYNC_ENUMCASE(FSYNC_VG_SCAN);
	FSYNC_ENUMCASE(FSYNC_VG_SCAN_ALL);

    default:
	return "**UNKNOWN**";
    }
}

static_inline char *
FSYNC_reason2string(afs_int32 reason)
{
    switch (reason) {
	FSYNC_ENUMCASE(SYNC_REASON_NONE);
	FSYNC_ENUMCASE(SYNC_REASON_MALFORMED_PACKET);
	FSYNC_ENUMCASE(SYNC_REASON_NOMEM);
	FSYNC_ENUMCASE(SYNC_REASON_ENCODING_ERROR);
	FSYNC_ENUMCASE(FSYNC_WHATEVER);
	FSYNC_ENUMCASE(FSYNC_SALVAGE);
	FSYNC_ENUMCASE(FSYNC_MOVE);
	FSYNC_ENUMCASE(FSYNC_OPERATOR);
	FSYNC_ENUMCASE(FSYNC_EXCLUSIVE);
	FSYNC_ENUMCASE(FSYNC_UNKNOWN_VOLID);
	FSYNC_ENUMCASE(FSYNC_HDR_NOT_ATTACHED);
	FSYNC_ENUMCASE(FSYNC_NO_PENDING_VOL_OP);
	FSYNC_ENUMCASE(FSYNC_VOL_PKG_ERROR);
	FSYNC_ENUMCASE(FSYNC_UNKNOWN_VNID);
	FSYNC_ENUMCASE(FSYNC_WRONG_PART);
	FSYNC_ENUMCASE(FSYNC_BAD_STATE);
	FSYNC_ENUMCASE(FSYNC_BAD_PART);
	FSYNC_ENUMCASE(FSYNC_PART_SCANNING);
    default:
	return "**UNKNOWN**";
    }
}

#undef FSYNC_ENUMCASE

#endif /* AFS_VOL_FSSYNC_INLINE_H */
