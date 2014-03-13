/* rxgk/rxgk_procs.c - Server-side RPC procedures for RXGK */
/*
 * Copyright (C) 2013 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Server-side RPC procedures for RXGK.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <errno.h>

#include <rx/rx.h>
#include <rx/rx_identity.h>
#include <rx/rxgk.h>

#include "rxgk_private.h"

afs_int32
SRXGK_GSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
		   RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
		   RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
		   afs_uint32 *gss_major_status, afs_uint32 *gss_minor_status,
		   RXGK_Data *rxgk_info)
{
#ifdef KERNEL
    /* No libgssapi in the kernel. */
    return RXGEN_OPCODE;
#else
    /* The actual backend for this routine is in rxgk_gss.c. */
    return SGSSNegotiate(z_call, client_start, input_token_buffer, opaque_in,
			 output_token_buffer, opaque_out, gss_major_status,
			 gss_minor_status, rxgk_info);
#endif
}

static afs_int32
combine_tokeninfo(RXGK_Token *t0, RXGK_Token *t1, RXGK_TokenInfo *info)
{
    if (t0->lifetime == 0)
	info->lifetime = t1->lifetime;
    else
	info->lifetime = min(t0->lifetime, t1->lifetime);
    if (t0->bytelife == 0)
	info->bytelife = t1->bytelife;
    else
	info->bytelife = min(t0->bytelife, t1->bytelife);
    info->expiration = min(t0->expirationtime, t1->expirationtime);
    if (t0->start_time > RXGK_NOW() || t1->start_time > RXGK_NOW())
	return RXGK_NOTAUTH;
    return 0;
}

static afs_int32
process_combineoptions(RXGK_CombineOptions *options, RXGK_TokenInfo *info)
{
    if (options->enctypes.len == 0)
	return RXGK_BADETYPE;
    info->enctype = options->enctypes.val[0];
    if (options->levels.len == 0)
	return RXGK_BADLEVEL;
    info->level = options->levels.val[0];
    return 0;
}

static afs_int32
copy_id(struct PrAuthName *out, struct PrAuthName *in)
{
    out->kind = in->kind;
    out->data.val = rxi_Alloc(in->data.len);
    if (out->data.val == NULL)
	return ENOMEM;
    memcpy(out->data.val, in->data.val, in->data.len);
    out->data.len = in->data.len;
    out->display.val = rxi_Alloc(in->display.len);
    if (out->display.val == NULL) {
	rxi_Free(out->data.val, in->data.len);
	return ENOMEM;
    }
    memcpy(out->display.val, in->display.val, in->display.len);
    out->display.len = in->display.len;

    return 0;
}

static afs_int32
copy_ids(struct PrAuthName *out, struct PrAuthName *in, u_int n)
{
    afs_int32 ret;
    u_int i;

    for(i = 0; i < n; ++i) {
	ret = copy_id(out + i, in + i);
	if (ret != 0) {
	    n = i + 1;
	    goto cleanup;
	}
    }
    return 0;

cleanup:
    for(i = 0; i < n; ++i) {
	xdr_free((xdrproc_t)xdr_PrAuthName, out + i);
    }
    memset(out, 0, n * sizeof(struct PrAuthName));
    return ret;
}

/*
 * Concatenate the lists of PrAuthNames in id0 and id1 (of lengths nid0 and
 * nid1), returning the list in *ids_out and the length of the output list
 * in *nid_out.
 * Callers are responsible for freeing ids_out and its contents.
 *
 * Returns com_err errors.
 */
static afs_int32
join_ids(struct PrAuthName *id0, u_int nid0, struct PrAuthName *id1,
	 u_int nid1, struct PrAuthName **ids_out, int *nid_out)
{
    afs_int32 ret;
    int nid, i;
    struct PrAuthName *ids;

    *nid_out = -1;
    *ids_out = NULL;

    nid = nid0 + nid1;
    /* XXX arbitrary limit not really supported by protocol spec */
    if (nid > 200 || nid0 == 0 || nid1 == 0)
	return RXGK_BAD_TOKEN;

    ids = xdr_alloc(nid * sizeof(struct PrAuthName));
    if (ids == NULL)
	goto cleanup;
    memset(ids, 0, nid * sizeof(struct PrAuthName));

    ret = copy_ids(ids, id0, nid0);
    if (ret != 0)
	goto cleanup;
    ret = copy_ids(ids + nid0, id1, nid1);
    if (ret != 0)
	goto cleanup;

    /* Success; transfer ownership of the storage to the caller. */
    *nid_out = nid;
    *ids_out = ids;
    ids = NULL;

cleanup:
    if (ids != NULL) {
	for(i = 0; i < nid; ++i) {
	    xdr_free((xdrproc_t)xdr_PrAuthName, ids + i);
	}
	rxi_Free(ids, nid * sizeof(struct PrAuthName));
    }
    return ret;
}

/*
 * Like rxgk_make_token, this function eats the supplied PrAuthName array
 * and frees the underlying storage during cleanup.
 */
afs_int32
rxgk_combinetokens_common(struct rx_call *z_call, RXGK_Token *t0,
			  RXGK_Token *t1, RXGK_CombineOptions *options,
			  RXGK_Data *new_token, RXGK_TokenInfo *info,
			  struct PrAuthName *user_ids, afs_int32 nuid)
{
    RXGK_TokenInfo localinfo;
    struct rx_opaque kn = RX_EMPTY_OPAQUE;
    rxgkTime now;
    rxgk_key encrypt_key = NULL;
    afs_int32 ret, kvno = 0, enctype = 0;

    memset(&localinfo, 0, sizeof(localinfo));
    now = RXGK_NOW();

    if (t0->expirationtime < now || t1->expirationtime < now) {
	ret = RXGK_EXPIRED;
	goto cleanup;
    }
    ret = combine_tokeninfo(t0, t1, &localinfo);
    if (ret != 0)
	goto cleanup;
    ret = process_combineoptions(options, &localinfo);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_combine_keys_data(&t0->K0, t0->enctype, &t1->K0, t1->enctype,
				 &kn, localinfo.enctype);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_service_get_long_term_key(z_call, &encrypt_key, &kvno, &enctype);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_make_token(new_token, &localinfo, &kn, now, user_ids, nuid,
			  encrypt_key, kvno, enctype);

cleanup:
    rxgk_release_key(&encrypt_key);
    rx_opaque_freeContents(&kn);
    return ret;
}

afs_int32
SRXGK_CombineTokens(struct rx_call *z_call, RXGK_Data *token0,
		    RXGK_Data *token1, RXGK_CombineOptions *options,
		    RXGK_Data *new_token, RXGK_TokenInfo *info)
{
    RXGK_Token t0, t1;
    struct rx_connection *conn;
    struct rx_securityClass *aobj;
    struct rxgk_sprivate *sp;
    struct PrAuthName *user_ids = NULL;
    afs_int32 ret;
    int nuid = -1;

    memset(&t0, 0, sizeof(t0));
    memset(&t1, 0, sizeof(t1));

    conn = rx_ConnectionOf(z_call);
    aobj = rx_SecurityObjectOf(conn);
    sp = aobj->privateData;

    ret = rxgk_extract_token(token0, &t0, sp->getkey, sp->rock);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_extract_token(token1, &t1, sp->getkey, sp->rock);
    if (ret != 0)
	goto cleanup;
    ret = join_ids(t0.identities.val, t0.identities.len, t1.identities.val,
		   t1.identities.len, &user_ids, &nuid);
    if (ret != 0)
	goto cleanup;

    ret = rxgk_combinetokens_common(z_call, &t0, &t1, options, new_token,
				    info, user_ids, nuid);
cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_Token, &t0);
    xdr_free((xdrproc_t)xdr_RXGK_Token, &t1);
    return ret;
}

afs_int32
SRXGK_AFSCombineTokens(struct rx_call *z_call, RXGK_Data *token0,
		       RXGK_Data *token1, RXGK_CombineOptions *options,
		       afsUUID destination, RXGK_Data *new_token,
		       RXGK_TokenInfo *info)
{
    return RXGEN_OPCODE;
}
