/* rxgk/rxgk_procs.c - Server-side RPC procedures for RXGK */
/*
 * Copyright (C) 2013, 2014 by the Massachusetts Institute of Technology.
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
    rxgk_key encrypt_key = NULL;
    afs_int32 ret, kvno = 0, enctype = 0;
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
    ret = rxgk_service_get_long_term_key(z_call, &encrypt_key, &kvno, &enctype);
    if (ret != 0)
	goto cleanup;

    ret = rxgk_combinetokens_common(z_call, &t0, &t1, options, new_token,
				    info, user_ids, nuid, encrypt_key, kvno,
				    enctype);
cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_Token, &t0);
    xdr_free((xdrproc_t)xdr_RXGK_Token, &t1);
    /* user_ids is consumed by rxgk_combinetokens_common. */
    return ret;
}

afs_int32
SRXGK_AFSCombineTokens(struct rx_call *z_call, RXGK_Data *user_tok,
		       RXGK_Data *cm_tok, RXGK_CombineOptions *options,
		       afsUUID destination, RXGK_Data *new_token,
		       RXGK_TokenInfo *info)
{
    return RXGEN_OPCODE;
}
