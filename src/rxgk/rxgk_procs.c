/* prototype/prototype.c - Server-side RPC procedures for RXGK */
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

#include <gssapi/gssapi.h>

#include <rx/rxgk.h>

/* Must use xdr_alloc to allocate data for output structures.
 * It will be freed by the server-side stub code using osi_free. */

afs_int32
SRXGK_GSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
		   RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
		   RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
		   u_int *gss_major_status, u_int *gss_minor_status,
		   RXGK_Data *rxgk_info)
{
    afs_int32 ret = 0;
    size_t len;
    char *tmp;

    /* XXXBJK This routine is a stub implementation */

    /* fill output_token_buffer */
    len = 8;
    tmp = xdr_alloc(len);
    if (tmp == NULL) {
        ret = RXGEN_SS_MARSHAL;
        goto fail;
    }
    memcpy(tmp, "KADUKtok", len);
    output_token_buffer->len = len;
    output_token_buffer->val = tmp;

    /* fill opaque_out */
    len = 12;
    tmp = xdr_alloc(len);
    if (tmp == NULL) {
        ret = RXGEN_SS_MARSHAL;
        goto fail;
    }
    memcpy(tmp, "opaqueOPAQUEopaque", len);
    opaque_out->len = len;
    opaque_out->val = tmp;

    /* set the GSS status to dummy values for now */
    *gss_major_status = GSS_S_COMPLETE;
    *gss_minor_status = 0;

    /* fill the output rxgk_info */
    len = 16;
    tmp = xdr_alloc(len);
    if (tmp == NULL) {
        ret = RXGEN_SS_MARSHAL;
        goto fail;
    }
    memcpy(tmp, "This should be an encrypted blob but is plaintext", len);
    rxgk_info->len = len;
    rxgk_info->val = tmp;

fail:
    return ret;
}


afs_int32
SRXGK_CombineTokens(struct rx_call *z_call, RXGK_Data *token0,
		    RXGK_Data *token1, RXGK_CombineOptions *options,
		    RXGK_Data *new_token, RXGK_TokenInfo *info)
{
    afs_int32 ret = 0;
    size_t len;
    char *tmp;

    /* XXXBJK This routine is a stub implementation */

    /* fill in the new_token */
    len = 8;
    tmp = xdr_alloc(len);
    if (tmp == NULL) {
        ret = RXGEN_SS_MARSHAL;
        goto fail;
    }
    memcpy(tmp, "This token has no meaning", len);
    new_token->len = len;
    new_token->val = tmp;

    /* what values did we end up with? */
    info->errorcode = RXGK_INCONSISTENCY;
    info->enctype = 1; /* des-cbc-crc */
    info->level = RXGK_LEVEL_CLEAR;
    info->lifetime = 1;
    info->bytelife = 1;
    info->expiration = 0;

fail:
    return ret;
}
