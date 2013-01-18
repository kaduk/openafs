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
#include <gssapi/gssapi_krb5.h>

#include <rx/rxgk.h>

/* One week */
#define MAX_LIFETIME	(60 * 60 * 24 * 7)
/* One TiB */
#define MAX_BYTELIFE	40

/* The layout of the opaque blob we expect the client to return to us. */
struct rxgk_opaque {
    afs_int32 enctype;
    afs_int32 level;
    afs_int32 lifetime;
    afs_int32 bytelife;
    gss_ctx_id_t gss_ctx;
} __attribute((packed));

/* Must use xdr_alloc to allocate data for output structures.
 * It will be freed by the server-side stub code using osi_free. */

static afs_int32
process_client_params(RXGK_StartParams *params, int *enctype,
		      RXGK_Level *level, int *lifetime, int *bytelife)
{
    if (params->enctypes.len == 0)
	return RXGK_BADETYPE;
    *enctype = params->enctypes.val[0];
    if (params->levels.len == 0)
	return RXGK_BADLEVEL;
    *level = params->levels.val[0];
    *lifetime = params->lifetime;
    if (*lifetime < 0 || *lifetime > MAX_LIFETIME)
	*lifetime = MAX_LIFETIME;
    *bytelife = params->bytelife;
    if (*bytelife < 0 || *bytelife > MAX_BYTELIFE)
	*bytelife = MAX_BYTELIFE;
    return 0;
}

static afs_int32
get_creds(afs_int32 *minor_status, gss_cred_id_t *creds)
{
    gss_buffer_desc name_buf;
    gss_name_t sname;
    afs_int32 ret;
    char *name = "afs-rxgk@_afs.perfluence.mit.edu";

    /* Tell gssapi-krb5 where to find the keytab. */
    krb5_gss_register_acceptor_identity(
	"/Users/kaduk/openafs/perfluence-keytab");

    name_buf.value = name;
    name_buf.length = strlen(name) + 1;
    ret = gss_import_name(minor_status, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
			  &sname);
    if (ret != 0)
	return ret;

    /* Actually get creds. */
    ret = gss_acquire_cred(minor_status, sname, 0 /* time */,
			    GSS_C_NO_OID_SET, GSS_C_ACCEPT, creds,
			    NULL /* actual mechs */, NULL /* time rec */);
    if (ret != 0)
	return ret;

    /* (void)gss_release_name(minor_status, &sname); */

    *minor_status = 0;
    return 0;
}

afs_int32
SRXGK_GSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
		   RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
		   RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
		   u_int *gss_major_status, u_int *gss_minor_status,
		   RXGK_Data *rxgk_info)
{
    gss_buffer_desc gss_token_in, gss_token_out;
    gss_cred_id_t creds;
    gss_ctx_id_t gss_ctx;
    gss_name_t client_name;
    struct rxgk_opaque local_opaque;
    RXGK_Level level;
    afs_int32 ret = 0;
    size_t len;
    char *tmp;
    int enctype, lifetime, bytelife;

    /* See what the client sent us. */
    if (opaque_in->len == 0) {
	gss_ctx = NULL;
    } else {
	if (opaque_in->len != sizeof(local_opaque)) {
	    dprintf(2, "Evil client detected\n");
	    return RXGK_DATA_LEN;
	}
	memcpy(&local_opaque, opaque_in->val, sizeof(local_opaque));
	/* XXX nefarious client will crash us */
	/* XXX also we leak memory */
	gss_ctx = local_opaque.gss_ctx;
    }

    ret = process_client_params(client_start, &enctype, &level, &lifetime,
				&bytelife);
    local_opaque.enctype = enctype;
    local_opaque.level = level;
    local_opaque.lifetime = lifetime;
    local_opaque.bytelife = bytelife;
    /* XXX compare against input token, further validation */

    /* Need credentials before we can accept a security context. */
    ret = get_creds(gss_minor_status, &creds);
    if (ret != 0) {
	dprintf(2, "No credentials!\n");
	printf("get_creds gives major %i minor %i\n",
	       ret, *gss_minor_status);
	return RXGK_INCONSISTENCY;
    }

    /* prepare the input token */
    if (input_token_buffer->len > 0) {
	printf("using client-supplied input token of length %i\n",
	       input_token_buffer->len);
	gss_token_in.length = input_token_buffer->len;
	gss_token_in.value = input_token_buffer->val;
    } else {
	printf("no input token\n");
	gss_token_in.length = 0;
	gss_token_in.value = NULL;
    }

    /* Call into GSS */
    *gss_major_status = gss_accept_sec_context(gss_minor_status, &gss_ctx,
					       creds, &gss_token_in,
					       GSS_C_NO_CHANNEL_BINDINGS,
					       &client_name, NULL,
					       &gss_token_out,
					       NULL /* ret flags */,
					       NULL /* time rec */,
					       NULL /* del. cred handle */);

    printf("GSS accept_sec_context gives major %i minor %i\n",
	   *gss_major_status, *gss_minor_status);

    /* fill output_token_buffer */
    if (gss_token_out.length > 0) {
	len = gss_token_out.length;
	tmp = xdr_alloc(len);
	if (tmp == NULL) {
	    ret = RXGEN_SS_MARSHAL;
	    goto fail;
	}
	memcpy(tmp, gss_token_out.value, len);
	output_token_buffer->len = len;
	output_token_buffer->val = tmp;
    }

    /* fill opaque_out */
    local_opaque.gss_ctx = gss_ctx;
    len = sizeof(local_opaque);
    tmp = xdr_alloc(len);
    if (tmp == NULL) {
        ret = RXGEN_SS_MARSHAL;
        goto fail;
    }
    memcpy(tmp, &local_opaque, len);
    opaque_out->len = len;
    opaque_out->val = tmp;

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
