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
#include <hcrypto/rand.h>

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
	"/Users/kaduk/openafs/perfluence.keytab");

    name_buf.value = name;
    name_buf.length = strlen(name);
    ret = gss_import_name(minor_status, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
			  &sname);
    if (ret != 0)
	return ret;

    /* Actually get creds. */
    ret = gss_acquire_cred(minor_status, GSS_C_NO_NAME, 0 /* time */,
			    (gss_OID_set)gss_mech_set_krb5, GSS_C_ACCEPT, creds,
			    NULL /* actual mechs */, NULL /* time rec */);
    if (ret != 0)
	return ret;

    (void)gss_release_name(minor_status, &sname);

    *minor_status = 0;
    return 0;
}

/* Allocates its mic parameter, the caller must arrange for it to be freed. */
static afs_uint32
mic_startparams(afs_uint32 *gss_minor_status, gss_ctx_id_t gss_ctx,
		RXGK_Data *mic, RXGK_StartParams *client_start)
{
    XDR xdrs;
    gss_buffer_desc startparams, mic_buffer;
    afs_uint32 ret;
    u_int len;
    void *tmp = NULL;

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	ret = GSS_S_FAILURE;
	dprintf(2, "xdrlen for StartParams says they are invalid\n");
	goto out;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    tmp = malloc(len);
    if (tmp == NULL) {
	dprintf(2, "Couldn't allocate for encoding StartParams\n");
	return GSS_S_FAILURE;
    }
    xdrmem_create(&xdrs, tmp, len, XDR_ENCODE);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	ret = GSS_S_FAILURE;
	dprintf(2, "xdrmem for StartParams says they are invalid\n");
	goto out;
    }

    /* We have the StartParams encoded in tmp, now get the mic. */
    startparams.length = len;
    startparams.value = tmp;
    ret = gss_get_mic(gss_minor_status, gss_ctx, GSS_C_QOP_DEFAULT, &startparams,
		      &mic_buffer);
    if (ret != 0)
	goto out;
    mic->len = mic_buffer.length;
    mic->val = xdr_alloc(mic->len);
    if (mic->val == NULL) {
	dprintf(2, "No memory for RXGK_Data mic\n");
	goto out;
    }
    memcpy(mic->val, mic_buffer.value, mic->len);
    ret = gss_release_buffer(gss_minor_status, &mic_buffer);

out:
    free(tmp);
    xdr_destroy(&xdrs);
    return ret;
}

static afs_uint32
pack_clientinfo(afs_uint32 *gss_minor_status, gss_ctx_id_t gss_ctx,
		RXGK_Data *rxgk_info, RXGK_ClientInfo *info)
{
    XDR xdrs;
    gss_buffer_desc info_buffer, wrapped;
    afs_uint32 ret;
    u_int len;
    int conf_state;
    void *tmp = NULL;

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_ClientInfo(&xdrs, info)) {
	ret = GSS_S_FAILURE;
	dprintf(2, "xdrlen for ClientInfo says they are invalid\n");
	goto out;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    tmp = malloc(len);
    if (tmp == NULL) {
	dprintf(2, "Couldn't allocate for encoding ClientInfo\n");
	return GSS_S_FAILURE;
    }
    xdrmem_create(&xdrs, tmp, len, XDR_ENCODE);
    if (!xdr_RXGK_ClientInfo(&xdrs, info)) {
	ret = GSS_S_FAILURE;
	dprintf(2, "xdrmem for ClientInfo says they are invalid\n");
	goto out;
    }

    info_buffer.length = len;
    info_buffer.value = tmp;
    ret = gss_wrap(gss_minor_status, gss_ctx, TRUE, GSS_C_QOP_DEFAULT,
		   &info_buffer, &conf_state, &wrapped);
    if (ret == 0 && conf_state == 0) {
	(void)gss_release_buffer(gss_minor_status, &wrapped);
	ret = GSS_S_FAILURE;
    }
    if (ret != 0)
	goto out;

    rxgk_info->val = xdr_alloc(wrapped.length);
    if (rxgk_info->val == NULL) {
	dprintf(2, "No memory for wrapped ClientInfo\n");
	ret = GSS_S_FAILURE;
	goto out;
    }
    rxgk_info->len = wrapped.length;
    memcpy(rxgk_info->val, wrapped.value, wrapped.length);
    ret = gss_release_buffer(gss_minor_status, &wrapped);

out:
    free(tmp);
    xdr_destroy(&xdrs);
    return ret;
}

afs_int32
SRXGK_GSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
		   RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
		   RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
		   u_int *gss_major_status, u_int *gss_minor_status,
		   RXGK_Data *rxgk_info)
{
    gss_buffer_desc gss_token_in, gss_token_out, k0;
    gss_cred_id_t creds;
    gss_ctx_id_t gss_ctx;
    gss_name_t client_name;
    struct rxgk_opaque local_opaque;
    RXGK_ClientInfo info;
    RXGK_Level level;
    rxgkTime start_time;
    afs_int32 ret = 0;
    afs_uint32 time_rec;
    size_t len;
    char *tmp;
    int enctype, lifetime, bytelife;

    start_time = RXGK_NOW();

    /* See what the client sent us. */
    if (opaque_in->len == 0) {
	gss_ctx = GSS_C_NO_CONTEXT;
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
					       &time_rec,
					       NULL /* del. cred handle */);

    printf("GSS accept_sec_context gives major %i minor %i\n",
	   *gss_major_status, *gss_minor_status);
    if (GSS_ERROR(*gss_major_status)) {
	/* Though the GSS negotiation failed, the RPC shall succeed. */
	ret = 0;
	goto out;
    }

    /* fill output_token_buffer */
    if (gss_token_out.length > 0) {
	len = gss_token_out.length;
	printf("Filling output_token_buffer with length %i\n", len);
	tmp = xdr_alloc(len);
	if (tmp == NULL) {
	    ret = RXGEN_SS_MARSHAL;
	    goto out;
	}
	memcpy(tmp, gss_token_out.value, len);
	output_token_buffer->len = len;
	output_token_buffer->val = tmp;
	(void)gss_release_buffer(gss_minor_status, &gss_token_out);
    }

    /* If our side is done, we don't need to give anything to the client
     * for it to give back to us. */
    if (*gss_major_status != GSS_S_COMPLETE) {
	/* Continue needed, since our GSS is not in error.
	 * Fill opaque_out so we have state when the client calls back. */
	local_opaque.gss_ctx = gss_ctx;
	len = sizeof(local_opaque);
	tmp = xdr_alloc(len);
	if (tmp == NULL) {
	    ret = RXGEN_SS_MARSHAL;
	    goto out;
	}
	memcpy(tmp, &local_opaque, len);
	opaque_out->len = len;
	opaque_out->val = tmp;
	ret = 0;
	goto out;
    }
    /* else */
    /* We're done and can generate a token, and fill in rxgk_info. */
    printf("time_rec is %u\n", time_rec);
    printf("start_time is %llu\n", start_time);
    info.errorcode = 0;
    info.enctype = enctype;
    info.level = level;
    info.lifetime = lifetime;
    info.bytelife = bytelife;
    info.expiration = start_time + time_rec * 1000 * 10;
    if ((RXGK_NOW() - start_time) > 50000) {
	/* We've been processing for 5 seconds?! */
	dprintf(2, "extended SRXGK_GSSNegotiation processing\n");
	/* five minutes only */
	info.expiration = start_time + 5 * 60 * 1000 * 10;
    }
    if (RXGK_NOW() < start_time) {
	/* time went backwards */
	info.expiration = RXGK_NOW() + 5 * 60 * 1000 * 10;
    }
    len = 20;
    tmp = xdr_alloc(len);
    if (tmp == NULL) {
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    ret = RAND_bytes(tmp, len);
    /* RAND_bytes returns 1 on success, sigh. */
    if (ret != 1) {
	dprintf(2, "no random data for server_nonce\n");
	return 1;
    }
    info.server_nonce.len = len;
    info.server_nonce.val = tmp;
    ret = mic_startparams(gss_minor_status, gss_ctx, &info.mic, client_start);
    if (ret != 0)
	goto out;
    /* Token not implemented yet. */
    ret = rxgk_make_k0(gss_minor_status, gss_ctx, &client_start->client_nonce,
		       &info.server_nonce, enctype, &k0);
    if (ret != 0)
	goto out;
    zero_rxgkdata(&info.token);

    /* Wrap the ClientInfo response and pack it as an RXGK_Data. */
    ret = pack_clientinfo(gss_minor_status, gss_ctx, rxgk_info, &info);
    if (ret != 0)
	goto out;

    (void)gss_delete_sec_context(gss_minor_status, &gss_ctx, GSS_C_NO_BUFFER);
    (void)gss_release_name(gss_minor_status, &client_name);

out:
    xdr_free((xdrproc_t)xdr_RXGK_ClientInfo, &info);
    (void)gss_release_cred(gss_minor_status, &creds);
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
