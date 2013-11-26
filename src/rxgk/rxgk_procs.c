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
#include <errno.h>

#include <rx/rxgk.h>

#include "rxgk_private.h"

/* One week */
#define MAX_LIFETIME	(60 * 60 * 24 * 7)
/* One TiB */
#define MAX_BYTELIFE	40

/* Must use xdr_alloc to allocate data for output structures.
 * It will be freed by the server-side stub code using osi_free. */

/*
 * Process the client's suggested starting parameters and determine what the
 * actual values of the parameters will be (or that the client's suggestion
 * was unacceptable).
 * Final values are stored in the TokenInfo struct for convenience.
 * This "local tokeninfo" will be the source of truth for information about
 * the token being constructed.
 *
 * Returns an RX error code.
 */
static afs_int32
process_client_params(RXGK_StartParams *params, RXGK_TokenInfo *info)
{

    info->errorcode = 0;
    info->expiration = -1;
    if (params->enctypes.len == 0)
	return RXGK_BADETYPE;
    info->enctype = params->enctypes.val[0];
    if (params->levels.len == 0)
	return RXGK_BADLEVEL;
    info->level = params->levels.val[0];
    info->lifetime = params->lifetime;
    if (info->lifetime < 0 || info->lifetime > MAX_LIFETIME)
	info->lifetime = MAX_LIFETIME;
    info->bytelife = params->bytelife;
    if (info->bytelife < 0 || info->bytelife > MAX_BYTELIFE)
	info->bytelife = MAX_BYTELIFE;
    return 0;
}

/*
 * Put cached GSS acceptor credentials in creds.
 * These creds should not be released by the caller.
 * Returns GSS error codes with corresponding minor status.
 */
static afs_int32
get_creds(struct rx_call *call, gss_cred_id_t *creds)
{
    struct rxgk_gss_sspecific_data *gk;
    struct rx_connection *conn = NULL;
    struct rx_service *svc = NULL;
    afs_int32 ret;

    conn = rx_ConnectionOf(call);
    svc = rx_ServiceOf(conn);
    gk = rx_GetServiceSpecific(svc, RXGK_NEG_SSPECIFIC_GSS);
    if (gk == NULL)
	return RXGK_INCONSISTENCY;
    if (gk->expires > 0 && gk->expires < RXGK_NOW()) {
	dprintf(2, "cached credentials expired!\n");
	return RXGK_INCONSISTENCY;
    }
    *creds = gk->creds;
    return 0;
}

/*
 * Set a token expiration time.  Use the GSSAPI context lifetime as a guide,
 * but also enforce local policy.
 */
static rxgkTime
get_expiration(rxgkTime start, afs_uint32 gss_lifetime)
{
    rxgkTime ret;
    rxgkTime now = RXGK_NOW();

    printf("time_rec is %u\n", gss_lifetime);
    printf("start_time is %llu\n", start);
    ret = start + gss_lifetime * 1000 * 1000 * 10;
    if ((now - start) > 50000000) {
	/* We've been processing for 5 seconds?! */
	dprintf(2, "extended SRXGK_GSSNegotiation processing\n");
	/* five minutes only */
	ret = start + 5 * 60 * 1000 * 1000 * 10;
    }
    if (now < start) {
	/* time went backwards */
	ret = now + 5 * 60 * 1000 * 1000 * 10;
    }

    return ret;
}

/*
 * Copy the fields from a TokenInfo into a ClientInfo.
 * ClientInfo is a superset of TokenInfo.
 */
static void
tokeninfo_to_clientinfo(RXGK_ClientInfo *client, RXGK_TokenInfo *local)
{

    client->errorcode = local->errorcode;
    client->enctype = local->enctype;
    client->level = local->level;
    client->lifetime = local->lifetime;
    client->bytelife = local->bytelife;
    client->expiration = local->expiration;
    return;
}

/*
 * Copy the fields from a TokenInfo to a Token.
 * Token is not a complete superset of TokenInfo; errorcode is ignored.
 */
static void
tokeninfo_to_token(RXGK_Token *token, RXGK_TokenInfo *info)
{

    token->enctype = info->enctype;
    token->level = info->level;
    token->lifetime = info->lifetime;
    token->bytelife = info->bytelife;
    token->expirationtime = info->expiration;
    return;
}

/*
 * XDR-encode the StartPArams structure, and compute a MIC of it using the
 * provided gss context.
 * Allocates its mic parameter, the caller must arrange for it to be freed.
 */
static afs_uint32
mic_startparams(afs_uint32 *gss_minor_status, gss_ctx_id_t gss_ctx,
		RXGK_Data *mic, RXGK_StartParams *client_start)
{
    XDR xdrs;
    gss_buffer_desc startparams, mic_buffer;
    afs_uint32 ret;
    u_int len;

    memset(&startparams, 0, sizeof(startparams));

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	ret = GSS_S_FAILURE;
	dprintf(2, "xdrlen for StartParams says they are invalid\n");
	goto out;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    startparams.value = malloc(len);
    if (startparams.value == NULL) {
	dprintf(2, "Couldn't allocate for encoding StartParams\n");
	return GSS_S_FAILURE;
    }
    startparams.length = len;
    xdrmem_create(&xdrs, startparams.value, len, XDR_ENCODE);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	ret = GSS_S_FAILURE;
	dprintf(2, "xdrmem for StartParams says they are invalid\n");
	goto out;
    }

    /* We have the StartParams encoded, now get the mic. */
    ret = gss_get_mic(gss_minor_status, gss_ctx, GSS_C_QOP_DEFAULT, &startparams,
		      &mic_buffer);
    if (ret != 0)
	goto out;
    /* Must double-buffer here, as GSS allocations might not be freed by XDR. */
    mic->val = xdr_alloc(mic_buffer.length);
    if (mic->val == NULL) {
	dprintf(2, "No memory for RXGK_Data mic\n");
	goto out;
    }
    mic->len = mic_buffer.length;
    memcpy(mic->val, mic_buffer.value, mic->len);
    ret = gss_release_buffer(gss_minor_status, &mic_buffer);

out:
    free(startparams.value);
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * XDR-encode the proviced ClientInfo structure, and encrypt it to
 * the client using the provided GSS context.
 * The contents of rxgk_info are allocated and the caller must arrange for
 * them to be freed.
 * Returns a GSS error code, with corresponding minor status.  We fake up
 * a minor status for non-GSS failures (e.g., XDR encoding issues).
 */
static afs_uint32
pack_clientinfo(afs_uint32 *minor_status, gss_ctx_id_t gss_ctx,
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
	*minor_status = RXGEN_SS_MARSHAL;
	dprintf(2, "xdrlen for ClientInfo says they are invalid\n");
	goto out;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    tmp = malloc(len);
    if (tmp == NULL) {
	dprintf(2, "Couldn't allocate for encoding ClientInfo\n");
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    xdrmem_create(&xdrs, tmp, len, XDR_ENCODE);
    if (!xdr_RXGK_ClientInfo(&xdrs, info)) {
	ret = GSS_S_FAILURE;
	*minor_status = RXGEN_SS_MARSHAL;
	dprintf(2, "xdrmem for ClientInfo says they are invalid\n");
	goto out;
    }

    info_buffer.length = len;
    info_buffer.value = tmp;
    ret = gss_wrap(minor_status, gss_ctx, TRUE, GSS_C_QOP_DEFAULT,
		   &info_buffer, &conf_state, &wrapped);
    if (ret == 0 && conf_state == 0) {
	(void)gss_release_buffer(minor_status, &wrapped);
	ret = GSS_S_FAILURE;
	*minor_status = GSS_S_BAD_QOP;
    }
    if (ret != 0)
	goto out;

    rxgk_info->val = xdr_alloc(wrapped.length);
    if (rxgk_info->val == NULL) {
	dprintf(2, "No memory for wrapped ClientInfo\n");
	(void)gss_release_buffer(minor_status, &wrapped);
	ret = GSS_S_FAILURE;
	*minor_status = ENOMEM;
	goto out;
    }
    rxgk_info->len = wrapped.length;
    memcpy(rxgk_info->val, wrapped.value, wrapped.length);
    ret = gss_release_buffer(minor_status, &wrapped);

out:
    free(tmp);
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Take the input RXGK_Token and XDR-encode it, returning the result in
 * packed_token.  The caller is responsible for freeing the memory contained
 * in packed_token.
 *
 * Returns RX errors.
 */
static afs_int32
pack_token(RXGK_Token *token, RXGK_Data *packed_token)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	dprintf(2, "xdrlen for Token says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    packed_token->val = xdr_alloc(len);
    if (packed_token->val == NULL) {
	dprintf(2, "Couldn't allocate for encoding Token\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    packed_token->len = len;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, packed_token->val, len, XDR_ENCODE);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	dprintf(2, "xdrmem for Token says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    ret = 0;

out:
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Take the input TokenContainer and XDR-encode it, returning the result
 * in 'out'.  The caller is responsible for freeing the memory contained
 * in 'out'.
 *
 * Returns RX errors.
 */
static afs_int32
pack_container(RXGK_TokenContainer *container, RXGK_Data *out)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	dprintf(2, "xdrlen for TokenContainer says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    out->val = xdr_alloc(len);
    if (out->val == NULL) {
	dprintf(2, "Couldn't allocate for encoding TokenContainer\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    out->len = len;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, out->val, len, XDR_ENCODE);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	dprintf(2, "xdrmem for TokenContainer says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    ret = 0;

out:
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Take the input token, encode it, encrypt that blob, populate a
 * TokenContainer with the encrypted token, kvno, and enctype, and encode
 * the resulting TokenContainer into 'out'.
 *
 * Returns RX errors.
 */
static afs_int32
pack_wrap_token(rxgk_key server_key, afs_int32 kvno, afs_int32 enctype,
		RXGK_Token *token, RXGK_Data *out)
{
    RXGK_Data packed_token, encrypted_token;
    RXGK_TokenContainer container;
    afs_int32 ret;

    zero_rxgkdata(&packed_token);
    zero_rxgkdata(&encrypted_token);
    zero_rxgkdata(out);
    container.encrypted_token.len = 0;
    container.encrypted_token.val = NULL;

    /* XDR-encode the token in to packed_token. */
    ret = pack_token(token, &packed_token);
    if (ret != 0)
	goto out;

    ret = encrypt_in_key(server_key, RXGK_SERVER_ENC_TOKEN, &packed_token,
			 &encrypted_token);
    if (ret != 0)
	goto out;
    ret = rx_opaque_populate(&container.encrypted_token, encrypted_token.val,
			     encrypted_token.len);
    if (ret != 0)
	goto out;
    container.kvno = kvno;
    container.enctype = enctype;

    /* Now the token container is populated; time to encode it into 'out'. */
    ret = pack_container(&container, out);
    if (ret != 0)
	goto out;

out:
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packed_token);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &encrypted_token);
    xdr_free((xdrproc_t)xdr_RXGK_TokenContainer, &container);
    return ret;
}

/*
 * Convert the given gss_name_t into both an exported name used for
 * authorization comparisons and a display name for display, placing
 * those in the appropriate fields of the PrAuthName structure, and
 * setting its type appropriately.
 *
 * Returns GSS-API major/minor pairs.
 */
static afs_uint32
fill_token_identity(afs_uint32 *minor, PrAuthName *identity, gss_name_t name)
{
    gss_buffer_desc exported_name, display_name;
    afs_uint32 ret, dummy;

    memset(&exported_name, 0, sizeof(exported_name));
    memset(&display_name, 0, sizeof(display_name));

    ret = gss_export_name(minor, name, &exported_name);
    if (ret != 0)
	goto out;
    ret = gss_display_name(minor, name, &display_name, NULL);
    if (ret != 0)
	goto out;

    identity->kind = 2;		/* PRAUTHTYPE_GSS */
    ret = rx_opaque_populate(&identity->data, exported_name.value,
			     exported_name.length);
    if (ret != 0) {
	ret = GSS_S_FAILURE;
	*minor = ENOMEM;
	goto out;
    }
    ret = rx_opaque_populate(&identity->display, display_name.value,
			     display_name.length);
    if (ret != 0) {
	ret = GSS_S_FAILURE;
	*minor = ENOMEM;
	goto out;
    }
out:
    (void)gss_release_buffer(&dummy, &exported_name);
    (void)gss_release_buffer(&dummy, &display_name);
    return ret;
}

/*
 * Create a single PrAuthName structure containing the specified identity.
 * Will be used to create a token (with that single identity).
 *
 * Returns GSS major/minor pairs.
 */
static afs_uint32
make_single_identity(afs_uint32 *minor, PrAuthName **identity, gss_name_t name)
{
    *identity = xdr_alloc(sizeof(**identity));
    if (*identity == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }
    return fill_token_identity(minor, *identity, name);
}

/*
 * Grab the getkey service-specific data for this connection, and use
 * its getkey function to get a key with which to encrypt a token.
 * In principle, we could have hooks to allow the idea of an "active kvno",
 * so that a higher kvno than is used could be present in the database
 * to allow transparent rekeying when keys must be distributed amongst
 * multiple hosts.
 * For now, though, just use the highest kvno.
 *
 * Returns RX errors.
 */
static afs_int32
get_long_term_key(struct rx_call *acall, rxgk_key *key, afs_int32 *kvno,
		  afs_int32 *enctype)
{
    struct rx_connection *conn;
    struct rx_service *svc;
    struct rxgk_getkey_sspecific_data *gk;
    afs_int32 ret;

    conn = rx_ConnectionOf(acall);
    svc = rx_ServiceOf(conn);
    gk = rx_GetServiceSpecific(svc, RXGK_NEG_SSPECIFIC_GETKEY);

    return (*gk->getkey)(gk->rock, kvno, enctype, key);
}

/*
 * Create a token from the specified TokenInfo, key, start time, and list
 * of identities.  Encrypts the token and stores it as an rx_opaque.
 * Returns RX errors.
 */
static afs_int32
make_token(struct rx_opaque *out, RXGK_TokenInfo *info, gss_buffer_t k0,
	   rxgkTime start, PrAuthName *identities, int nids, rxgk_key key,
	   afs_int32 kvno, afs_int32 enctype)
{
    RXGK_Token token;
    afs_int32 ret;

    memset(&token, 0, sizeof(token));

    /* Get the tokeninfo values from the authoritative source. */
    tokeninfo_to_token(&token, info);

    /* Create the rest of the token. */
    token.starttime = start;
    token.K0.val = xdr_alloc(k0->length);
    if (token.K0.val == NULL)
	return RXGEN_SS_MARSHAL;
    memcpy(token.K0.val, k0->value, k0->length);
    token.K0.len = k0->length;
    token.identities.len = nids;
    token.identities.val = identities;
    ret = pack_wrap_token(key, kvno, enctype, &token, out);
    xdr_free((xdrproc_t)xdr_RXGK_Token, &token);
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
    RXGK_ClientInfo info;
    RXGK_TokenInfo localinfo;
    PrAuthName *identity;
    RXGK_Level level;
    rxgkTime start_time;
    rxgk_key key;
    afs_int32 ret, kvno = 0, enctype = 0;
    afs_uint32 time_rec, dummy;
    size_t len;
    char *tmp;

    /* Zero out all the stack-allocated stuff so we can unconditionally free
     * their contents at the end. */
    memset(&gss_token_in, 0, sizeof(gss_token_in));
    memset(&gss_token_out, 0, sizeof(gss_token_out));
    memset(&k0, 0, sizeof(k0));
    memset(&key, 0, sizeof(key));
    creds = GSS_C_NO_CREDENTIAL;
    gss_ctx = GSS_C_NO_CONTEXT;
    client_name = GSS_C_NO_NAME;
    memset(&info, 0, sizeof(info));
    memset(&localinfo, 0, sizeof(localinfo));
    identity = NULL;
    *gss_major_status = *gss_minor_status = 0;

    start_time = RXGK_NOW();

    /* See what the client sent us. */
    if (opaque_in->len != 0) {
	/* We don't support multi-round negotiation yet.  Abort. */
	ret = RX_INVALID_OPERATION;
	goto out;
    }

    /* Get a validated local copy of the various parameters in localinfo. */
    ret = process_client_params(client_start, &localinfo);
    if (ret != 0)
	goto out;

    /* Need credentials before we can accept a security context. */
    ret = get_creds(z_call, &creds);
    if (ret != 0) {
	dprintf(2, "No credentials!\n");
	goto out;
    }

    /* prepare the input token */
    if (input_token_buffer->len > 0) {
	printf("using client-supplied input token of length %i\n",
	       input_token_buffer->len);
	gss_token_in.length = input_token_buffer->len;
	gss_token_in.value = input_token_buffer->val;
    } else {
	/* Already initialized to zero. */
	printf("no input token\n");
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
    }

    /* If our side is done, we don't need to give anything to the client
     * for it to give back to us. */
    if (*gss_major_status != GSS_S_COMPLETE) {
	/* Continue needed, since our GSS is not in error. */
	/* We *should* fill opaque_out, but instead return an error as we
	 * do not support multi-round mechanism exchanges yet. */
	ret = RX_INVALID_OPERATION;
	goto out;
    }
    /* else */
    /* We're done and can generate a token and tokeninfo. */
    localinfo.expiration = get_expiration(start_time, time_rec);

    /* Fill the ClientInfo from the source of truth. */
    tokeninfo_to_clientinfo(&info, &localinfo);

    /* 20-byte nonce is UUID length, used elsewhere. */
    ret = rxgk_nonce(&info.server_nonce, 20);
    if (ret != 0)
	goto out;
    *gss_major_status = mic_startparams(gss_minor_status, gss_ctx, &info.mic,
					client_start);
    if (GSS_ERROR(*gss_major_status))
	goto out;
    *gss_major_status = rxgk_make_k0(gss_minor_status, gss_ctx,
				     &client_start->client_nonce,
				     &info.server_nonce, localinfo.enctype, &k0);
    if (GSS_ERROR(*gss_major_status))
	goto out;

    *gss_major_status = make_single_identity(gss_minor_status, &identity, 
					     client_name);
    if (GSS_ERROR(*gss_major_status)) {
	/* Must free here, as the success case will be freed when make_token()
	 * frees its identity field. */
	xdr_free((xdrproc_t)xdr_PrAuthName, &identity);
	goto out;
    }
    /* Do not bother making a token if we have a policy error. */
    if (localinfo.errorcode != 0)
	goto out;
    /* Get a key to encrypt the token in. */
    ret = get_long_term_key(z_call, &key, &kvno, &enctype);
    if (ret != 0)
	goto out;
    ret = make_token(&info.token, &localinfo, &k0, start_time, identity, 1, key,
		     kvno, enctype);
    /* Clean up right away so as to not leave key material around */
    release_key(&key);
    if (ret != 0)
	goto out;

    /* Wrap the ClientInfo response and pack it as an RXGK_Data. */
    *gss_major_status = pack_clientinfo(gss_minor_status, gss_ctx, rxgk_info,
					&info);
    if (GSS_ERROR(*gss_major_status))
	goto out;

out:
    /* gss_token_in aliases XDR-allocated storage */
    (void)gss_release_buffer(&dummy, &gss_token_out);
    (void)gss_release_buffer(&dummy, &k0);
    (void)gss_delete_sec_context(&dummy, &gss_ctx, GSS_C_NO_BUFFER);
    (void)gss_release_name(&dummy, &client_name);
    xdr_free((xdrproc_t)xdr_RXGK_ClientInfo, &info);
    /* localinfo is entirely scalar types and need not be freed. */

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

afs_int32
SRXGK_AFSCombineTokens(struct rx_call *z_call, RXGK_Data *token0,
		       RXGK_Data *token1, RXGK_CombineOptions *options,
		       afsUUID destination, RXGK_Data *new_token,
		       RXGK_TokenInfo *info)
{
    /* XXXBJK This routine is a stub implementation */

    return 0;
}
