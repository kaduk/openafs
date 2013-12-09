/* rxgk/rxgk_gss.c - RXGK routines that interface with the GSS-API */
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
 * RXGK routines that involve GSS types or make calls into the GSS-API
 * library.
 * These routines must be separated out into their own object file
 * because there are rxgk consumers (such as the kernel cache manager)
 * which do not have a GSS-API library available.
 *
 * In particular, this file contains the core routines for performing
 * both sides of the GSS negotiation loop -- what the client uses to
 * get a token, and the entire server-side backend for SRXGK_GSSNegotiate.
 * Both of these have a number of helper routines which, though they do
 * not directly interact with GSSAPI types, are best placed as file-local
 * helpers for the core routines in question.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <rx/rx.h>
#include <rx/rxgk.h>
#include <gssapi/gssapi.h>
#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif
#include <errno.h>

#include "rxgk_private.h"

/* XXX There should be a better API for this. */
static ssize_t
etype_to_len(int etype)
{

    switch(etype)
    {
	case 1: return 7;
	case 2: return 7;
	case 3: return 7;
	case 5: return 21;
	case 7: return 21;
	case 16: return 21;
	case 17: return 16;
	case 18: return 32;
	default: return -1;
    }
}

/*
 * Generate a token master key from a complete GSS security context and
 * some other data.  Used by both client and server.
 */
static afs_uint32
rxgk_make_k0(afs_uint32 *minor_status, gss_ctx_id_t gss_ctx,
	     RXGK_Data *client_nonce, RXGK_Data *server_nonce, int enctype,
	     gss_buffer_t key)
{
    gss_buffer_desc seed;
    ssize_t len;
    afs_uint32 ret;

    len = etype_to_len(enctype);
    if (len == -1) {
	*minor_status = RXGK_BADETYPE;
	return GSS_S_FAILURE;
    }
    seed.length = client_nonce->len + server_nonce->len;
    seed.value = rxi_Alloc(seed.length);
    if (seed.value == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    memcpy(seed.value, client_nonce->val, client_nonce->len);
    memcpy(seed.value + client_nonce->len, server_nonce->val, server_nonce->len);

    ret = gss_pseudo_random(minor_status, gss_ctx, GSS_C_PRF_KEY_FULL,
			    &seed, len, key);

    rxi_Free(seed.value, seed.length);
    return ret;
}


/* Routines for a client obtaining a token. */

/*
 * Populate a StartParams structure.
 * Just use fixed values for now.
 *
 * Returns RX error codes.
 */
static afs_int32
fill_start_params(RXGK_StartParams *params, RXGK_Level level)
{
    void *tmp;
    size_t len;
    int ret;

    /* enctypes */
    len = 2;
    tmp = xdr_alloc(len * sizeof(int));
    if (tmp == NULL) {
	return RXGEN_CC_MARSHAL;
    }
    params->enctypes.len = len;
    params->enctypes.val = tmp;
    params->enctypes.val[0] = 18;
    params->enctypes.val[1] = 17;
   
    /* security levels */
    len = 1;
    tmp = xdr_alloc(len * sizeof(RXGK_Level));
    if (tmp == NULL) {
	return RXGEN_CC_MARSHAL;
    }
    params->levels.len = len;
    params->levels.val = tmp;
    params->levels.val[0] = level;

    /* lifetimes (advisory) */
    params->lifetime = 60 * 60 * 10;	/* 10 hours */
    params->bytelife = 30;		/* 1 GiB */

    /* Use a random nonce; 20 bytes is UUID-length. */
    ret = rxgk_nonce(&params->client_nonce, 20);
    if (ret != 0)
	return ret;

    return 0;
}

/*
 * Import the (GSS) name of the remote server to contact.
 *
 * Returns GSS major/minor pairs.
 */
static afs_uint32
get_server_name(afs_uint32 *minor_status, char *svc, char *hostname,
		gss_name_t *target_name)
{
    char *sname;
    gss_buffer_desc name_tmp;
    afs_uint32 ret;
    int code;

    code = asprintf(&sname, "%s@%s", svc, hostname);
    if (code < 0) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    name_tmp.length = code;

    name_tmp.value = sname;
    ret = gss_import_name(minor_status, &name_tmp,
			  GSS_C_NT_HOSTBASED_SERVICE,
			  target_name);
    free(sname);
    return ret;
}

/*
 * Decrypt the encrypted reply from the server containing the ClientInfo
 * structure using gss_unwrap, and decode the XDR representation into an
 * actual ClientInfo structure.
 *
 * Returns GSS major/minor pairs.
 */
static afs_uint32
decode_clientinfo(afs_uint32 *minor_status, gss_ctx_id_t gss_ctx,
		  RXGK_Data *info_in, RXGK_ClientInfo *info_out)
{
    XDR xdrs;
    gss_buffer_desc info_buf, clientinfo_buf;
    gss_qop_t qop_state;
    afs_uint32 ret, dummy;
    int conf_state;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(&clientinfo_buf, 0, sizeof(clientinfo_buf));
    info_buf.length = info_in->len;
    info_buf.value = info_in->val;
    ret = gss_unwrap(minor_status, gss_ctx, &info_buf, &clientinfo_buf,
		     &conf_state, &qop_state);
    if (ret != 0)
	return ret;
    if (conf_state == 0 || qop_state != GSS_C_QOP_DEFAULT) {
	/* Cannot goto out as xdrs are not instantiated yet. */
	(void)gss_release_buffer(&dummy, &clientinfo_buf);
	*minor_status = GSS_S_BAD_QOP;
	return GSS_S_FAILURE;
    }

    /* We don't know how long it should be until we decode it. */
    xdrmem_create(&xdrs, clientinfo_buf.value, clientinfo_buf.length, XDR_DECODE);
    if (!xdr_RXGK_ClientInfo(&xdrs, info_out)) {
	ret = GSS_S_FAILURE;
	*minor_status = RXGEN_CC_UNMARSHAL;
	goto out;
    }
    ret = 0;

out:
    (void)gss_release_buffer(&dummy, &clientinfo_buf);
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Perform up to one round-trip of the GSS negotiation exchange.
 * Call gss_init_sec_context locally, and send the output token to the
 * server using the GSSNegotiate RPC.  The server calls gss_accept_sec_context
 * and returns its output token to us when the RPC completes.
 * If negotiation is complete after gss_init_sec_context, we return early;
 * otherwise, we return our status and the caller is responsible for determining
 * whether an additional (full- or half-) round-trip is necessary.
 *
 * We present an RXGK_Data interface for GSS tokens, as the output to the caller
 * is allocated by XDR and must be freed by the caller using that interface,
 * converting to/from gss_buffers internally as needed.
 *
 * Even though the RPC does not have in and out versions of the info argument,
 * we have them, to present a more unified interface to the caller.  We actually
 * do need the input info object from the previous round if using a mechanism
 * that uses a half integral number of round trips, as in that case we will not
 * make another RPC call.
 *
 * Allocates token_out, opaque_out, and info_out, to be freed by the caller.
 *
 * Returns zero for success, 1 if another (half) round-trip is needed, an RXGK
 * error if the RPC failed, 2 if the local GSS state is in error, or 3 if the
 * remote GSS state is in error.
 */
static afs_int32
get_token_round_trip(afs_uint32 *major, afs_uint32 *minor, gss_ctx_id_t *gss_ctx,
		     gss_name_t target_name, RXGK_Data *token_in,
		     RXGK_Data *token_out, afs_uint32 in_flags,
		     afs_uint32 *ret_flags, struct rx_connection *conn,
		     RXGK_StartParams *params, RXGK_Data *opaque_in,
		     RXGK_Data *opaque_out, RXGK_Data *info_in,
		     RXGK_Data *info_out)
{
    struct rx_opaque send_token = RX_EMPTY_OPAQUE;
    gss_buffer_desc gss_send_token, gss_recv_token;
    afs_uint32 dummy;
    afs_int32 ret;

    memset(&gss_send_token, 0, sizeof(gss_send_token));
    memset(&gss_recv_token, 0, sizeof(gss_recv_token));
    memset(info_out, 0, sizeof(*info_out));

    /* Alias the input token to gss_recv_token for the GSS call. */
    gss_recv_token.value = token_in->val;
    gss_recv_token.length = token_in->len;
    *major = gss_init_sec_context(minor, GSS_C_NO_CREDENTIAL, gss_ctx,
				  target_name, GSS_C_NO_OID, in_flags,
				  0 /* time */, NULL /* channel bindings */,
				  &gss_recv_token, NULL /* actual mech type */,
				  &gss_send_token, ret_flags,
				  NULL /* time_rec */);
    if (GSS_ERROR(*major)) {
	ret = 2;
	goto cleanup;
    }
    if (*major == GSS_S_COMPLETE && gss_send_token.length == 0) {
	/* Success!  Copy the info_in argument to info_out. */
	ret = 0;
	info_out->val = xdr_alloc(info_in->len);
	if (info_out->val == NULL) {
	    ret = RXGEN_CC_UNMARSHAL;
	} else {
	    info_out->len = info_in->len;
	    memcpy(info_out->val, info_in->val, info_in->len);
	}
	goto cleanup;
    }

    /* Alias send_token to gss_send_token for the network call. */
    send_token.len = gss_send_token.length;
    send_token.val = gss_send_token.value;

    /* Actual RPC call */
    ret = RXGK_GSSNegotiate(conn, params, &send_token, opaque_in,
			    token_out, opaque_out, major, minor, info_out);
    if (ret != 0) {
	if (ret >= 1 && ret <= 3)
	    ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    if (GSS_ERROR(*major)) {
	ret = 3;
	goto cleanup;
    }
    if (token_out->len > 0) {
	/* Could check server's return here, but not formally needed. */
	ret = 1;
	goto cleanup;
    }
    /* else, ret is zero and we're done */

cleanup:
    /* send_token and gss_send_token alias the same storage */
    (void)gss_release_buffer(&dummy, &gss_send_token);
    return ret;
}

/*
 * Obtain a token over the RXGK negotiation service, for the GSS hostbased
 * principal of service sname on the host given in hostname at the IPv4
 * address in addr (host byte order) and the indicated port (also HBO),
 * for RXGK_Level level.
 *
 * Returns information about the token in the supplied TokenInfo object, and
 * the master key of the token in return_k0, and the token itself in
 * return_token.
 *
 * Returns RX errors.
 */
afs_int32
rxgk_get_token(char *sname, char *hostname, afs_uint32 addr, u_short port,
	       RXGK_Level level, RXGK_TokenInfo *return_info,
	       rxgk_key *return_k0, RXGK_Data *return_token)
{
    gss_buffer_desc k0;
    gss_ctx_id_t gss_ctx;
    gss_name_t target_name;
    RXGK_StartParams params;
    /* These are in/out with respect to get_token_round_trip. */
    struct rx_opaque token_in = RX_EMPTY_OPAQUE, token_out = RX_EMPTY_OPAQUE;
    struct rx_opaque opaque_in = RX_EMPTY_OPAQUE, opaque_out = RX_EMPTY_OPAQUE;
    struct rx_opaque info_in = RX_EMPTY_OPAQUE, info_out;
    RXGK_ClientInfo clientinfo;
    struct rx_connection *conn;
    struct rx_securityClass *secobj;
    afs_uint32 gss_flags, ret_flags, major_status, minor_status, dummy;
    afs_int32 ret;
    u_short svc = 34567;

    major_status = minor_status = 0;
    memset(&k0, 0, sizeof(k0));
    gss_ctx = GSS_C_NO_CONTEXT;
    target_name = GSS_C_NO_NAME;
    memset(&params, 0, sizeof(params));
    memset(&clientinfo, 0, sizeof(clientinfo));
    memset(return_info, 0, sizeof(*return_info));
    *return_k0 = NULL;
    memset(return_token, 0, sizeof(*return_token));
    conn = NULL;
    ret = 0;
    secobj = rxnull_NewClientSecurityObject();

    conn = rx_NewConnection(addr, port, svc, secobj, 0);
    if (conn == NULL) {
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    /* Prepare things for gss_init_sec_context unchanged by the loop. */
    gss_flags = (GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG ) &
		~GSS_C_DELEG_FLAG;
    major_status = get_server_name(&minor_status, sname, hostname,
				   &target_name);
    if (GSS_ERROR(major_status)) {
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    /* Prepare arguments for GSSNegotiate that are unchanged over the loop. */
    ret = fill_start_params(&params, level);
    if (ret != 0)
	goto cleanup;

    /*
     * The negotiation loop to establish a security context and generate
     * a token.
     */
    do  {
	/* Clear out things allocated during the loop here. */
	/* Allocated by XDR */
	memset(&token_out, 0, sizeof(token_out));
	memset(&info_out, 0, sizeof(info_out));
	memset(&opaque_out, 0, sizeof(opaque_out));
	/* Call gss_init_sec_context and GSSNegotiate. */
	ret = get_token_round_trip(&major_status, &minor_status, &gss_ctx,
				   target_name, &token_in, &token_out,
				   gss_flags, &ret_flags, conn, &params,
				   &opaque_in, &opaque_out, &info_in, &info_out);
	/* Always free the input arguments. */
	rx_opaque_freeContents(&token_in);
	rx_opaque_freeContents(&opaque_in);
	rx_opaque_freeContents(&info_in);
	/* Swap things over for a possible next cycle. */
	token_in.val = token_out.val;
	token_in.len = token_out.len;
	opaque_in.val = opaque_out.val;
	opaque_in.len = opaque_out.len;
	info_in.val = info_out.val;
	info_in.len = info_out.len;
    } while(ret == 1);
    /* end negotiation loop */

    if (ret != 0) {
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    major_status = decode_clientinfo(&minor_status, gss_ctx, &info_out,
				     &clientinfo);
    if (GSS_ERROR(major_status)) {
	ret = RXGK_SEALED_INCON;
	goto cleanup;
    }
    if (clientinfo.errorcode != 0) {
	ret = clientinfo.errorcode;
	goto cleanup;
    }
    ret = rxgk_make_k0(&minor_status, gss_ctx, &params.client_nonce,
		       &clientinfo.server_nonce, clientinfo.enctype, &k0);
    if (ret != 0)
	goto cleanup;

    /* Copy data for output */
    return_info->enctype = clientinfo.enctype;
    return_info->level = clientinfo.level;
    return_info->lifetime = clientinfo.lifetime;
    return_info->bytelife = clientinfo.bytelife;
    return_info->expiration = clientinfo.expiration;
    return_token->val = xdr_alloc(clientinfo.token.len);
    if (return_token->val == NULL) {
	ret = RXGEN_CC_UNMARSHAL;
	goto cleanup;
    }
    memcpy(return_token->val, clientinfo.token.val, clientinfo.token.len);
    return_token->len = clientinfo.token.len;
    ret = rxgk_make_key(return_k0, k0.value, k0.length, clientinfo.enctype);

cleanup:
    /* Free memory allocated in the loop and returned */
    rx_opaque_freeContents(&token_out);
    rx_opaque_freeContents(&opaque_out);
    rx_opaque_freeContents(&info_out);
    /* Free other memory */
    (void)gss_release_buffer(&dummy, &k0);
    (void)gss_release_name(&dummy, &target_name);
    (void)gss_delete_sec_context(&dummy, &gss_ctx, GSS_C_NO_BUFFER);
    xdr_free((xdrproc_t)xdr_RXGK_StartParams, &params);
    xdr_free((xdrproc_t)xdr_RXGK_ClientInfo, &clientinfo);
    rx_DestroyConnection(conn);

    return ret;
}

/*
 * Server-side routines for service-specific GSS-related data.
 */

struct rxgk_gss_sspecific_data {
    gss_name_t sname;
    char *keytab_path;
    rxgkTime expires;
    gss_cred_id_t creds;
};

/*
 * Used to set service-specific data for a server process.
 * Store the GSS acceptor name, and optionally a path to a keytab,
 * cached creds, and more.
 */
afs_int32
rxgk_set_gss_specific(struct rx_service *svc, char *svcname, char *host,
		      char *keytab)
{
    struct rxgk_gss_sspecific_data *gk = NULL;
    char *string_name = NULL;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    afs_int32 ret;
    afs_uint32 major, minor, time_rec;

    if (svc == NULL || svcname == NULL || host == NULL)
	return RXGK_INCONSISTENCY;

    gk = rxi_Alloc(sizeof(*gk));
    if (gk == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    gk->sname = GSS_C_NO_NAME;
    gk->creds = GSS_C_NO_CREDENTIAL;

    ret = asprintf(&string_name, "%s@%s", svcname, host);
    if (ret < 0)
	goto cleanup;
    name_buf.value = string_name;
    name_buf.length = strlen(string_name);
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
			    &gk->sname);
    if (GSS_ERROR(major)) {
	/* mumble gss_display_status() here */
	ret = major;
	goto cleanup;
    }
#if HAVE_KRB5_GSS_REGISTER_ACCEPTOR_IDENTITY
    if (keytab != NULL) {
	ret = krb5_gss_register_acceptor_identity(keytab);
	if (ret != 0)
	    goto cleanup;
    }
#endif
    major = gss_acquire_cred(&minor, gk->sname, 0, GSS_C_NO_OID_SET,
			     GSS_C_ACCEPT, &gk->creds, NULL, &time_rec);
    if (GSS_ERROR(major)) {
	/* mumble gss_display_status() here */
	ret = major;
	goto cleanup;
    }
    if (time_rec != 0 && time_rec != GSS_C_INDEFINITE) {
	gk->expires = RXGK_NOW() + time_rec * 1000 * 1000 * 10;
    }
    rx_SetServiceSpecific(svc, RXGK_NEG_SSPECIFIC_GSS, gk);
    gk = NULL;
    ret = 0;

cleanup:
    if (gk != NULL) {
	(void)gss_release_name(&minor, &gk->sname);
	(void)gss_release_cred(&minor, &gk->creds);
    }
    free(gk);
    free(string_name);
    return ret;
}
/* Server-side routines supporting SRXGK_GSSNegotiate(). */

/* One week */
#define MAX_LIFETIME	(60 * 60 * 24 * 7)
/* One TiB */
#define MAX_BYTELIFE	40
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

    info->expiration = -1;
    if (params->enctypes.len == 0)
	return RXGK_BADETYPE;
    info->enctype = params->enctypes.val[0];
    if (params->levels.len == 0)
	return RXGK_BADLEVEL;
    info->level = params->levels.val[0];
    info->lifetime = params->lifetime;
    if (info->lifetime > MAX_LIFETIME)
	info->lifetime = MAX_LIFETIME;
    info->bytelife = params->bytelife;
    if (info->bytelife > MAX_BYTELIFE)
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

    ret = start + gss_lifetime * 1000 * 1000 * 10;
    if ((now - start) > 50000000) {
	/* We've been processing for 5 seconds?! */
	/* five minutes only */
	ret = start + (rxgkTime)5 * 60 * 1000 * 1000 * 10;
    }
    if (now < start) {
	/* time went backwards */
	ret = now + (rxgkTime)5 * 60 * 1000 * 1000 * 10;
    }

    return ret;
}

/*
 * Copy the fields from a TokenInfo into a ClientInfo.
 * ClientInfo is a superset of TokenInfo.
 */
static_inline void
tokeninfo_to_clientinfo(RXGK_ClientInfo *client, RXGK_TokenInfo *local)
{

    client->enctype = local->enctype;
    client->level = local->level;
    client->lifetime = local->lifetime;
    client->bytelife = local->bytelife;
    client->expiration = local->expiration;
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
	*gss_minor_status = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    startparams.value = rxi_Alloc(len);
    if (startparams.value == NULL) {
	*gss_minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    startparams.length = len;
    xdrmem_create(&xdrs, startparams.value, len, XDR_ENCODE);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	ret = GSS_S_FAILURE;
	*gss_minor_status = RXGEN_SS_MARSHAL;
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
	*gss_minor_status = ENOMEM;
	goto out;
    }
    mic->len = mic_buffer.length;
    memcpy(mic->val, mic_buffer.value, mic->len);
    ret = gss_release_buffer(gss_minor_status, &mic_buffer);

out:
    rxi_Free(startparams.value, len);
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
	goto out;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    tmp = rxi_Alloc(len);
    if (tmp == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    xdrmem_create(&xdrs, tmp, len, XDR_ENCODE);
    if (!xdr_RXGK_ClientInfo(&xdrs, info)) {
	ret = GSS_S_FAILURE;
	*minor_status = RXGEN_SS_MARSHAL;
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
	(void)gss_release_buffer(minor_status, &wrapped);
	ret = GSS_S_FAILURE;
	*minor_status = ENOMEM;
	goto out;
    }
    rxgk_info->len = wrapped.length;
    memcpy(rxgk_info->val, wrapped.value, wrapped.length);
    ret = gss_release_buffer(minor_status, &wrapped);

out:
    rxi_Free(tmp, len);
    xdr_destroy(&xdrs);
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

    if (gk == NULL || gk->getkey == NULL)
	return RXGK_INCONSISTENCY;
    return (*gk->getkey)(gk->rock, kvno, enctype, key);
}

/*
 * Returns true if the acceptor (stored in the rx service-specific
 * data) name and initiator name (client_name) are the same; false
 * otherwise.
 */
static int
is_selfauth(struct rx_call *call, gss_name_t client_name)
{
    struct rx_connection *conn;
    struct rx_service *svc;
    struct rxgk_gss_sspecific_data *gk = NULL;
    afs_uint32 major, minor;
    int eq;

    conn = rx_ConnectionOf(call);
    svc = rx_ServiceOf(conn);
    gk = rx_GetServiceSpecific(svc, RXGK_NEG_SSPECIFIC_GSS);
    if (gk == NULL) {
	/* Fail safe. */
	return 0;
    }
    major = gss_compare_name(&minor, gk->sname, client_name, &eq);
    if (GSS_ERROR(major))
	return 0;
    if (eq != 0)
	return 1;
    return 0;
}

afs_int32
SGSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
	      RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
	      RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
	      u_int *gss_major_status, u_int *gss_minor_status,
	      RXGK_Data *rxgk_info)
{
    gss_buffer_desc gss_token_in, gss_token_out, k0;
    gss_cred_id_t creds;
    gss_ctx_id_t gss_ctx;
    gss_name_t client_name;
    struct rx_opaque k0_data;
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
	goto out;
    }

    /* prepare the input token */
    if (input_token_buffer->len > 0) {
	gss_token_in.length = input_token_buffer->len;
	gss_token_in.value = input_token_buffer->val;
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

    if (GSS_ERROR(*gss_major_status)) {
	/* Though the GSS negotiation failed, the RPC shall succeed. */
	ret = 0;
	goto out;
    }

    /* fill output_token_buffer */
    if (gss_token_out.length > 0) {
	len = gss_token_out.length;
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
    if (info.errorcode != 0)
	goto out;
    /* Get a key to encrypt the token in. */
    ret = get_long_term_key(z_call, &key, &kvno, &enctype);
    if (ret != 0)
	goto out;
    /* Alias the gss buffer into an rx type. */
    k0_data.val = k0.value;
    k0_data.len = k0.length;
    /* If we're negotiating with ourself, print a token instead of supplying
     * an identity. */
    if (is_selfauth(z_call, client_name)) {
	ret = rxgk_print_token(&info.token, &localinfo, &k0_data, key, kvno,
			       enctype);
    } else {
	ret = rxgk_make_token(&info.token, &localinfo, &k0_data, start_time,
			      identity, 1, key, kvno, enctype);
    }
    /* Clean up right away so as to not leave key material around */
    rxgk_release_key(&key);
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
