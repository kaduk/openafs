/* rxgk/rxgk_client.c - Client-only security object routines */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
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
 * Client-only sercurity object routines.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

/* OS-specific system headers go here */

#include <rx/rx.h>
#include <rx/xdr.h>
#include <rx/rx_packet.h>
#include <rx/rx_identity.h>
#include <gssapi/gssapi.h>
#include <errno.h>
#include <rx/rxgk.h>
#include <afs/rfc3961.h>

#include "rxgk_private.h"

static struct rx_securityOps rxgk_client_ops = {
    rxgk_Close,
    rxgk_NewConnection,		/* every new connection */
    rxgk_PreparePacket,		/* once per packet creation */
    0,				/* send packet (once per retrans) */
    0,
    0,
    0,
    rxgk_GetResponse,		/* respond to challenge packet */
    0,
    rxgk_CheckPacket,		/* check data packet */
    rxgk_DestroyConnection,
    rxgk_GetStats,
    0,
    0,
    0,
};

struct rx_securityClass *
rxgk_NewClientSecurityObject(RXGK_Level level, afs_int32 enctype, rxgk_key k0,
			     RXGK_Data *token, afsUUID *uuid)
{
    struct rx_securityClass *sc;
    struct rxgk_cprivate *cp;

    sc = calloc(1, sizeof(*sc));
    if (sc == NULL)
	return NULL;
    cp = calloc(1, sizeof(*cp));
    if (cp == NULL) {
	free(sc);
	return NULL;
    }
    sc->ops = &rxgk_client_ops;
    sc->refCount = 1;
    sc->privateData = cp;

    /* Now get the client-private data. */
    cp->type = RXGK_CLIENT;
    cp->flags = 0;
    cp->k0 = k0;
    cp->enctype = enctype;
    cp->level = level;
    if (copy_rxgkdata(&cp->token, token) != 0) {
	free(sc);
	free(cp);
	return NULL;
    }
    if (uuid != NULL) {
	cp->uuid = malloc(sizeof(*uuid));
	if (cp->uuid == NULL) {
	    free(sc);
	    xdr_free((xdrproc_t)xdr_RXGK_Data, &cp->token);
	    free(cp);
	    return NULL;
	}
	memcpy(&cp->uuid, uuid, sizeof(*uuid));
    }

    return sc;
}

/*
 * Helpers for get_token().
 */

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
    len = 3;
    tmp = xdr_alloc(len * sizeof(int));
    if (tmp == NULL) {
	dprintf(2, "couldn't allocate for params.enctypes\n");
	return RXGEN_CC_MARSHAL;
    }
    params->enctypes.len = len;
    params->enctypes.val = tmp;
    params->enctypes.val[0] = ETYPE_AES256_CTS_HMAC_SHA1_96;
    params->enctypes.val[1] = ETYPE_AES128_CTS_HMAC_SHA1_96;
    params->enctypes.val[2] = ETYPE_DES_CBC_CRC;
   
    /* security levels */
    len = 1;
    tmp = xdr_alloc(len * sizeof(RXGK_Level));
    if (tmp == NULL) {
	dprintf(2, "couldn't allocate for params.levels\n");
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

    name_tmp.length = asprintf(&sname, "%s@%s", svc, hostname);
    if (name_tmp.length < 0) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

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
	dprintf(2, "xdrmem for ClientInfo says they are invalid\n");
	goto out;
    }
    printf("Successfully decoded clientinfo\n");
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
    RXGK_Data send_token;
    gss_buffer_desc gss_send_token, gss_recv_token;
    afs_uint32 dummy;
    afs_int32 ret;

    memset(&gss_send_token, 0, sizeof(gss_send_token));
    memset(&gss_recv_token, 0, sizeof(gss_recv_token));
    zero_rxgkdata(&send_token);
    zero_rxgkdata(info_out);

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
	dprintf(2, "init sec context in error, major %i minor %i\n", *major,
		*minor);
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
    printf("init_sec_context token length %i\n", gss_send_token.length);

    /* Actual RPC call */
    ret = RXGK_GSSNegotiate(conn, params, &send_token, opaque_in,
			    token_out, opaque_out, major, minor, info_out);
    if (ret != 0) {
	dprintf(2, "GSSNegotiate returned %i\n", ret);
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
    zero_rxgkdata(&send_token);
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
static afs_int32
get_token(char *sname, char *hostname, afs_uint32 addr, u_short port,
	  RXGK_Level level, RXGK_TokenInfo *return_info, rxgk_key *return_k0,
	  RXGK_Data *return_token)
{
    gss_buffer_desc k0;
    gss_ctx_id_t gss_ctx;
    gss_name_t target_name;
    RXGK_StartParams params;
    /* These are in/out with respect to get_token_round_trip. */
    RXGK_Data token_in, token_out, opaque_in, opaque_out, info_in, info_out;
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
    zero_rxgkdata(&token_in);
    zero_rxgkdata(&token_out);
    zero_rxgkdata(&opaque_in);
    zero_rxgkdata(&opaque_out);
    zero_rxgkdata(&info_in);
    memset(return_info, 0, sizeof(*return_info));
    *return_k0 = NULL;
    zero_rxgkdata(return_token);
    conn = NULL;
    ret = 0;
    secobj = rxnull_NewClientSecurityObject();

    conn = rx_NewConnection(addr, port, svc, secobj, 0);
    if (conn == NULL) {
	dprintf(2, "Did not get RX connection\n");
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    /* Prepare things for gss_init_sec_context unchanged by the loop. */
    gss_flags = (GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG ) &
		~GSS_C_DELEG_FLAG;
    major_status = get_server_name(&minor_status, sname, hostname,
				   &target_name);
    if (GSS_ERROR(major_status)) {
	dprintf(2, "Could not import server name major %i minor %i\n",
		major_status, minor_status);
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
	zero_rxgkdata(&token_out);
	zero_rxgkdata(&info_out);
	zero_rxgkdata(&opaque_out);
	/* Call gss_init_sec_context and GSSNegotiate. */
	ret = get_token_round_trip(&major_status, &minor_status, &gss_ctx,
				   target_name, &token_in, &token_out,
				   gss_flags, &ret_flags, conn, &params,
				   &opaque_in, &opaque_out, &info_in, &info_out);
	/* Always free the input arguments. */
	xdr_free((xdrproc_t)xdr_RXGK_Data, &token_in);
	xdr_free((xdrproc_t)xdr_RXGK_Data, &opaque_in);
	xdr_free((xdrproc_t)xdr_RXGK_Data, &info_in);
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
	dprintf(2, "GSS negotiation failed, major %i minor %i RXGK %i\n",
		major_status, minor_status, ret);
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    printf("GSSNegotiate returned info of length %zu\n", info_out.len);
    major_status = decode_clientinfo(&minor_status, gss_ctx, &info_out,
				     &clientinfo);
    if (GSS_ERROR(major_status)) {
	ret = RXGK_SEALED_INCON;
	goto cleanup;
    }
    ret = rxgk_make_k0(&minor_status, gss_ctx, &params.client_nonce,
		       &clientinfo.server_nonce, clientinfo.enctype, &k0);
    if (ret != 0) {
	printf("Failed to generate k0\n");
	goto cleanup;
    }

    /* Copy data for output */
    return_info->errorcode = clientinfo.errorcode;
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
    ret = make_key(return_k0, k0.value, k0.length, clientinfo.enctype);

cleanup:
    /* Free memory allocated in the loop and returned */
    xdr_free((xdrproc_t)xdr_RXGK_Data, &token_out);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &opaque_out);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &info_out);
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
 * Create a rxnull connection to the specified addr and port, and perform
 * the GSS negotiation loop to obtain a token for the GSS host-based
 * service of type svc on the host named by hostname.  Use that token (and
 * its token master key k0) to create a client security object that may
 * be used to establish an rxgk connection to that same address and port.
 */
struct rx_securityClass *
rxgk_NegotiateSecurityObject(RXGK_Level level, afsUUID *uuid, u_short port,
			     char *svc, char *hostname, afs_uint32 addr)
{
    struct rx_securityClass *so;
    RXGK_TokenInfo info;
    rxgk_key k0;
    RXGK_Data token;
    afs_int32 ret;

    memset(&token, 0, sizeof(token));
    memset(&info, 0, sizeof(info));
    memset(&k0, 0, sizeof(k0));

    ret = get_token(svc, hostname, addr, port, level, &info, &k0, &token);
    if (ret != 0)
	return NULL;
    so = rxgk_NewClientSecurityObject(info.level, info.enctype, k0, &token,
				      uuid);

    /* k0 is donated to the security object for now */
#if 0
    xdr_free((xdrproc_t)xdr_RXGK_Data, &token);
    xdr_free((xdrproc_t)xdr_RXGK_ClientInfo, &info);
#endif
    return so;
}

/*
 * Helpers for GetResponse.
 */

/*
 * Populate the RXGK_Authenticator structure.
 * The caller is responsible for pre-zeroing the structure and freeing
 * the resulting allocations, including partial allocations in the case
 * of failure.
 */
static int
fill_authenticator(RXGK_Authenticator *authenticator, char *nonce,
		   struct rxgk_cprivate *cp, struct rx_connection *aconn)
{
    XDR xdrs;
    afs_int32 call_numbers[RX_MAXCALLS];
    int ret, i;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(&call_numbers, 0, sizeof(call_numbers));

    memcpy(authenticator->nonce, nonce, 20);
    /* Encode the uuid to an opaque, if present. */
    xdrlen_create(&xdrs);
    if (cp->uuid != NULL) {
	if (!xdr_afsUUID(&xdrs, cp->uuid)) {
	    ret = RXGEN_CC_MARSHAL;
	    goto cleanup;
	}
	len = xdr_getpos(&xdrs);
	authenticator->appdata.val = xdr_alloc(len);
	if (authenticator->appdata.val == NULL) {
	    ret = RXGEN_CC_MARSHAL;
	    goto cleanup;
	}
	xdr_destroy(&xdrs);
	xdrmem_create(&xdrs, authenticator->appdata.val, len, XDR_ENCODE);
	if (!xdr_afsUUID(&xdrs, cp->uuid)) {
	    ret = RXGEN_CC_MARSHAL;
	    goto cleanup;
	}
    } else {
	authenticator->appdata.val = NULL;
	authenticator->appdata.len = 0;
    }

    authenticator->level = cp->level;
    authenticator->epoch = rx_GetConnectionEpoch(aconn);
    authenticator->cid = rx_GetConnectionId(aconn);
    /* Export the call numbers. */
    ret = rxi_GetCallNumberVector(aconn, call_numbers);
    if (ret != 0)
	goto cleanup;
    authenticator->call_numbers.val = xdr_alloc(RX_MAXCALLS *
						sizeof(afs_int32));
    if (authenticator->call_numbers.val == NULL) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    authenticator->call_numbers.len = RX_MAXCALLS;
    for(i = 0; i < RX_MAXCALLS; ++i)
	authenticator->call_numbers.val[i] = (afs_uint32)call_numbers[i];
    ret = 0;
cleanup:
    xdr_destroy(&xdrs);
    return ret;
}

/* XDR-encode an authenticator and encrypt it. */
static int
pack_wrap_authenticator(RXGK_Data *encdata, RXGK_Authenticator *authenticator,
			struct rxgk_cprivate *cp, struct rxgk_cconn *cc)
{
    XDR xdrs;
    RXGK_Data data;
    rxgk_key tk;
    int ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    zero_rxgkdata(&data);
    tk = NULL;

    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Authenticator(&xdrs, authenticator)) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    len = xdr_getpos(&xdrs);
    data.val = xdr_alloc(len);
    if (data.val == NULL) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    data.len = len;
    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, data.val, len, XDR_ENCODE);
    if (!xdr_RXGK_Authenticator(&xdrs, authenticator)) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    ret = derive_tk(&tk, cp->k0, authenticator->epoch, authenticator->cid,
		    cc->start_time, cc->key_number);
    if (ret != 0)
	goto cleanup;
    ret = encrypt_in_key(tk, RXGK_CLIENT_ENC_RESPONSE, &data, encdata);
    if (ret != 0)
	goto cleanup;

cleanup:
    xdr_destroy(&xdrs);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &data);
    release_key(&tk);
    return ret;
}

/* XDR-encode an RXGK_Response structure to put it on the wire.
 * The caller must free the out parameter. */
static int
pack_response(RXGK_Data *out, RXGK_Response *response)
{
    XDR xdrs;
    int ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));

    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Response(&xdrs, response)) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    len = xdr_getpos(&xdrs);
    out->val = xdr_alloc(len);
    if (out->val == NULL) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    out->len = len;
    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, out->val, len, XDR_ENCODE);
    if (!xdr_RXGK_Response(&xdrs, response)) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    ret = 0;

cleanup:
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Respond to a challenge packet.
 * The data of the packet on entry is the XDR-encoded RXGK_Challenge.
 * We decode it and reuse the packet structure to prepare a response.
 */
int
rxgk_GetResponse(struct rx_securityClass *aobj, struct rx_connection *aconn,
		 struct rx_packet *apacket)
{
    struct rxgk_cprivate *cp;
    struct rxgk_cconn *cc;
    XDR xdrs;
    RXGK_Challenge challenge;
    RXGK_Response response;
    RXGK_Authenticator authenticator;
    RXGK_Data encdata, packed;
    int ret;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(&challenge, 0, sizeof(challenge));
    memset(&response, 0, sizeof(response));
    memset(&authenticator, 0, sizeof(authenticator));
    zero_rxgkdata(&encdata);
    zero_rxgkdata(&packed);

    cp = aobj->privateData;
    cc = rx_GetSecurityData(aconn);

    /* Decode the challenge to get the nonce. */
    if (rx_Contiguous(apacket) < 20)
	return RXGK_PACKETSHORT;
    xdrmem_create(&xdrs, rx_DataOf(apacket), rx_Contiguous(apacket),
		  XDR_DECODE);
    if (!xdr_RXGK_Challenge(&xdrs, &challenge)) {
	ret = RXGEN_CC_UNMARSHAL;
	goto cleanup;
    }

    /* Start filling the response. */
    response.start_time = cc->start_time;
    if (copy_rxgkdata(&response.token, &cp->token) != 0) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }

    /* Fill up the authenticator */
    ret = fill_authenticator(&authenticator, challenge.nonce, cp, aconn);
    if (ret != 0)
	goto cleanup;
    /* Authenticator is full, now to pack and encrypt it. */
    ret = pack_wrap_authenticator(&encdata, &authenticator, cp, cc);
    if (ret != 0)
	goto cleanup;
    rx_opaque_populate(&response.authenticator, encdata.val, encdata.len);
    /* Put the kvno we used on the wire for the remote end. */
    rx_SetPacketCksum(apacket, htons((afs_uint16)cc->key_number));

    /* Response is ready, now to shove it in a packet. */
    ret = pack_response(&packed, &response);
    if (ret != 0)
	goto cleanup;
    rx_packetwrite(apacket, 0, packed.len, packed.val);
    rx_SetDataSize(apacket, packed.len);

cleanup:
    xdr_destroy(&xdrs);
    xdr_free((xdrproc_t)xdr_RXGK_Challenge, &challenge);
    xdr_free((xdrproc_t)xdr_RXGK_Response, &response);
    xdr_free((xdrproc_t)xdr_RXGK_Authenticator, &authenticator);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &encdata);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packed);
    return ret;
}
