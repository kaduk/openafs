/* rxgk/ndebug.c - Debugging interface for GSSNegotiate */
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
 * Simple test program to call GSSNegotiate and display the results.
 */

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <ctype.h>

#include <afsconfig.h>
#include <afs/param.h>

#include <rx/rx.h>
#include <rx/rxgk.h>

/*
 * Populate a StartParams structure.
 * Just use fixed values for now.
 *
 * Returns RX error codes.
 */
static afs_int32
fill_start_params(RXGK_StartParams *params)
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
    params->enctypes.val[0] = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    params->enctypes.val[1] = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
    params->enctypes.val[2] = ENCTYPE_DES_CBC_CRC;
   
    /* security levels */
    len = 3;
    tmp = xdr_alloc(len * sizeof(RXGK_Level));
    if (tmp == NULL) {
	dprintf(2, "couldn't allocate for params.levels\n");
	return RXGEN_CC_MARSHAL;
    }
    params->levels.len = len;
    params->levels.val = tmp;
    params->levels.val[0] = RXGK_LEVEL_CRYPT;
    params->levels.val[0] = RXGK_LEVEL_AUTH;
    params->levels.val[0] = RXGK_LEVEL_CLEAR;

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
 * Determine the (GSS) name of the remote server to contact.
 * For now, hardcoded.
 *
 * Returns GSS major/minor pairs.
 */
static afs_uint32
get_server_name(afs_uint32 *minor_status, char *sname, gss_name_t *target_name)
{
    gss_buffer_desc name_tmp;

    name_tmp.value = sname;
    name_tmp.length = strlen(sname);
    return gss_import_name(minor_status, &name_tmp,
			   GSS_C_NT_HOSTBASED_SERVICE,
			   target_name);
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
				  target_name, (gss_OID)gss_mech_krb5, in_flags,
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
 * Obtain a token over the RXGK negotiation service, using the provided
 * security object, using the server principal name from sname and target
 * IPv4 address given in addr (host byte order).
 *
 * Returns RX errors.
 */
static afs_int32
get_token(struct rx_securityClass *secobj, char *sname, afs_uint32 addr)
{
    gss_buffer_desc k0;
    gss_ctx_id_t gss_ctx;
    gss_name_t target_name;
    RXGK_StartParams params;
    /* These are in/out with respect to get_token_round_trip. */
    RXGK_Data token_in, token_out, opaque_in, opaque_out, info_in, info_out;
    RXGK_ClientInfo clientinfo;
    struct rx_connection *conn;
    afs_uint32 gss_flags, ret_flags, major_status, minor_status, dummy;
    afs_int32 ret;
    u_short port = 8888;
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
    conn = NULL;
    ret = 0;

    conn = rx_NewConnection(htonl(addr), port,
			    svc, secobj, RX_SECIDX_NULL);
    if (conn == NULL) {
	dprintf(2, "Did not get RX connection\n");
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    /* Prepare things for gss_init_sec_context unchanged by the loop. */
    gss_flags = (GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG ) &
		~GSS_C_DELEG_FLAG;
    major_status = get_server_name(&minor_status, sname, &target_name);
    if (GSS_ERROR(major_status)) {
	dprintf(2, "Could not import server name major %i minor %i\n",
		major_status, minor_status);
	ret = RX_CALL_DEAD;
	goto cleanup;
    }

    /* Prepare arguments for GSSNegotiate that are unchanged over the loop. */
    ret = fill_start_params(&params);
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

int
main(int argc, char *argv[])
{
    struct rx_securityClass *secobj;
    char *sname = "afs-rxgk@_afs.perfluence.mit.edu";
    afs_int32 ret;

    ret = rx_Init(0);
    if (ret != 0) {
	dprintf(2, "Could not initialize RX\n");
	exit(1);
    }

    secobj = rxnull_NewClientSecurityObject();

    ret = get_token(secobj, sname, INADDR_LOOPBACK);

    /* Done. */
    rx_Finalize();

    return ret;
}
