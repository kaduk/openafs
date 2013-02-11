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
get_server_name(afs_uint32 *minor_status, gss_name_t *target_name)
{
    gss_buffer_desc name_tmp;
    char *sname = "afs-rxgk@_afs.perfluence.mit.edu";

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
 * Obtain a token over the RXGK negotiation service, using the provided
 * security object.
 *
 * Returns RX errors.
 */
static afs_int32
get_token(struct rx_securityClass *secobj)
{
    /*
     * We have both gss_buffer and RXGK_Data copies of the token_in and
     * token_out structures (the 'in' and 'out' are with respect to the
     * GSSNegotiate RPC, not gss_init_sec_context!).  token_out is allocated
     * by the XDR routines and must be freed by them,  and token_in is
     * allocated in gss_init_sec_context and must be freed with
     * gss_release_buffer.
     */
    gss_buffer_desc gss_token_in, gss_token_out, *gss_token_ptr, k0;
    gss_ctx_id_t gss_ctx;
    gss_name_t target_name;
    RXGK_StartParams params;
    RXGK_Data token_out, token_in, opaque_in, opaque_out, info;
    RXGK_ClientInfo clientinfo;
    struct rx_connection *conn;
    afs_uint32 gss_flags, ret_flags;
    unsigned int major_status, minor_status;
    int ret;
    u_short port = 8888;
    u_short svc = 34567;

    conn = rx_NewConnection(htonl(INADDR_LOOPBACK), port,
			    svc, secobj, RX_SECIDX_NULL);
    if (conn == NULL) {
	dprintf(2, "Did not get RX connection\n");
	exit(1);
    }

    /* Prepare things for gss_init_sec_context unchanged by the loop. */
    gss_flags = (GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG ) &
		~GSS_C_DELEG_FLAG;
    major_status = get_server_name(&minor_status, &target_name);
    if (major_status != 0) {
	dprintf(2, "Could not import server name major %i minor %i\n",
		major_status, minor_status);
	exit(1);
    }

    /* Prepare arguments for GSSNegotiate that are unchanged over the loop. */
    ret = fill_start_params(&params);

    /* Initialize GSSNegotiate argument that changes in the loop. */
    zero_rxgkdata(&token_in);

    /* The GSS variables, too. */
    gss_ctx = GSS_C_NO_CONTEXT;
    gss_token_ptr = (gss_buffer_desc *)GSS_C_NO_BUFFER;

    /* For the first call to GSSNegotiate(), there is no input opaque token. */
    zero_rxgkdata(&opaque_in);

    /* tell the XDR decoder to allocate space */
    zero_rxgkdata(&token_out);
    zero_rxgkdata(&opaque_out);
    zero_rxgkdata(&info);

    /*
     * The negotiation loop to establish a security context and generate
     * a token.
     */
    do  {
	major_status = gss_init_sec_context(&minor_status,
					    GSS_C_NO_CREDENTIAL,
					    &gss_ctx, target_name,
					    (gss_OID)gss_mech_krb5,
					    gss_flags,
					    0 /* time */,
					    NULL /* channel bindings */,
					    gss_token_ptr,
					    NULL /* actual mech type */,
					    &gss_token_in, &ret_flags,
					    NULL /* time_rec */);

	printf("GSS init sec context status major %i minor %i\n",
	       major_status, minor_status);
	if (GSS_ERROR(major_status)) {
	    dprintf(2, "init sec context in error, major %i minor %i\n",
		    major_status, minor_status);
	    exit(1);
	}
	/* Done with token_out. */
	xdr_free((xdrproc_t)xdr_RXGK_Data, &token_out);
	if (major_status == GSS_S_COMPLETE && gss_token_in.length == 0)
	    break;

	/* Translate from gss_buffer to RXGK_Data. GSS still owns the storage
	 * and we must use gss_release_buffer() later. */
	token_in.len = gss_token_in.length;
	token_in.val = gss_token_in.value;
	printf("init_sec_context token length %i\n", gss_token_in.length);

	/* Actual RPC call */
	ret = RXGK_GSSNegotiate(conn, &params, &token_in, &opaque_in,
				&token_out, &opaque_out, &major_status,
				&minor_status, &info);
	if (ret != 0) {
	    dprintf(2, "GSSNegotiate returned %i\n", ret);
	    exit(1);
	}

	/* Decode the reply and print it to the user */
	if (major_status != GSS_S_COMPLETE) {
	    printf("GSS negotiation incomplete, major %i minor %i\n",
		   major_status, minor_status);
	} else {
	    printf("GSSNegotiate finished, major %i minor %i\n",
		   major_status, minor_status);
	    printf("Server gave us token of length %i\n", token_out.len);
	}
	/* Done with token_in. Down here so as to not spoil minor_status. */
	zero_rxgkdata(&token_in);
	ret = gss_release_buffer(&minor_status, &gss_token_in);

	/* Prepare for a possible next cycle */
	xdr_free((xdrproc_t)xdr_RXGK_Data, &opaque_in);
	opaque_in.len = opaque_out.len;
	opaque_in.val = opaque_out.val;
	gss_token_out.length = token_out.len;
	gss_token_out.value = token_out.val;
	gss_token_ptr = &gss_token_out;
    } while(major_status == GSS_S_CONTINUE_NEEDED ||
	    token_out.len > 0);
    /* end negotiation loop */

    if (major_status != GSS_S_COMPLETE) {
	dprintf(2, "GSS negotiation failed, major %i minor %i\n",
		major_status, minor_status);
	exit(2);
    }

    printf("GSSNegotiate returned info of length %zu\n", info.len);
    major_status = decode_clientinfo(&minor_status, gss_ctx, &info, &clientinfo);
    ret = rxgk_make_k0(&minor_status, gss_ctx, &params.client_nonce,
		       &clientinfo.server_nonce, clientinfo.enctype, &k0);
    if (ret != 0)
	printf("Failed to generate k0\n");

    /* Free memory allocated for k0 */
    (void)gss_release_buffer(&minor_status, &k0);

    /* Free memory allocated by the XDR decoder */
    xdr_free((xdrproc_t)xdr_RXGK_Data, &token_out);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &opaque_out);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &info);

    return 0;
}

int
main(int argc, char *argv[])
{
    struct rx_securityClass *secobj;
    afs_int32 ret;

    ret = rx_Init(0);
    if (ret != 0) {
	dprintf(2, "Could not initialize RX\n");
	exit(1);
    }

    secobj = rxnull_NewClientSecurityObject();

    ret = get_token(secobj);

    /* Done. */
    rx_Finalize();

    return ret;
}
