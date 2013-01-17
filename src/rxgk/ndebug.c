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
#include <hcrypto/rand.h>

#include <rx/rx.h>
#include <rx/rxgk.h>

int
main(int argc, char *argv[])
{
    gss_buffer_desc gss_token_in, gss_token_out, *gss_token_ptr;
    gss_ctx_id_t gss_ctx;
    gss_name_t target_name;
    RXGK_StartParams params;
    /* 'in' and 'out' here are for GSSNegotiate, *not* gss_init_sec_context! */
    RXGK_Data token_out, token_in, opaque_in, opaque_out, info;
    struct rx_securityClass *secobj;
    struct rx_connection *conn;
    unsigned char *data;
    char *sname = "afs-rxgk@_afs.perfluence.mit.edu";
    void *tmp;
    afs_uint32 gss_flags, ret_flags;
    size_t len, i;
    unsigned int major_status, minor_status;
    int ret;
    u_short port = 8888;
    u_short svc = 34567;
    unsigned char c;

    ret = rx_Init(0);
    if (ret != 0) {
	dprintf(2, "Could not initialize RX\n");
	exit(1);
    }

    secobj = rxnull_NewClientSecurityObject();

    conn = rx_NewConnection(htonl(INADDR_LOOPBACK), port,
			    svc, secobj, RX_SECIDX_NULL);
    if (conn == NULL) {
	dprintf(2, "Did not get RX connection\n");
	exit(1);
    }

    /* prepare arguments for GSSNegotiate */
    /* enctypes */
    len = 3;
    tmp = malloc(len * sizeof(int));
    if (tmp == NULL) {
	dprintf(2, "couldn't allocate for params.enctypes\n");
	exit(1);
    }
    params.enctypes.len = len;
    params.enctypes.val = tmp;
    params.enctypes.val[0] = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    params.enctypes.val[1] = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
    params.enctypes.val[2] = ENCTYPE_DES_CBC_CRC;
   
    /* security levels */
    len = 3;
    tmp = malloc(len * sizeof(RXGK_Level));
    if (tmp == NULL) {
	dprintf(2, "couldn't allocate for params.levels\n");
	exit(1);
    }
    params.levels.len = len;
    params.levels.val = tmp;
    params.levels.val[0] = RXGK_LEVEL_CRYPT;
    params.levels.val[0] = RXGK_LEVEL_AUTH;
    params.levels.val[0] = RXGK_LEVEL_CLEAR;

    /* lifetimes (advisory) */
    params.lifetime = 60 * 60 * 10;	/* 10 hours */
    params.bytelife = 30;		/* 1 GiB */

    /* use a random nonce */
    len = 20;
    tmp = malloc(len);
    if (tmp == NULL) {
	dprintf(2, "couldn't allocate for params.client_nonce\n");
	exit(1);
    }
    ret = RAND_bytes(tmp, len);
    /* RAND_bytes returns 1 on success, sigh. */
    if (ret != 1) {
	dprintf(2, "no random data for client_nonce\n");
	exit(1);
    }
    params.client_nonce.len = len;
    params.client_nonce.val = tmp;

    /* Set a few things before entering the context-establishment loop. */
    token_in.len = 0;
    token_in.val = NULL;
    /* The GSS variables, too. */
    major_status = GSS_S_CONTINUE_NEEDED;
    gss_ctx = GSS_C_NO_CONTEXT;
    gss_token_ptr = (gss_buffer_desc *)GSS_C_NO_BUFFER;
    gss_flags = (GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG ) &
		~GSS_C_DELEG_FLAG;
    gss_token_in.value = sname;
    gss_token_in.length = strlen(sname);
    major_status = gss_import_name(&minor_status, &gss_token_in,
				   GSS_C_NT_HOSTBASED_SERVICE,
				   &target_name);
    gss_token_in.value = NULL;
    gss_token_in.length = 0;

    /* For the first call to GSSNegotiate(), there is no input opaque token. */
    opaque_in.len = 0;
    opaque_in.val = NULL;

    /* tell the XDR decoder to allocate space */
    token_out.len = 0;
    token_out.val = NULL;
    opaque_out.len = 0;
    opaque_out.val = NULL;
    info.len = 0;
    info.val = NULL;

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

	/* XXX error checking here */

	token_in.len = gss_token_in.length;
	token_in.val = gss_token_in.value;

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
	    printf("GSS negotiation finished, major %i minor %i\n",
		   major_status, minor_status);
	}

	/* Prepare for a possible next cycle */
	opaque_in.len = opaque_out.len;
	opaque_in.val = opaque_out.val;
	gss_token_out.length = token_out.len;
	gss_token_out.value = token_out.val;
	gss_token_ptr = &gss_token_out;
    } while(major_status == GSS_S_CONTINUE_NEEDED);
    /* end negotiation loop */

    if (major_status != GSS_S_COMPLETE) {
	dprintf(2, "GSS negotiation failed, major %i minor %i\n",
		major_status, minor_status);
	exit(2);
    }

    printf("GSSNegotiate returned info of length %zu\n", info.len);
    data = info.val;
    for(i = 0; i < info.len; ++i) {
	c = *(data + i);
	if (isascii(c))
	    putchar(c);
	else
	    putchar('?');
    }
    printf("\n");

    /* Done. */
    rx_Finalize();

    /* Free memory allocated by the XDR decoder */
    xdr_free((xdrproc_t)xdr_RXGK_Data, &token_out);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &opaque_out);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &info);

    return 0;
}
