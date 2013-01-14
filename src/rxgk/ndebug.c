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
#include <ctype.h>

#include <afsconfig.h>
#include <afs/param.h>

#include <rx/rx.h>
#include <rx/rxgk.h>

int
main(int argc, char *argv[])
{
    RXGK_StartParams params;
    RXGK_Data token_out, token_in, opaque_in, opaque_out, info;
    RXGK_Level level;
    struct rx_securityClass *secobj;
    struct rx_connection *conn;
    unsigned char *data;
    size_t i;
    unsigned int major_status, minor_status, nonce;
    int ret, etype;
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
    /* XXXBJK dummy arguments for now */
    etype = 1;		/* des-cbc-crc */
    params.enctypes.len = 1;
    params.enctypes.val = &etype;
    level = RXGK_LEVEL_CLEAR;
    params.levels.len = 1;
    params.levels.val = &level;
    params.lifetime = 2;
    params.bytelife = 2;
    nonce = 0x41328576;
    params.client_nonce.len = 1;
    params.client_nonce.val = &nonce;

    token_in.len = 0;
    token_in.val = NULL;

    opaque_in.len = 0;
    opaque_in.val = NULL;

    /* tell the XDR decoder to allocate space */
    token_out.len = 0;
    token_out.val = NULL;
    opaque_out.len = 0;
    opaque_out.val = NULL;
    info.len = 0;
    info.val = NULL;

    /* Actual RPC call */
    ret = RXGK_GSSNegotiate(conn, &params, &token_in, &opaque_in, &token_out,
			    &opaque_out, &major_status, &minor_status, &info);

    if (ret != 0) {
	dprintf(2, "GSSNegotiate returned %i\n", ret);
	exit(1);
    }

    /* Decode the reply and print it to the user */
    if (major_status != GSS_S_COMPLETE) {
	printf("GSS negotiation incomplete, major %i minor %i\n",
	       major_status, minor_status);
    } else {
	printf("GSS negotiation successful, major %i minor %i\n",
	       major_status, minor_status);
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
