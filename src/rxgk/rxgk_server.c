/* rxgk/rxgk_server.c - server-specific security object routines */
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
 * Server-specific security object routines.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>

/* OS-specific system includes go here */

#include <afs/opr.h>
#include <rx/rx.h>
#include <rx/xdr.h>
#include <rx/rx_packet.h>
#include <gssapi/gssapi.h>
#include <rx/rxgk.h>
#include <hcrypto/rand.h>
#include <afs/afsutil.h>

#include "rxgk_private.h"


static struct rx_securityOps rxgk_server_ops = {
    rxgk_Close,
    rxgk_NewConnection,
    rxgk_PreparePacket,		/* once per packet creation */
    0,				/* send packet (once per retrans) */
    rxgk_CheckAuthentication,
    rxgk_CreateChallenge,
    rxgk_GetChallenge,
    0,
    rxgk_CheckResponse,
    rxgk_CheckPacket,		/* check data packet */
    rxgk_DestroyConnection,
    rxgk_GetStats,
    rxgk_SetConfiguration,
    0,				/* spare 1 */
    0,				/* spare 2 */
};

struct rx_securityClass *
rxgk_NewServerSecurityObject(void *getkey_rock, rxgk_getkey_func getkey)
{
    struct rx_securityClass *sc;
    struct rxgk_sprivate *sp;

    sc = calloc(1, sizeof(*sc));
    if (sc == NULL)
	return NULL;
    sp = calloc(1, sizeof(*sp));
    if (sp == NULL) {
	free(sc);
	return NULL;
    }
    sc->ops = &rxgk_server_ops;
    sc->refCount = 1;
    sc->privateData = sp;

    /* Now get the server-private data. */
    sp->type = RXGK_SERVER;
    sp->flags = 0;
    sp->rock = getkey_rock;
    sp->getkey = getkey;

    return sc;
}

/* Did a connection properly authenticate? */
int
rxgk_CheckAuthentication(struct rx_securityClass *aobj,
			 struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;

    sc = rx_GetSecurityData(aconn);
    if (sc == NULL)
	return RXGK_INCONSISTENCY;

    return !(sc->auth);
}

/* Generate a challenge to be used later. */
int
rxgk_CreateChallenge(struct rx_securityClass *aobj,
		     struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;

    sc = rx_GetSecurityData(aconn);
    if (sc == NULL)
	return RXGK_INCONSISTENCY;

    /* The challenge is a 20-byte random nonce. */
    if (RAND_bytes(sc->challenge, 20) != 1)
	return RXGK_INCONSISTENCY;
    sc->auth = 0;
    return 0;
}

/* Incorporate a challenge into a packet */
int
rxgk_GetChallenge(struct rx_securityClass *aobj, struct rx_connection *aconn,
		  struct rx_packet *apacket)
{
    XDR xdrs;
    struct rxgk_sconn *sc;
    void *data;
    RXGK_Challenge challenge;
    int ret;
    u_int len;

    data = NULL;
    memset(&xdrs, 0, sizeof(xdrs));
    memset(&challenge, 0, sizeof(challenge));

    sc = rx_GetSecurityData(aconn);
    if (sc == NULL)
	return RXGK_INCONSISTENCY;
    memcpy(challenge.nonce, sc->challenge, 20);

    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Challenge(&xdrs, &challenge)) {
	ret = RXGK_BADCHALLENGE;
	goto cleanup;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);

    data = malloc(len);
    if (data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    xdrmem_create(&xdrs, data, len, XDR_ENCODE);
    if (!xdr_RXGK_Challenge(&xdrs, &challenge)) {
	ret = RXGK_BADCHALLENGE;
	goto cleanup;
    }
    rx_packetwrite(apacket, 0, len, data);
    rx_SetDataSize(apacket, len);
    sc->tried_auth = 1;
    ret = 0;
    
cleanup:
    free(data);
    xdr_destroy(&xdrs);
    return ret;
}

/* Process the response packet to a challenge */
int
rxgk_CheckResponse(struct rx_securityClass *aobj,
		   struct rx_connection *aconn, struct rx_packet *apacket)
{
    /* XXXBJK */
    return 0;
}

/* Set configuration values for the security object */
int
rxgk_SetConfiguration(struct rx_securityClass *aobj,
		      struct rx_connection *aconn,
		      rx_securityConfigVariables atype,
		      void *avalue, void **currentValue)
{
    /* XXXBJK */
    return 0;
}
