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
#include <gssapi/gssapi.h>
#include <rx/rxgk.h>

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
			     RXGK_Data *token)
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

    return sc;
}

/* Respondn to a challenge packet */
int
rxgk_GetResponse(struct rx_securityClass *aobj, struct rx_connection *aconn,
		 struct rx_packet *apacket)
{
    /* XXXBJK */
    return 0;
}
