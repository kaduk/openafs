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
    afs_int32 call_numbers[RX_MAXCALLS], maxcall;
    int ret, i, ncalls;
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
    ncalls = maxcall = 0;
    for(i = 0; i < RX_MAXCALLS; ++i)
	maxcall = (maxcall > call_numbers[i]) ? maxcall : call_numbers[i];
    authenticator->maxcalls = maxcall;
    authenticator->call_numbers.val = xdr_alloc(RX_MAXCALLS *
						sizeof(afs_int32));
    if (authenticator->call_numbers.val == NULL) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    authenticator->call_numbers.len = RX_MAXCALLS;
    for(i = 0; i < ncalls; ++i)
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
    /* XXX key number hardcoded at zero. */
    ret = derive_tk(&tk, cp->k0, authenticator->epoch, authenticator->cid,
		    cc->start_time, 0);
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
