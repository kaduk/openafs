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
#include <rx/rxgk.h>

#include "rxgk_private.h"

/* Pre-declare the securityclass routines for the securityOps definition. */
static int rxgk_ClientClose(struct rx_securityClass *aobj);
static int rxgk_NewClientConnection(struct rx_securityClass *aobj,
				    struct rx_connection *aconn);
static int rxgk_ClientPreparePacket(struct rx_securityClass *aobj,
				    struct rx_call *acall,
				    struct rx_packet *apacket);
static int rxgk_GetResponse(struct rx_securityClass *aobj,
			    struct rx_connection *aconn, struct rx_packet *apacket);
static int rxgk_ClientCheckPacket(struct rx_securityClass *aobj,
				  struct rx_call *acall, struct rx_packet *apacket);
static int rxgk_DestroyClientConnection(struct rx_securityClass *aobj,
					struct rx_connection *aconn);
static int rxgk_ClientGetStats(struct rx_securityClass *aobj,
			       struct rx_connection *aconn,
			       struct rx_securityObjectStats *astats);

static struct rx_securityOps rxgk_client_ops = {
    rxgk_ClientClose,
    rxgk_NewClientConnection,		/* every new connection */
    rxgk_ClientPreparePacket,		/* once per packet creation */
    0,					/* send packet (once per retrans) */
    0,
    0,
    0,
    rxgk_GetResponse,			/* respond to challenge packet */
    0,
    rxgk_ClientCheckPacket,		/* check data packet */
    rxgk_DestroyClientConnection,
    rxgk_ClientGetStats,
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

    sc = rxi_Alloc(sizeof(*sc));
    if (sc == NULL)
	return NULL;
    cp = rxi_Alloc(sizeof(*cp));
    if (cp == NULL) {
	free(sc);
	return NULL;
    }
    sc->ops = &rxgk_client_ops;
    sc->refCount = 1;
    sc->privateData = cp;

    /* Now get the client-private data. */
    cp->flags = 0;
    cp->k0 = k0;
    cp->enctype = enctype;
    cp->level = level;
    if (rx_opaque_copy(&cp->token, token) != 0) {
	free(sc);
	free(cp);
	return NULL;
    }
    if (uuid != NULL) {
	cp->uuid = rxi_Alloc(sizeof(*uuid));
	if (cp->uuid == NULL) {
	    free(sc);
	    rx_opaque_freeContents(&cp->token);
	    free(cp);
	    return NULL;
	}
	memcpy(&cp->uuid, uuid, sizeof(*uuid));
    }

    return sc;
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
    struct rx_opaque token = RX_EMPTY_OPAQUE;
    afs_int32 ret;

    memset(&info, 0, sizeof(info));
    memset(&k0, 0, sizeof(k0));

    ret = rxgk_get_token(svc, hostname, addr, port, level, &info, &k0, &token);
    if (ret != 0)
	return NULL;
    so = rxgk_NewClientSecurityObject(info.level, info.enctype, k0, &token,
				      uuid);

    /* k0 is donated to the security object for now */
    rx_opaque_freeContents(&token);
    xdr_free((xdrproc_t)xdr_RXGK_TokenInfo, &info);
    return so;
}

static int
release_object(struct rx_securityClass *secobj)
{
    struct rxgk_cprivate *cp;

    cp = secobj->privateData;
    rxi_Free(secobj, sizeof(*secobj));
    /* XXX free k0 but it is not a copy yet */
    rxi_Free(cp->uuid, sizeof(*cp->uuid));
    rxi_Free(cp, sizeof(*cp));

    return 0;
}

static int
rxgk_ClientClose(struct rx_securityClass *aobj)
{
    aobj->refCount--;
    if (aobj->refCount > 0) {
	/* still in use */
	return 0;
    }
    return release_object(aobj);
}

static int
rxgk_NewClientConnection(struct rx_securityClass *aobj,
			 struct rx_connection *aconn)
{
    struct rxgk_cconn *cc;
    struct rxgk_cprivate *cp;

    /* Take a reference before we do anything else. */
    aobj->refCount++;
    if (rx_GetSecurityData(aconn) != NULL)
	goto error;
    cp = aobj->privateData;

    cc = rxi_Alloc(sizeof(*cc));
    if (cc == NULL)
	goto error;
    cc->start_time = RXGK_NOW();
    /* XXX need epoch (once) and connection ID (always) */
    rx_SetSecurityData(aconn, cc);
    /* Set the header and trailer size to be reserved for the security
     * class in each packet. */
    if (rxgk_security_overhead(aconn, cp->level, cp->k0) != 0)
	goto error;
    return 0;
error:
    aobj->refCount--;
    return RXGK_INCONSISTENCY;
}

static int
rxgk_ClientPreparePacket(struct rx_securityClass *aobj, struct rx_call *acall,
			 struct rx_packet *apacket)
{
    struct rxgk_cconn *cc;
    struct rxgk_cprivate *cp;
    struct rx_connection *aconn;
    RXGK_Level level;
    rxgk_key k0, tk;
    rxgkTime start_time;
    afs_uint32 lkvno;
    afs_uint16 wkvno;
    int ret, len;

    aconn = rx_ConnectionOf(acall);
    cc = rx_GetSecurityData(aconn);
    cp = aobj->privateData;

    len = rx_GetDataSize(apacket);
    level = cp->level;
    k0 = cp->k0;
    start_time = cc->start_time;
    lkvno = cc->key_number;
    cc->stats.psent++;
    cc->stats.bsent += len;
    wkvno = (afs_int16)lkvno;
    rx_SetPacketCksum(apacket, htons(wkvno));
    ret = rxgk_derive_tk(&tk, k0, rx_GetConnectionEpoch(aconn),
			 rx_GetConnectionId(aconn), start_time, lkvno);
    if (ret != 0)
	return ret;

    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_mic_packet(tk, RXGK_CLIENT_MIC_PACKET, aconn, apacket);
	    break;
	case RXGK_LEVEL_CRYPT:
	    ret = rxgk_enc_packet(tk, RXGK_CLIENT_ENC_PACKET, aconn, apacket);
	    break;
	default:
	    return RXGK_INCONSISTENCY;
    }

    return ret;
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
	ret = rx_opaque_alloc(&authenticator->appdata, len);
	if (ret != 0)
	    goto cleanup;
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
    struct rx_opaque data = RX_EMPTY_OPAQUE;
    rxgk_key tk;
    int ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    tk = NULL;

    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Authenticator(&xdrs, authenticator)) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    len = xdr_getpos(&xdrs);
    ret = rx_opaque_alloc(&data, len);
    if (ret != 0)
	goto cleanup;
    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, data.val, len, XDR_ENCODE);
    if (!xdr_RXGK_Authenticator(&xdrs, authenticator)) {
	ret = RXGEN_CC_MARSHAL;
	goto cleanup;
    }
    ret = rxgk_derive_tk(&tk, cp->k0, authenticator->epoch, authenticator->cid,
		    cc->start_time, cc->key_number);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_encrypt_in_key(tk, RXGK_CLIENT_ENC_RESPONSE, &data, encdata);
    if (ret != 0)
	goto cleanup;

cleanup:
    xdr_destroy(&xdrs);
    rx_opaque_freeContents(&data);
    rxgk_release_key(&tk);
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
    ret = rx_opaque_alloc(out, len);
    if (ret != 0)
	goto cleanup;
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
static int
rxgk_GetResponse(struct rx_securityClass *aobj, struct rx_connection *aconn,
		 struct rx_packet *apacket)
{
    struct rxgk_cprivate *cp;
    struct rxgk_cconn *cc;
    XDR xdrs;
    RXGK_Challenge challenge;
    RXGK_Response response;
    RXGK_Authenticator authenticator;
    struct rx_opaque encdata = RX_EMPTY_OPAQUE, packed = RX_EMPTY_OPAQUE;
    int ret;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(&challenge, 0, sizeof(challenge));
    memset(&response, 0, sizeof(response));
    memset(&authenticator, 0, sizeof(authenticator));

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
    if (rx_opaque_copy(&response.token, &cp->token) != 0) {
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
    ret = rx_opaque_copy(&response.authenticator, &encdata);
    if (ret != 0)
	goto cleanup;
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
    rx_opaque_freeContents(&encdata);
    rx_opaque_freeContents(&packed);
    return ret;
}

static int
rxgk_ClientCheckPacket(struct rx_securityClass *aobj, struct rx_call *acall,
		       struct rx_packet *apacket)
{
    struct rxgk_cconn *cc;
    struct rxgk_cprivate *cp;
    struct rx_connection *aconn;
    RXGK_Level level;
    rxgk_key k0, tk;
    rxgkTime start_time;
    afs_uint32 lkvno, kvno;
    afs_uint16 wkvno;
    int ret, len;

    aconn = rx_ConnectionOf(acall);
    cc = rx_GetSecurityData(aconn);
    cp = aobj->privateData;

    len = rx_GetDataSize(apacket);
    level = cp->level;
    k0 = cp->k0;
    start_time = cc->start_time;
    lkvno = cc->key_number;
    cc->stats.precv++;
    cc->stats.brecv += len;
    wkvno = ntohs(rx_GetPacketCksum(apacket));
    ret = rxgk_key_number(wkvno, lkvno, &kvno);
    if (ret != 0)
	return ret;
    ret = rxgk_derive_tk(&tk, k0, rx_GetConnectionEpoch(aconn),
			 rx_GetConnectionId(aconn), start_time, kvno);
    if (ret != 0)
	return ret;

    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    /* Do not fall through to the kvno update with no crypto. */
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_check_mic_packet(tk, RXGK_SERVER_MIC_PACKET, aconn,
					apacket);
	    break;
	case RXGK_LEVEL_CRYPT:
	    ret = rxgk_decrypt_packet(tk, RXGK_SERVER_ENC_PACKET, aconn,
				      apacket);
	    break;
	default:
	    return RXGK_INCONSISTENCY;
    }
    if (ret == 0 && kvno > lkvno)
	rxgk_update_kvno(aconn, kvno);

    return ret;
}

static int
rxgk_DestroyClientConnection(struct rx_securityClass *aobj,
			     struct rx_connection *aconn)
{
    struct rxgk_cconn *cc;

    cc = rx_GetSecurityData(aconn);
    rx_SetSecurityData(aconn, NULL);

    rxi_Free(cc, sizeof(*cc));
    aobj->refCount--;
    if (aobj->refCount <= 0) {
	return release_object(aobj);
    }
    return 0;
}

static int
rxgk_ClientGetStats(struct rx_securityClass *aobj, struct rx_connection *aconn,
		    struct rx_securityObjectStats *astats)
{
    struct rxgkStats *stats;
    struct rxgk_cprivate *cp;
    struct rxgk_cconn *cc;

    astats->type = 4;	/* rxgk */
    cc = rx_GetSecurityData(aconn);
    if (cc == NULL) {
	astats->flags |= 1;
	return 0;
    }

    stats = &cc->stats;
    cp = rx_GetSecurityData(aconn);
    astats->level = cp->level;

    astats->packetsReceived = stats->precv;
    astats->packetsSent = stats->psent;
    astats->bytesReceived = stats->brecv;
    astats->bytesSent = stats->bsent;
	
    return 0;
}
