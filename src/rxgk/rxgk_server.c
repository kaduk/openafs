/* rxgk/rxgk_server.c - server-specific security object routines */
/*
 * Copyright (C) 2013, 2014 by the Massachusetts Institute of Technology.
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

#include <afs/opr.h>
#include <rx/rx.h>
#include <rx/xdr.h>
#include <rx/rx_packet.h>
#include <rx/rxgk.h>
#include <errno.h>

#include "rxgk_private.h"

/* Pre-declare the securityclass routines for the securityOps definition. */
struct rx_securityClass *rxgk_NewServerSecurityObject(void *getkey_rock,
						      rxgk_getkey_func getkey);
static int rxgk_ServerClose(struct rx_securityClass *aobj);
static int rxgk_NewServerConnection(struct rx_securityClass *aobj,
				    struct rx_connection *aconn);
static int rxgk_ServerPreparePacket(struct rx_securityClass *aobj,
				    struct rx_call *acall,
				    struct rx_packet *apacket);
static int rxgk_CheckAuthentication(struct rx_securityClass *aobj,
				    struct rx_connection *aconn);
static int rxgk_CreateChallenge(struct rx_securityClass *aobj,
				struct rx_connection *aconn);
static int rxgk_GetChallenge(struct rx_securityClass *aobj,
			     struct rx_connection *aconn,
			     struct rx_packet *apacket);
static int rxgk_CheckResponse(struct rx_securityClass *aobj,
			      struct rx_connection *aconn,
			      struct rx_packet *apacket);
static int rxgk_ServerCheckPacket(struct rx_securityClass *aobj,
				  struct rx_call *acall, struct rx_packet *apacket);
static int rxgk_DestroyServerConnection(struct rx_securityClass *aobj,
					struct rx_connection *aconn);
static int rxgk_ServerGetStats(struct rx_securityClass *aobj,
			       struct rx_connection *aconn,
			       struct rx_securityObjectStats *astats);

static struct rx_securityOps rxgk_server_ops = {
    rxgk_ServerClose,
    rxgk_NewServerConnection,
    rxgk_ServerPreparePacket,		/* once per packet creation */
    0,					/* send packet (once per retrans) */
    rxgk_CheckAuthentication,
    rxgk_CreateChallenge,
    rxgk_GetChallenge,
    0,
    rxgk_CheckResponse,
    rxgk_ServerCheckPacket,		/* check data packet */
    rxgk_DestroyServerConnection,
    rxgk_ServerGetStats,
    0,
    0,				/* spare 1 */
    0,				/* spare 2 */
};

/**
 * The low-level routine to generate a new server security object.
 *
 * Takes a getkey function and its rock.
 *
 * It is not expected that most callers will use this function, as
 * we provide helpers that do other setup, setting service-specific
 * data and such.
 */
struct rx_securityClass *
rxgk_NewServerSecurityObject(void *getkey_rock, rxgk_getkey_func getkey)
{
    struct rx_securityClass *sc;
    struct rxgk_sprivate *sp;

    sc = rxi_Alloc(sizeof(*sc));
    if (sc == NULL)
	return NULL;
    sp = rxi_Alloc(sizeof(*sp));
    if (sp == NULL) {
	rxi_Free(sc, sizeof(*sc));
	return NULL;
    }
    sc->ops = &rxgk_server_ops;
    sc->refCount = 1;
    sc->privateData = sp;

    /* Now set the server-private data. */
    sp->flags = 0;
    sp->rock = getkey_rock;
    sp->getkey = getkey;

    return sc;
}

/**
 * Produce an rxgk server security object and provide the RXGK_ service
 *
 * Wrapper around rxgk_NewServerSecurityObject and rx_NewService.
 * We need to register a key negotiation service for anything with
 * an rxgk server security object; this wrapper takes care of a bit
 * of the boilerplate and also helps ensure that the routine to
 * fetch the long-term key for the token negotiation service is
 * the same as that used for the security object which will receive
 * those tokens.
 *
 * @param[in] port	The port on which the RXGK service should listen
 *			(0 for the default port).
 * @param[out] service_out	Returns a pointer to the rx service created.
 * @param[in] serviceName	A descriptive name for the rx service created.
 * @param[out] secObjs	An array of security objects; the rxgk server security
 *			object is inserted at RX_SECIDX_GK.
 * @param[in] nsecObjs	The length of the secObjs array (must be at least 5).
 * @param[in] getkey	The getkey function to use for the security object
 *			and encrypting the tokens created by the RXGK_ service.
 * @param[in] getkey_rock	Data to pass to getkey.
 * @return rxgk error codes.
 */
afs_int32
rxgk_NewService_SecObj(u_short port, struct rx_service **service_out,
		       char *serviceName,
		       struct rx_securityClass **secObjs, int nsecObjs,
		       rxgk_getkey_func getkey, void *getkey_rock)
{
    struct rx_service *service = NULL;
    struct rx_securityClass *so = NULL;
    afs_int32 ret;
    u_short svc = RXGK_SERVICE_ID;

    if (nsecObjs < 5 || secObjs == NULL || service_out == NULL)
	return RX_INVALID_OPERATION;

    *service_out = NULL;

    so = rxgk_NewServerSecurityObject(getkey_rock, getkey);
    service = rx_NewService(port, svc, serviceName, secObjs, nsecObjs,
			     RXGK_ExecuteRequest);

    if (so != NULL && service != NULL) {
	ret = rxgk_set_getkey_specific(service, getkey, getkey_rock);
	if (ret != 0)
	    goto cleanup;
	secObjs[RX_SECIDX_GK] = so;
	*service_out = service;
	return 0;
    } /* else */
cleanup:
    rxgk_ServerClose(so);
    /* No way to de-allocate a service? */
    return RXGK_INCONSISTENCY;
}

/*
 * Helper for NewEphemeralService_SecObj.
 * The rock contains a key, and we just return a copy of it, after some
 * sanity checking on the kvno and enctype.
 */
#define EPHEMERAL_ENCTYPE	17
static afs_int32
copy_getkey(void *rock, afs_int32 *kvno, afs_int32 *enctype, rxgk_key *new_key)
{
    rxgk_key secret_key = rock;

    if (enctype == NULL || (*enctype != 0 && *enctype != EPHEMERAL_ENCTYPE))
	return RXGK_BADETYPE;
    if (kvno == NULL || *kvno < 0 || *kvno > 1)
	return RXGK_BADKEYNO;

    *enctype = EPHEMERAL_ENCTYPE;
    *kvno = 1;
    return rxgk_copy_key(secret_key, new_key);
}

/**
 * Create a server security object and service using an ephemeral long-term key
 *
 * Creates an ephemeral random key which is used as the "long-term" private
 * key for the rxgk security object and service which are returned.  This
 * is intended to be used for applications where generating a new key each
 * time the application starts up is reasonable.
 *
 * @sa rxgk_NewService_SecObj
 */
afs_int32
rxgk_NewEphemeralService_SecObj(u_short port, struct rx_service **service_out,
				char *serviceName,
				struct rx_securityClass **secObjs, int nsecObjs)
{
    rxgk_key key;
    afs_int32 ret;

    ret = rxgk_random_key(EPHEMERAL_ENCTYPE, &key);
    if (ret != 0)
	return ret;
    return rxgk_NewService_SecObj(port, service_out, serviceName, secObjs,
				  nsecObjs, &copy_getkey, key);
}

/*
 * Increment the reference count on the security object secobj.
 */
static_inline void
obj_ref(struct rx_securityClass *secobj)
{
    secobj->refCount++;
}

/*
 * Decrement the reference count on the security object secobj.
 * If the reference count falls to zero, release the underlying storage.
 */
static void
obj_rele(struct rx_securityClass *secobj)
{
    struct rxgk_sprivate *sp;

    secobj->refCount--;
    if (secobj->refCount > 0) {
	/* still in use */
	return;
    }

    sp  = secobj->privateData;
    rxi_Free(secobj, sizeof(*secobj));
    rxi_Free(sp, sizeof(*sp));
    return;
}

/* Release a server security object. */
static int
rxgk_ServerClose(struct rx_securityClass *aobj)
{
    obj_rele(aobj);
    return 0;
}

/*
 * Create a new rx connection on this given server security object.
 */
static int
rxgk_NewServerConnection(struct rx_securityClass *aobj,
			 struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;

    /* Take a reference before we do anything else. */
    obj_ref(aobj);
    if (rx_GetSecurityData(aconn) != NULL)
	goto error;

    sc = rxi_Alloc(sizeof(*sc));
    if (sc == NULL)
	goto error;
    rx_SetSecurityData(aconn, sc);
    return 0;
error:
    obj_rele(aobj);
    return RXGK_INCONSISTENCY;
}

/*
 * Server-specific packet preparation routine.  All the interesting bits
 * are in rx_packet; all we have to do here is extract data from the
 * security data on the connection and use the proper key usage.
 */
static int
rxgk_ServerPreparePacket(struct rx_securityClass *aobj, struct rx_call *acall,
			 struct rx_packet *apacket)
{
    struct rxgk_sconn *sc;
    struct rx_connection *aconn;
    rxgk_key tk;
    afs_uint32 lkvno;
    afs_uint16 wkvno, len;
    int ret;

    aconn = rx_ConnectionOf(acall);
    sc = rx_GetSecurityData(aconn);

    if (sc->expiration < RXGK_NOW() && sc->expiration != 0)
	return RXGK_EXPIRED;
    len = rx_GetDataSize(apacket);
    lkvno = sc->key_number;
    sc->stats.psent++;
    sc->stats.bsent += len;
    wkvno = (afs_uint16)lkvno;
    rx_SetPacketCksum(apacket, htons(wkvno));
    ret = rxgk_derive_tk(&tk, sc->k0, rx_GetConnectionEpoch(aconn),
			 rx_GetConnectionId(aconn), sc->start_time, lkvno);
    if (ret != 0)
	return ret;

    switch(sc->level) {
	case RXGK_LEVEL_CLEAR:
	    ret = 0;
	    break;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_mic_packet(tk, RXGK_SERVER_MIC_PACKET, aconn, apacket);
	    break;
	case RXGK_LEVEL_CRYPT:
	    ret = rxgk_enc_packet(tk, RXGK_SERVER_ENC_PACKET, aconn, apacket);
	    break;
	default:
	    ret = RXGK_INCONSISTENCY;
	    break;
    }

    rxgk_release_key(&tk);
    return ret;
}

/* Did a connection properly authenticate? */
static int
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
static int
rxgk_CreateChallenge(struct rx_securityClass *aobj,
		     struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;
    struct rx_opaque buf = RX_EMPTY_OPAQUE;

    sc = rx_GetSecurityData(aconn);
    if (sc == NULL)
	return RXGK_INCONSISTENCY;
    sc->auth = 0;

    /* The challenge is a 20-byte random nonce. */
    if (rxgk_nonce(&buf, 20) != 0)
	return RXGK_INCONSISTENCY;
    memcpy(&sc->challenge, buf.val, 20);
    rx_opaque_freeContents(&buf);
    return 0;
}

/* Incorporate a challenge into a packet */
static int
rxgk_GetChallenge(struct rx_securityClass *aobj, struct rx_connection *aconn,
		  struct rx_packet *apacket)
{
    XDR xdrs;
    struct rxgk_sconn *sc;
    void *data = NULL;
    RXGK_Challenge challenge;
    int ret;
    u_int len;

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

    data = rxi_Alloc(len);
    if (data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, data, len, XDR_ENCODE);
    if (!xdr_RXGK_Challenge(&xdrs, &challenge)) {
	ret = RXGK_BADCHALLENGE;
	goto cleanup;
    }
    opr_Assert(len <= 0xffffu);
    rx_packetwrite(apacket, 0, len, data);
    rx_SetDataSize(apacket, len);
    sc->tried_auth = 1;
    ret = 0;

cleanup:
    if (data != NULL)
	rxi_Free(data, len);
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Helper functions for CheckResponse.
 */

/*
 * The XDR token format uses the XDR PrAuthName type to store identities.
 * However, there is an existing rx_identity type used in libauth, so
 * we convert from the wire type to the internal type as soon as possible
 * in order to be able to use the most library code.
 */
static struct rx_identity *
prnames_to_identity(PrAuthName *namelist, size_t nnames)
{
    rx_identity_kind kind;
    struct rx_identity *tmp;
    char *display;

    /* Could grab the acceptor identity from ServiceSpecific if wanted. */
    if (nnames == 0)
	return rx_identity_new(RX_ID_SUPERUSER, "<printed token>",
			       "", 0);
    else if (nnames > 1)
	return NULL;
    /* XXX Need a solution for compound identities! */
    if (namelist[0].kind == 1)
	kind = RX_ID_KRB4;
    else if (namelist[0].kind == 2)
	kind = RX_ID_GSS;
    else
	return NULL;
    display = rxi_Alloc(namelist[0].display.len + 1);
    if (display == NULL)
	return NULL;
    memcpy(display, namelist[0].display.val, namelist[0].display.len);
    display[namelist[0].display.len] = '\0';
    tmp = rx_identity_new(kind, display, namelist[0].data.val,
			  namelist[0].data.len);
    rxi_Free(display, namelist[0].display.len + 1);
    return tmp;
}

/*
 * Unpack, decrypt, and extract information from a token.
 * Store the relevant bits in the connection security data.
 */
static int
process_token(RXGK_Data *tc, struct rxgk_sprivate *sp, struct rxgk_sconn *sc)
{
    RXGK_Token token;
    int ret;

    memset(&token, 0, sizeof(token));

    ret = rxgk_extract_token(tc, &token, sp->getkey, sp->rock);
    if (ret != 0)
	goto cleanup;

    /* Stash the token master key in the per-connection data. */
    if (sc->k0 != NULL)
	rxgk_release_key(&sc->k0);
    ret = rxgk_make_key(&sc->k0, token.K0.val, token.K0.len, token.enctype);
    if (ret != 0)
	goto cleanup;
    sc->level = token.level;
    sc->expiration = token.expirationtime;
    if (sc->client != NULL)
	rx_identity_free(&sc->client);
    sc->client = prnames_to_identity(token.identities.val,
				     token.identities.len);

cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_Token, &token);
    return ret;
}

/* Caller is responsible for freeing 'out'. */
static int
decrypt_authenticator(RXGK_Authenticator *out, struct rx_opaque *in,
		      struct rx_connection *aconn, struct rxgk_sconn *sc,
		      struct rx_packet *apacket)
{
    XDR xdrs;
    struct rx_opaque packauth = RX_EMPTY_OPAQUE;
    rxgk_key tk = NULL;
    afs_uint32 lkvno, kvno = 0;
    afs_uint16 wkvno;
    int ret;

    memset(&xdrs, 0, sizeof(xdrs));

    wkvno = ntohs(rx_GetPacketCksum(apacket));
    lkvno = sc->key_number;
    ret = rxgk_key_number(wkvno, lkvno, &kvno);
    if (ret != 0)
	return ret;
    ret = rxgk_derive_tk(&tk, sc->k0, rx_GetConnectionEpoch(aconn),
			 rx_GetConnectionId(aconn), sc->start_time, kvno);
    if (ret != 0)
	return ret;
    ret = rxgk_decrypt_in_key(tk, RXGK_CLIENT_ENC_RESPONSE, in, &packauth);
    if (ret != 0) {
	rxgk_release_key(&tk);
	return ret;
    }
    if (kvno > lkvno)
	rxgk_update_kvno(aconn, kvno);

    /* XXX easier error handling with a separate decode_authenticator() */
    xdrmem_create(&xdrs, packauth.val, packauth.len, XDR_DECODE);
    if (!xdr_RXGK_Authenticator(&xdrs, out)) {
	ret = RXGEN_SS_UNMARSHAL;
	goto cleanup;
    }
    ret = 0;
cleanup:
    rx_opaque_freeContents(&packauth);
    rxgk_release_key(&tk);
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Make the authenticator do its job with channel binding and nonce
 * verification.
 */
static int
check_authenticator(RXGK_Authenticator *authenticator,
		    struct rx_connection *aconn, struct rxgk_sconn *sc)
{
    if (memcmp(authenticator->nonce, sc->challenge, 20) != 0)
	return RXGK_SEALED_INCON;
    if (authenticator->level != sc->level)
	return RXGK_BADLEVEL;
    /* XXX Checking RX_MAXCALLS breaks hypothetical other rx implementations. */
    if (authenticator->epoch != (afs_uint32)rx_GetConnectionEpoch(aconn) ||
	authenticator->cid != (afs_uint32)rx_GetConnectionId(aconn) ||
	authenticator->call_numbers.len != RX_MAXCALLS)
	return RXGK_BADCHALLENGE;
    /* XXX We do nothing with the appdata. */
    return 0;
}

/* Process the response packet to a challenge */
static int
rxgk_CheckResponse(struct rx_securityClass *aobj,
		   struct rx_connection *aconn, struct rx_packet *apacket)
{
    struct rxgk_sprivate *sp;
    struct rxgk_sconn *sc;
    XDR xdrs;
    RXGK_Response response;
    RXGK_Authenticator authenticator;
    int ret;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(&response, 0, sizeof(response));
    memset(&authenticator, 0, sizeof(authenticator));

    sp = aobj->privateData;
    sc = rx_GetSecurityData(aconn);

    /* XXX Assumes that the entire response is in a contiguous data block
     * in the packet. */
    xdrmem_create(&xdrs, rx_DataOf(apacket), rx_GetDataSize(apacket),
		  XDR_DECODE);
    if (!xdr_RXGK_Response(&xdrs, &response)) {
	ret = RXGEN_SS_UNMARSHAL;
	goto cleanup;
    }

    /* Stash useful bits from the token in sc. */
    ret = process_token(&response.token, sp, sc);
    if (ret != 0)
	goto cleanup;
    if (sc->expiration < RXGK_NOW() && sc->expiration != 0) {
	ret = RXGK_EXPIRED;
	goto cleanup;
    }

    /*
     * Cache the client-provided start_time.  If this is wrong, we cannot
     * derive the correct transport key and the authenticator decryption
     * will fail.
     */
    sc->start_time = response.start_time;

    /* Try to decrypt the authenticator. */
    ret = decrypt_authenticator(&authenticator, &response.authenticator, aconn,
				sc, apacket);
    if (ret != 0)
	goto cleanup;
    ret = check_authenticator(&authenticator, aconn, sc);
    if (ret != 0)
	goto cleanup;
    /* Success! */
    rxgk_security_overhead(aconn, sc->level, sc->k0);
    sc->auth = 1;
    (void)rxi_SetCallNumberVector(aconn,
				  (afs_int32 *)authenticator.call_numbers.val);

cleanup:
    xdr_destroy(&xdrs);
    xdr_free((xdrproc_t)xdr_RXGK_Response, &response);
    xdr_free((xdrproc_t)xdr_RXGK_Authenticator, &authenticator);
    return ret;
}

/*
 * Server-specific packet receipt routine.
 * The interesting bits are in rx_packet.c, we just extract data from
 * the connection security data and choose key usage values.
 */
static int
rxgk_ServerCheckPacket(struct rx_securityClass *aobj, struct rx_call *acall,
		       struct rx_packet *apacket)
{
    struct rxgk_sconn *sc;
    struct rx_connection *aconn;
    rxgk_key tk;
    afs_uint32 lkvno, kvno = 0;
    afs_uint16 wkvno, len;;
    int ret;

    aconn = rx_ConnectionOf(acall);
    sc = rx_GetSecurityData(aconn);

    len = rx_GetDataSize(apacket);
    lkvno = sc->key_number;
    sc->stats.precv++;
    sc->stats.brecv += len;
    wkvno = ntohs(rx_GetPacketCksum(apacket));
    if (sc->expiration < RXGK_NOW() && sc->expiration != 0)
	return RXGK_EXPIRED;
    ret = rxgk_key_number(wkvno, lkvno, &kvno);
    if (ret != 0)
	return ret;
    ret = rxgk_derive_tk(&tk, sc->k0, rx_GetConnectionEpoch(aconn),
			 rx_GetConnectionId(aconn), sc->start_time, kvno);
    if (ret != 0)
	return ret;

    switch(sc->level) {
	case RXGK_LEVEL_CLEAR:
	    /* Do not fall through to the kvno update with no crypto. */
	    rxgk_release_key(&tk);
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_check_mic_packet(tk, RXGK_CLIENT_MIC_PACKET, aconn,
					apacket);
	    break;
	case RXGK_LEVEL_CRYPT:
	    ret = rxgk_decrypt_packet(tk, RXGK_CLIENT_ENC_PACKET, aconn,
				      apacket);
	    break;
	default:
	    ret = RXGK_INCONSISTENCY;
    }
    if (ret == 0 && kvno > lkvno)
	rxgk_update_kvno(aconn, kvno);

    rxgk_release_key(&tk);
    return ret;
}

/*
 * Perform server-side connection-specific teardown.
 */
static int
rxgk_DestroyServerConnection(struct rx_securityClass *aobj,
			     struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;

    sc = rx_GetSecurityData(aconn);
    rx_SetSecurityData(aconn, NULL);

    rxgk_release_key(&sc->k0);
    rxgk_release_key(&sc->cb_key);
    rx_opaque_freeContents(&sc->cb_tok);
    if (sc->client != NULL)
	rx_identity_free(&sc->client);
    rxi_Free(sc, sizeof(*sc));
    obj_rele(aobj);
    return 0;
}

/*
 * Get statistics about this connection.
 */
static int
rxgk_ServerGetStats(struct rx_securityClass *aobj, struct rx_connection *aconn,
		    struct rx_securityObjectStats *astats)
{
    struct rxgkStats *stats;
    struct rxgk_sconn *sc;

    astats->type = 4;	/* rxgk */
    sc = rx_GetSecurityData(aconn);
    if (sc == NULL) {
	astats->flags |= 1;
	return 0;
    }

    stats = &sc->stats;
    astats->level = sc->level;
    if (sc->auth)
	astats->flags |= 2;
    /* rxgkTime is 100s of nanoseconds; time here is seconds */
    astats->expires = (afs_uint32)(sc->expiration / 10000000);

    astats->packetsReceived = stats->precv;
    astats->packetsSent = stats->psent;
    astats->bytesReceived = stats->brecv;
    astats->bytesSent = stats->bsent;

    return 0;
}

/*
 * Get some information about this connection, in particular the security
 * level, expiry time, and the remote user's identity.
 */
afs_int32
rxgk_GetServerInfo(struct rx_connection *conn, RXGK_Level *level,
		   rxgkTime *expiry, struct rx_identity **identity)
{
    struct rxgk_sconn *sconn;

    sconn = rx_GetSecurityData(conn);
    if (sconn == NULL)
	return RXGK_INCONSISTENCY;
    opr_Assert(identity != NULL);
    *identity = rx_identity_copy(sconn->client);
    if (*identity == NULL)
	return ENOMEM;
    if (level != NULL)
	*level = sconn->level;
    if (expiry != NULL)
	*expiry = sconn->expiration;
    return 0;
}
