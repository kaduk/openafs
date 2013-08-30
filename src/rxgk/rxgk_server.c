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
    0,
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

/*
 * Wrapper around rxgk_NewServerSecurityObject and rx_NewService.
 * We need to register a key negotiation service for anything with
 * an rxgk server security object; this wrapper takes care of a bit
 * of the boilerplate and also helps ensure that the routine to
 * fetch the long-term key for the token negotiation service is
 * the same as that used for the security object which will receive
 * those tokens.
 */
afs_int32
rxgk_NewService_SecObj(u_short port, struct rx_service **service_out,
		       char *serviceName,
		       struct rx_securityClass **secObjs, int nsecObjs,
		       rxgk_getkey_func getkey, void *getkey_rock)
{
    struct rx_service *service = NULL;
    struct rx_securityClass *so = NULL;
    struct rxgk_getkey_sspecific_data *gk;
    afs_int32 ret;
    u_short svc = 34567;

    if (nsecObjs < 5 || secObjs == NULL || service_out == NULL)
	return RX_INVALID_OPERATION;

    gk = calloc(1, sizeof(*gk));

    so = rxgk_NewServerSecurityObject(getkey_rock, getkey);
    service = rx_NewService(port, svc, serviceName, secObjs, nsecObjs,
			     RXGK_ExecuteRequest);

    if (gk != NULL && so != NULL && service != NULL) {
	secObjs[RX_SECIDX_GK] = so;
	so = NULL;
	*service_out = service;
	service = NULL;
	gk->getkey = getkey;
	gk->rock = getkey_rock;
	rx_SetServiceSpecific(*service_out, RXGK_NEG_SSPECIFIC_GETKEY, gk);
	return 0;
    } /* else */
    free(gk);
    return RXGK_INCONSISTENCY;
}

/*
 * Helper for NewEphemeralService_SecObj.
 * The rock contains a key, and we just return a copy of it, after some
 * sanity checking on the kvno and enctype.
 */
#define EPHEMERAL_ENCTYPE	18
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
    return copy_key(secret_key, new_key);
}

/*
 * Creates an ephemeral random key which is used as the "long-term" private
 * key for the rxnull and rxgk security objects which are returned.  This
 * is intended to be used for applications where generating a new key each
 * time the application starts up is reasonable.
 */
afs_int32
rxgk_NewEphemeralService_SecObj(u_short port, struct rx_service **service_out,
				char *serviceName,
				struct rx_securityClass **secObjs, int nsecObjs)
{
    rxgk_key key;
    afs_int32 ret;

    ret = random_key(EPHEMERAL_ENCTYPE, &key);
    if (ret != 0)
	return ret;
    return rxgk_NewService_SecObj(port, service_out, serviceName, secObjs,
				  nsecObjs, &copy_getkey, key);
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

/*
 * Helper functions for CheckResponse.
 */

static int
unpack_container(RXGK_TokenContainer *container, RXGK_Data *in)
{
    XDR xdrs;

    memset(&xdrs, 0, sizeof(xdrs));

    xdrmem_create(&xdrs, in->val, in->len, XDR_DECODE);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	xdr_destroy(&xdrs);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdrs);
    return 0;
}

static int
decrypt_token(RXGK_Data *out, struct rx_opaque *encopaque, afs_int32 kvno,
	      afs_int32 enctype, struct rxgk_sprivate *sp)
{
    rxgk_key service_key;
    RXGK_Data enctoken;
    afs_int32 ret;

    service_key = NULL;
    zero_rxgkdata(&enctoken);

    if (kvno <= 0 || enctype <= 0)
	return RXGK_BAD_TOKEN;

    ret = sp->getkey(sp->rock, &kvno, &enctype, &service_key);
    if (ret != 0)
	goto cleanup;
    /* Must alias for type compliance */
    enctoken.val = encopaque->val;
    enctoken.len = encopaque->len;
    ret = decrypt_in_key(service_key, RXGK_SERVER_ENC_TOKEN, &enctoken, out);
    if (ret != 0)
	goto cleanup;

cleanup:
    release_key(&service_key);
    return ret;
}

static int
unpack_token(RXGK_Token *token, RXGK_Data *in)
{
    XDR xdrs;

    memset(&xdrs, 0, sizeof(xdrs));

    xdrmem_create(&xdrs, in->val, in->len, XDR_DECODE);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	xdr_destroy(&xdrs);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdrs);
    return 0;
}

static int
process_token(RXGK_Data *tc, struct rxgk_sprivate *sp, struct rxgk_sconn *sc)
{
    RXGK_TokenContainer container;
    RXGK_Token token;
    RXGK_Data packed_token;
    int ret;

    memset(&container, 0, sizeof(container));
    memset(&token, 0, sizeof(token));
    zero_rxgkdata(&packed_token);

    ret = unpack_container(&container, tc);
    if (ret != 0)
	goto cleanup;
    ret = decrypt_token(&packed_token, &container.encrypted_token,
			container.kvno, container.enctype, sp);
    if (ret != 0)
	goto cleanup;
    ret = unpack_token(&token, &packed_token);
    if (ret != 0)
	goto cleanup;

    /* Stash the token master key in the per-connection data. */
    if (sc->k0 != NULL)
	release_key(&sc->k0);
    ret = make_key(&sc->k0, token.K0.val, token.K0.len, token.enctype);
    sc->level = token.level;
    sc->expiration = token.expirationtime;
    
cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_TokenContainer, &container);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packed_token);
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
    RXGK_Data encauth, packauth;
    rxgk_key tk;
    afs_uint32 lkvno, kvno;
    afs_int16 wkvno;
    int ret;

    memset(&xdrs, 0, sizeof(xdrs));
    zero_rxgkdata(&packauth);
    tk = NULL;
    kvno = 0;

    encauth.len = in->len;
    encauth.val = in->val;
    wkvno = ntohs(rx_GetPacketCksum(apacket));
    lkvno = sc->key_number;
    ret = rxgk_key_number(wkvno, lkvno, &kvno);
    if (ret != 0)
	return ret;
    ret = derive_tk(&tk, sc->k0, rx_GetConnectionEpoch(aconn),
		    rx_GetConnectionId(aconn), sc->start_time, kvno);
    if (ret != 0)
	return ret;
    ret = decrypt_in_key(tk, RXGK_CLIENT_ENC_RESPONSE, &encauth, &packauth);
    if (ret != 0) {
	release_key(&tk);
	return ret;
    }
    if (kvno > lkvno)
	rxgk_update_kvno(aconn, kvno);

    xdrmem_create(&xdrs, packauth.val, packauth.len, XDR_DECODE);
    if (!xdr_RXGK_Authenticator(&xdrs, out)) {
	ret = RXGEN_SS_UNMARSHAL;
	goto cleanup;
    }
    ret = 0;
cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packauth);
    release_key(&tk);
    xdr_destroy(&xdrs);
    return ret;
}

static int
check_authenticator(RXGK_Authenticator *authenticator,
		    struct rx_connection *aconn, struct rxgk_sconn *sc)
{
    if (memcmp(authenticator->nonce, sc->challenge, 20) != 0)
	return RXGK_SEALED_INCON;
    if (authenticator->level != sc->level)
	return RXGK_BADLEVEL;
    if (authenticator->epoch != (afs_uint32)rx_GetConnectionEpoch(aconn) ||
	authenticator->cid != (afs_uint32)rx_GetConnectionId(aconn) ||
	authenticator->call_numbers.len != RX_MAXCALLS)
	return RXGK_BADCHALLENGE;
    return 0;
}

/* Process the response packet to a challenge */
int
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

    xdrmem_create(&xdrs, rx_DataOf(apacket), rx_GetDataSize(apacket),
		  XDR_DECODE);
    if (!xdr_RXGK_Response(&xdrs, &response)) {
	ret = RXGEN_SS_UNMARSHAL;
	goto cleanup;
    }

    /* Set local field from the response.  Yes, this is untrusted. */
    sc->start_time = response.start_time;

    /* We have a start_time, a token, and an encrypted authenticator. */
    ret = process_token(&response.token, sp, sc);
    if (ret != 0)
	goto cleanup;

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
