/* rxgk/rxgk_common.c - Security object routines common to client and server */
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
 * Security object routines common to client and server
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

/* OS-specific system headers go here */

#include <rx/rx.h>
#include <rx/rx_packet.h>
#include <rx/xdr.h>
#include <gssapi/gssapi.h>
#include <rx/rxgk.h>

#include "rxgk_private.h"

/* Helper functions. */
static int
release_object(struct rx_securityClass *secobj)
{
    union rxgk_private *priv;
    struct rxgk_sprivate *sp;
    struct rxgk_cprivate *cp;

    if (secobj->refCount > 0) {
	/* still in use; shouldn't happen. */
	return 0;
    }
    priv = secobj->privateData;
    free(secobj);
    if (priv->type == RXGK_SERVER) {
	sp = &priv->s;
	free(sp);
    } else if (priv->type == RXGK_CLIENT) {
	cp = &priv->c;
	/* XXX free k0 but it is not a copy yet */
	free(cp);
    }

    return 0;
}

/* Discard the security object, freeing resources */
int
rxgk_Close(struct rx_securityClass *aobj)
{
    /* XXXBJK */
    return 0;
}

/* Create a new connection */
int
rxgk_NewConnection(struct rx_securityClass *aobj,
		   struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;
    struct rxgk_cconn *cc;

    /* Take a reference before we do anything else. */
    aobj->refCount++;
    if (rx_GetSecurityData(aconn) != NULL)
	goto error;

    if (rx_IsServerConn(aconn)) {
	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
	    goto error;
	rx_SetSecurityData(aconn, sc);
    } else {
	/* It's a client. */
	cc = calloc(1, sizeof(*cc));
	if (cc == NULL)
	    goto error;
	cc->start_time = RXGK_NOW();
	/* XXX need epoch (once) and connection ID (always) */
	rx_SetSecurityData(aconn, cc);
    }
    return 0;
error:
    aobj->refCount--;
    return RXGK_INCONSISTENCY;
}

/* Destroy a connection, freeing resources */
int
rxgk_DestroyConnection(struct rx_securityClass *aobj,
		       struct rx_connection *aconn)
{
    struct rxgk_sconn *sc;
    struct rxgk_cconn *cc;
    void *data;

    data = rx_GetSecurityData(aconn);
    rx_SetSecurityData(aconn, NULL);

    if (rx_IsServerConn(aconn)) {
	sc = data;
	release_key(&sc->k0);
	free(sc);
    } else {
	/* It's a client. */
	cc = data;
	free(cc);
    }
    aobj->refCount--;
    if (aobj->refCount <= 0) {
	return release_object(aobj);
    }
    return 0;
}

static_inline afs_int32
pick_recv_keyusage(int isserver, RXGK_Level level)
{
    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    return isserver ? RXGK_CLIENT_MIC_PACKET : RXGK_SERVER_MIC_PACKET;
	case RXGK_LEVEL_CRYPT:
	    return isserver ? RXGK_CLIENT_ENC_PACKET : RXGK_SERVER_ENC_PACKET;
	default:
	    return -1;
    }
}

/* Decode a packet from the wire format */
int
rxgk_CheckPacket(struct rx_securityClass *aobj, struct rx_call *acall,
		 struct rx_packet *apacket)
{
    /* XXXBJK */
    return 0;
}

/*
 * Take a packet, prefix it with the rxgk pseudoheader, MIC the whole
 * thing with specified key and key usage, then rewrite the packet payload
 * to be the MIC followed by the original payload.
 */
static int
mic_packet(rxgk_key tk, afs_int32 keyusage, struct rx_connection *aconn,
	   struct rx_packet *apacket)
{
    RXGK_Data plain, mic;
    struct rxgk_header *header;
    afs_int32 len, miclen;

    len = rx_GetDataSize(apacket);
    miclen = rx_GetSecurityHeaderSize(aconn);
    plain.val = xdr_alloc(sizeof(*header) + len);
    plain.len = sizeof(*header) + len;
    header = plain.val;
    rxgk_populate_header(header, apacket, rx_SecurityClassOf(aconn), len);
    rx_packetread(apacket, miclen, len, plain.val + sizeof(*header));

    /* The actual mic */
    mic_in_key(tk, keyusage, &plain, &mic);

    if (mic.len != miclen)
	return RXGK_INCONSISTENCY;

    /* Now, put the data back. */
    rx_packetwrite(apacket, 0, mic.len, mic.val);
    rx_SetDataSize(apacket, mic.len + len);

    return 0;
}

/*
 * Take a packet, prefix it with the rxgk pseudoheader, encrypt the whole
 * thing with specified key and key usage, then rewrite the packet payload
 * to be the encrypted version.
 */
static int
enc_packet(rxgk_key tk, afs_int32 keyusage, struct rx_connection *aconn,
	   struct rx_packet *apacket)
{
    RXGK_Data plain, crypt;
    struct rxgk_header *header;
    afs_int32 ret, len;

    len = rx_GetDataSize(apacket);
    plain.val = xdr_alloc(sizeof(*header) + len);
    plain.len = sizeof(*header) + len;
    header = plain.val;
    rx_packetread(apacket, 0, len + sizeof(*header), plain.val);
    /* XXX I don't see how securityIndex is actually what is meant */
    rxgk_populate_header(header, apacket, rx_SecurityClassOf(aconn), len);

    /* The actual encryption */
    ret = encrypt_in_key(tk, keyusage, &plain, &crypt);

    /* Now, put the data back. */
    rxi_RoundUpPacket(apacket, crypt.len - plain.len);
    rx_packetwrite(apacket, 0, crypt.len, crypt.val);
    rx_SetDataSize(apacket, crypt.len);

    return 0;
}

static_inline afs_int32
pick_send_keyusage(int isserver, RXGK_Level level)
{
    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    return isserver ? RXGK_SERVER_MIC_PACKET : RXGK_CLIENT_MIC_PACKET;
	case RXGK_LEVEL_CRYPT:
	    return isserver ? RXGK_SERVER_ENC_PACKET : RXGK_CLIENT_ENC_PACKET;
	default:
	    return -1;
    }
}

/* Encode a packet to go on the wire */
int
rxgk_PreparePacket(struct rx_securityClass *aobj, struct rx_call *acall,
		   struct rx_packet *apacket)
{
    struct rxgk_sconn *sc;
    struct rxgk_cconn *cc;
    union rxgk_private *priv;
    struct rxgk_cprivate *cp;
    struct rx_securityClass *secobj;
    struct rx_connection *aconn;
    void *data;
    RXGK_Level level;
    rxgk_key k0, tk;
    rxgkTime start_time;
    afs_int32 keyusage;
    int isserver, ret;

    aconn = rx_ConnectionOf(acall);
    data = rx_GetSecurityData(aconn);
    secobj = rx_SecurityObjectOf(aconn);
    priv = secobj->privateData;

    if (rx_IsServerConn(aconn)) {
	sc = data;
	level = sc->level;
	isserver = 1;
	k0 = sc->k0;
	start_time = sc->start_time;
    } else {
	cc = data;
	cp = &priv->c;
	level = cp->level;
	isserver = 0;
	k0 = cp->k0;
	start_time = cc->start_time;
    }
    /* XXX hardcodes key number zero */
    ret = derive_tk(&tk, k0, rx_GetConnectionEpoch(aconn),
		    rx_GetConnectionId(aconn), start_time, 0);
    keyusage = pick_send_keyusage(isserver, level);
    if (keyusage == -1)
	return RXGK_INCONSISTENCY;

    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = mic_packet(tk, keyusage, aconn, apacket);
	    break;
	case RXGK_LEVEL_CRYPT:
	    ret = enc_packet(tk, keyusage, aconn, apacket);
	    break;
	default:
	    return RXGK_INCONSISTENCY;
    }

    return ret;
}

/* Retrieve statistics about this connection */
int
rxgk_GetStats(struct rx_securityClass *aobj, struct rx_connection *aconn,
	      struct rx_securityObjectStats *astats)
{
    /* XXXBJK */
    return 0;
}
