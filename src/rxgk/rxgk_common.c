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
	free(cp->uuid);
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
    union rxgk_private *p;
    struct rxgk_cprivate *cp;

    /* Take a reference before we do anything else. */
    aobj->refCount++;
    if (rx_GetSecurityData(aconn) != NULL)
	goto error;
    p = aobj->privateData;

    if (rx_IsServerConn(aconn)) {
	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
	    goto error;
	rx_SetSecurityData(aconn, sc);
    } else {
	/* It's a client. */
	cp = &p->c;
	cc = calloc(1, sizeof(*cc));
	if (cc == NULL)
	    goto error;
	cc->start_time = RXGK_NOW();
	/* XXX need epoch (once) and connection ID (always) */
	rx_SetSecurityData(aconn, cc);
	/* Set the header and trailer size to be reserved for the security
         * class in each packet. */
	rxgk_security_overhead(aconn, cp->level, cp->k0);
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

/*
 * Take a packet, extract the MIC and data payload, prefix the data with the
 * rxgk pseudoheader, and verify the mic of that assembly.  Strip the
 * MIC from the packet so just the plaintext data remains.
 */
static int
check_mic_packet(rxgk_key tk, afs_int32 keyusage, struct rx_connection *aconn,
	   struct rx_packet *apacket)
{
    RXGK_Data plain, mic;
    struct rxgk_header *header;
    afs_int32 ret, len;
    size_t miclen;

    ret = mic_length(tk, &miclen);
    len = rx_GetDataSize(apacket) - miclen;
    plain.val = xdr_alloc(sizeof(*header) + len);
    plain.len = sizeof(*header) + len;
    header = plain.val;
    mic.val = xdr_alloc(miclen);
    mic.len = miclen;
    rxgk_populate_header(header, apacket, rx_SecurityClassOf(aconn), len);
    rx_packetread(apacket, 0, miclen, mic.val);
    rx_packetread(apacket, miclen, len, plain.val + sizeof(*header));

    /* The actual crypto call */
    ret = check_mic_in_key(tk, keyusage, &plain, &mic);

    /* Data remains untouched in-place. */

    return ret;
}

/*
 * Take an encrypted packet and decrypt it with the specified key and
 * key usage.  Put the plaintext back in the packet.
 */
static int
decrypt_packet(rxgk_key tk, afs_int32 keyusage, struct rx_connection *aconn,
	       struct rx_packet *apacket)
{
    RXGK_Data plain, crypt;
    struct rxgk_header *header, *cryptheader;
    afs_int32 ret, len;

    ret = 0;
    len = rx_GetDataSize(apacket);
    header = malloc(sizeof(*header));
    crypt.val = xdr_alloc(len);
    crypt.len = len;
    /* XXX I don't see how securityIndex is actually what is meant */
    rxgk_populate_header(header, apacket, rx_SecurityClassOf(aconn), len);
    rx_packetread(apacket, 0, len, crypt.val);

    /* The actual encryption */
    ret = decrypt_in_key(tk, keyusage, &crypt, &plain);
    cryptheader = plain.val;

    /* Verify the encrypted header */
    header->length = cryptheader->length;
    ret = memcmp(header, cryptheader, sizeof(*header));
    if (ret != 0)
	ret = RXGK_SEALED_INCON;

    /* Now, put the data back. */
    len = ntohl(cryptheader->length) + sizeof(*header);
    rx_packetwrite(apacket, 0, len, plain.val);
    /* rx_SetDataSize(apacket, len); */

    return ret;
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
    afs_uint32 lkvno, kvno;
    afs_uint16 wkvno;
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
	lkvno = sc->key_number;
    } else {
	cc = data;
	cp = &priv->c;
	level = cp->level;
	isserver = 0;
	k0 = cp->k0;
	start_time = cc->start_time;
	lkvno = cc->key_number;
    }
    wkvno = ntohs(rx_GetPacketCksum(apacket));
    ret = rxgk_key_number(wkvno, lkvno, &kvno);
    if (ret != 0)
	return ret;
    ret = derive_tk(&tk, k0, rx_GetConnectionEpoch(aconn),
		    rx_GetConnectionId(aconn), start_time, kvno);
    keyusage = pick_recv_keyusage(isserver, level);
    if (keyusage == -1)
	return RXGK_INCONSISTENCY;

    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    ret = 0;
	    break;
	case RXGK_LEVEL_AUTH:
	    ret = check_mic_packet(tk, keyusage, aconn, apacket);
	    break;
	case RXGK_LEVEL_CRYPT:
	    ret = decrypt_packet(tk, keyusage, aconn, apacket);
	    break;
	default:
	    return RXGK_INCONSISTENCY;
    }
    if (ret == 0 && kvno > lkvno)
	rxgk_update_kvno(aconn, kvno);

    return ret;
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
    afs_uint32 lkvno;
    afs_uint16 wkvno;
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
	lkvno = sc->key_number;
    } else {
	cc = data;
	cp = &priv->c;
	level = cp->level;
	isserver = 0;
	k0 = cp->k0;
	start_time = cc->start_time;
	lkvno = cc->key_number;
    }
    wkvno = (afs_int16)lkvno;
    rx_SetPacketCksum(apacket, htons(wkvno));
    ret = derive_tk(&tk, k0, rx_GetConnectionEpoch(aconn),
		    rx_GetConnectionId(aconn), start_time, lkvno);
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
    struct rxgkStats *stats;
    struct rxgk_sconn *sc;
    union rxgk_private *p;
    struct rxgk_cprivate *cp;
    struct rxgk_cconn *cc;
    void *data;

    astats->type = 4;	/* rxgk */
    data = rx_GetSecurityData(aconn);
    if (data == NULL) {
	astats->flags |= 1;
	return 0;
    }

    if (rx_IsServerConn(aconn)) {
	sc = data;
	stats = &sc->stats;
	astats->level = sc->level;
	if (sc->auth)
	    astats->flags |= 2;
	/* rxgkTime is 100s of nanoseconds; time here is seconds */
	astats->expires = (afs_uint32)(sc->expiration / 10000000);
    } else {
	cc = data;
	stats = &cc->stats;
	p = rx_GetSecurityData(aconn);
	cp = &p->c;
	astats->level = cp->level;
    }

    astats->packetsReceived = stats->precv;
    astats->packetsSent = stats->psent;
    astats->bytesReceived = stats->brecv;
    astats->bytesSent = stats->bsent;
	
    return 0;
}
