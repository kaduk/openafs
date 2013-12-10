/* rxgk/rxgk_util.c - utility functions for RXGK use */
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

/**
 * @file
 * Utility functions for RXGK use.  Populate an rxgk_header struct,
 * compute the security overhead for a connection at a given security level,
 * and helpers for maintaining key version numbers for connections.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <rx/rx.h>
#include <rx/rx_identity.h>
#include <rx/rxgk.h>
#include <rx/rx_packet.h>
#include <afs/rfc3961.h>
#ifdef KERNEL
# include "afs/sysincludes.h"
# include "afsincludes.h"
#else
# include <errno.h>
#endif

#include "rxgk_private.h"

/**
 * Fill in an rxgk_header structure from a packet
 *
 * Fill in the elements of the rxgk_header structure, in network byte order,
 * using information from the packet structure and the supplied values for
 * the security index and data length.
 *
 * @param[out] header	The header structure to be populated.
 * @param[in] apacket	The packet from which to pull connection information.
 * @param[in] index	The security index of the connection.
 * @param[in] length	The (plaintext) data length of the packet.
 */
void
rxgk_populate_header(struct rxgk_header *header, struct rx_packet *apacket,
		     afs_int32 index, afs_uint32 length)
{
    header->epoch = htonl(apacket->header.epoch);
    header->cid = htonl(apacket->header.cid);
    header->callNumber = htonl(apacket->header.callNumber);
    header->seq = htonl(apacket->header.seq);
    header->index = htonl(index);
    header->length = htonl(length);
}

/**
 * Set the security header and trailer sizes on a connection
 *
 * Set the security header and trailer sizes on aconn to be consistent
 * with the space needed for packet handling at the given security level
 * using the given key (only its enctype/checksum type are relevant).
 *
 * @param[out] aconn	The connection being modified.
 * @param[in] level	The security level of the connection.
 * @param[in] k0	The master key for the connection.
 * @return rxgk error codes.
 */
afs_int32
rxgk_security_overhead(struct rx_connection *aconn, RXGK_Level level,
		       rxgk_key k0)
{
    afs_int32 ret;
    size_t mlen;
    afs_uint32 elen;

    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_mic_length(k0, &mlen);
	    if (ret != 0)
		goto cleanup;
	    rx_SetSecurityHeaderSize(aconn, mlen);
	    /* No padding needed since MIC is not done in-place. */
	    rx_SetSecurityMaxTrailerSize(aconn, 0);
	    return 0;
	case RXGK_LEVEL_CRYPT:
	    ret = rxgk_cipher_expansion(k0, &elen);
	    if (ret != 0)
		goto cleanup;
	    rx_SetSecurityHeaderSize(aconn, sizeof(struct rxgk_header));
	    rx_SetSecurityMaxTrailerSize(aconn, elen);
	    return 0;
	default:
	    return RXGK_INCONSISTENCY;
    }
cleanup:
    return ret;
}

/**
 * Compute the full 32-bit kvno of a connection
 *
 * Given the 16-bit wire kvno and the local state, return the actual kvno which
 * should be used for key derivation.  All values are in host byte order.
 *
 * @param[in] wire	The 16-bit kvno from the received packet.
 * @param[in] local	The 32-bit kvno from the local connection state.
 * @param[out] real	The kvno to be used to process this packet.
 * @return rxgk error codes.
 */
afs_int32
rxgk_key_number(afs_uint16 wire, afs_uint32 local, afs_uint32 *real)
{
    afs_uint16 lres, diff;

    lres = local % (1u << 16);
    diff = (afs_uint16)(wire - lres);

    if (diff == 0) {
	*real = local;
    } else if (diff == 1) {
	if (local == MAX_AFS_UINT32)
	    return RXGK_INCONSISTENCY;
	*real = local + 1;
    } else if (diff == (afs_uint16)0xffffu) {
	if (local == 0)
	    return RXGK_INCONSISTENCY;
	*real = local - 1;
    } else {
	return RXGK_BADKEYNO;
    }
    return 0;
}

/**
 * Update the key version number on a connection.
 *
 * Also reset the per-connection statistics.
 *
 * @param[out] aconn	The connection to be modified.
 * @param[in] kvno	The local key version number to set.
 */
void
rxgk_update_kvno(struct rx_connection *aconn, afs_uint32 kvno)
{
    struct rxgk_sconn *sc;
    struct rxgk_cconn *cc;
    void *data;

    data = rx_GetSecurityData(aconn);
    if (rx_IsServerConn(aconn)) {
	sc = data;
	sc->key_number = kvno;
    } else {
	cc = data;
	cc->key_number = kvno;
    }
}

#ifndef KERNEL
/**
 * Store an rxgk getkey function and rock into service-specific data
 *
 * Set the service-specific data on this service to hold the getkey
 * function and its rock.  The getkey function must be available so
 * that the token negotiation service can encrypt tokens in the
 * long-term key.
 *
 * @param[out] svc		The rx service to which getkey will be attached.
 * @param[in] getkey		The rxgk getkey function to use.
 * @param[in] getkey_rock	Data to pass to getkey.
 * @return 0 on success, or ENOMEM on failure.
 */
afs_int32
rxgk_set_getkey_specific(struct rx_service *svc, rxgk_getkey_func getkey,
			 void *getkey_rock)
{
    struct rxgk_getkey_sspecific_data *gk;

    gk = rxi_Alloc(sizeof(*gk));
    if (gk == NULL)
	return ENOMEM;
    gk->getkey = getkey;
    gk->rock = getkey_rock;
    rx_SetServiceSpecific(svc, RXGK_NEG_SSPECIFIC_GETKEY, gk);
    return 0;
}

/**
 * Obtain a token-encrypting key for a token to be produced for this call
 *
 * Grab the getkey service-specific data for this connection, and use
 * its getkey function to get a key with which to encrypt a token.
 * In principle, we could have hooks to allow the idea of an "active kvno",
 * so that a higher kvno than is used could be present in the database
 * to allow transparent rekeying when keys must be distributed amongst
 * multiple hosts.
 * For now, though, just use the highest kvno.
 *
 * @param[in] acall	The call from which to obtain service-specific data.
 * @param[out] key	The token-encrypting key.
 * @param[out] kvno	The kvno of key.
 * @param[out] enctype	The RFC 3961 enctype of key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_service_get_long_term_key(struct rx_call *acall, rxgk_key *key,
                               afs_int32 *kvno, afs_int32 *enctype)
{
    struct rx_connection *conn;
    struct rx_service *svc;
    struct rxgk_getkey_sspecific_data *gk;

    conn = rx_ConnectionOf(acall);
    svc = rx_ServiceOf(conn);
    gk = rx_GetServiceSpecific(svc, RXGK_NEG_SSPECIFIC_GETKEY);

    if (gk == NULL || gk->getkey == NULL)
	return RXGK_INCONSISTENCY;
    return (*gk->getkey)(gk->rock, kvno, enctype, key);
}
#endif	/* KERNEL */
