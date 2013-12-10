/* rxgk/rxgk_util.c - utility functions for RXGK use */
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
#include <errno.h>

#include "rxgk_private.h"

/*
 * Fill in the elements of the rxgk_header structure, in network byte order,
 * using information from the packet structure and the supplied values for
 * the security index and data length.
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

/*
 * Set the security header and trailer sizes on aconn to be consistent
 * with the space needed for packet handling at the given security level
 * using the given key (only its enctype/checksum type are relevant).
 */
afs_int32
rxgk_security_overhead(struct rx_connection *aconn, RXGK_Level level,
		       rxgk_key k0)
{
    afs_int32 ret;
    size_t mlen;
    int elen;

    switch(level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_mic_length(k0, &mlen);
	    if (ret != 0)
		goto cleanup;
	    rx_SetSecurityHeaderSize(aconn, (int)mlen);
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
	    return -1;
    }
cleanup:
    return ret;
}

/*
 * Given the wire kvno and the local state, return the actual kvno which
 * should be used for key derivation.  All values are in host byte order.
 * Return an error if the two input values are inconsistent, 0 otherwise.
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

/*
 * Update the key version number on a connection.
 * Also reset the per-connection statistics.
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
