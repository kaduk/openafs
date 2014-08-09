/* src/rxgk/rxgk_private.h - Declarations of RXGK-internal routines */
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
 * Prototypes for routines internal to RXGK.
 */

#ifndef RXGK_PRIVATE_H
#define RXGK_PRIVATE_H

/* RX-internal headers we depend on. */
#include <rx/rx_identity.h>

/** Statistics about a connection.  Bytes and packets sent/received. */
struct rxgkStats {
    afs_uint32 brecv;
    afs_uint32 bsent;
    afs_uint32 precv;
    afs_uint32 psent;
};

/* The packet pseudoheader used for auth and crypt connections. */
struct rxgk_header {
    afs_uint32 epoch;
    afs_uint32 cid;
    afs_uint32 callNumber;
    afs_uint32 seq;
    afs_uint32 index;
    afs_uint32 length;
} __attribute__((packed));

/*
 * rgxk_server.c
 */

/**
 * Security Object private data for the server.
 *
 * Per-connection flags, and a way to get a decryption key for what the client
 * sends us.
 */
struct rxgk_sprivate {
    afs_int32 flags;
    void *rock;
    rxgk_getkey_func getkey;
};
/**
 * Service-specific data needed for SRXGK_GSSNegotiate
 *
 * We need to put the getkey function into a service-specific data,
 * so that SRXGK_GSSNegotiate can get at the token-encrypting key when
 * producing tokens.
 */
struct rxgk_getkey_sspecific_data {
    rxgk_getkey_func getkey;
    void *rock;
};
/**
 * Per-connection security data for the server.
 *
 * Security level, authentication state, expiration, the current challenge
 * nonce, status, the connection start time and current key derivation key
 * number.  Cache both the user identity and callback identity presented
 * in the token, for later use.
 */
struct rxgk_sconn {
    RXGK_Level level;
    unsigned char tried_auth;
    unsigned char auth;
    rxgkTime expiration;
    unsigned char challenge[20];
    struct rxgkStats stats;
    rxgkTime start_time;
    struct rx_identity *client;
    afs_uint32 key_number;
    rxgk_key k0;
    RXGK_Data cb_tok;
    rxgk_key cb_key;
};

/*
 * rxgk_client.c
 */

/**
 * Security Object private data for client.
 *
 * The session key ("token master key"), plust the enctype of the
 * token and the token itself.
 * UUIDs for both the client (cache manager) and target server.  This is
 * doable because the token is either a db server (the target has no UUID)
 * or tied to a particular file server (which does have a UUID).
 */
struct rxgk_cprivate {
    afs_int32 flags;
    rxgk_key k0;
    afs_int32 enctype;
    RXGK_Level level;
    RXGK_Data token;
    afsUUID *client_uuid;
    afsUUID *target_uuid;
};
/**
 * Per-connection security data for client.
 *
 * The start time of the connection and connection key number are used
 * for key derivation, information about the callback key to be presented in
 * the authenticator for the connection, and the requisite connection
 * statistics.
 */
struct rxgk_cconn {
    rxgkTime start_time;
    afs_uint32 key_number;
    RXGK_Data cb_tok;
    RXGK_Data cb_k0;
    afs_int32 cb_enctype;
    struct rxgkStats stats;
};

/* rxgk_crypto_XXX.c */
ssize_t etype_to_len(int etype);

/* rxgk_util.c */
void rxgk_populate_header(struct rxgk_header *header, struct rx_packet *apacket,
			  afs_int32 index, afs_uint32 length);
afs_int32 rxgk_security_overhead(struct rx_connection *aconn, RXGK_Level level,
				 rxgk_key k0);
afs_int32 rxgk_key_number(afs_uint16 wire, afs_uint32 local, afs_uint32 *real);
void rxgk_update_kvno(struct rx_connection *aconn, afs_uint32 kvno);
#ifndef KERNEL
afs_int32 rxgk_service_get_long_term_key(struct rx_call *acall, rxgk_key *key,
					 afs_int32 *kvno, afs_int32 *enctype);
#endif

#endif /* RXGK_PRIVATE_H */
