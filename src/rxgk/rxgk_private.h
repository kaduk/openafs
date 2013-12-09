/* rxgk_prototypes.h - Declarations of RXGK-internal routines */
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
 * Prototypes for routines internal to RXGK.
 */

#ifndef RXGK_PROTOTYPES_H
#define RXGK_PROTOTYPES_H

/* RX-internal headers we depend on. */
#include <rx/rx_identity.h>

/* Statistics about a connection.  Bytes and packets sent/received. */
struct rxgkStats {
    afs_uint32 brecv;
    afs_uint32 bsent;
    afs_uint32 precv;
    afs_uint32 psent;
};

/*
 * rgxk_server.c
 */

/*
 * Security Object private data for the server.
 * Per-connection flags, and a way to get a decryption key for what the client
 * sends us.
 */
struct rxgk_sprivate {
    afs_int32 flags;
    void *rock;
    rxgk_getkey_func getkey;
};
/*
 * We also need to put the getkey function into a service-specific data,
 * so that SRXGK_GSSNegotiate can get at the token-encrypting key when
 * producing tokens.
 */
struct rxgk_getkey_sspecific_data {
    rxgk_getkey_func getkey;
    void *rock;
};
/*
 * Per-connection security data for the server.
 * Security level, authentication state, expiration, the current challenge
 * nonce, status, the connection start time and current key derivation key
 * number.
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
};

/*
 * rxgk_client.c
 */

/*
 * Security Object private data for client.
 * The session key ("token master key"), plust the enctype of the
 * token and the token itself.
 */
struct rxgk_cprivate {
    afs_int32 flags;
    rxgk_key k0;
    afs_int32 enctype;
    RXGK_Level level;
    RXGK_Data token;
    afsUUID *uuid;
};
/*
 * Per-connection security data for client.
 * The start time of the connection and connection key number are used
 * for key derivation, and the requisite connection statistics.
 */
struct rxgk_cconn {
    rxgkTime start_time;
    afs_uint32 key_number;
    struct rxgkStats stats;
};

#ifndef KERNEL
/* rxgk_gss.c */
afs_int32 SGSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
			RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
			RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
			u_int *gss_major_status, u_int *gss_minor_status,
			RXGK_Data *rxgk_info);
#endif

#endif /* RXGK_PROTOTYPES_H */
