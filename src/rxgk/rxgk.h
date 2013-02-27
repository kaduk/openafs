/* rxgk.h - External interfaces for RXGK */
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
 * External interfaces for RXGK.
 */

#ifndef OPENAFS_RXGK_H
#define OPENAFS_RXGK_H

/* Pull in the com_err table */
#include <rx/rxgk_errs.h>

/* Pull in the protocol description */
#include <rx/rxgk_int.h>

/* Interface between the rxgkTime type and other types */
static_inline rxgkTime RXGK_NOW(void)
{
    time_t _a = time(0);
    rxgkTime _b = ((rxgkTime)_a) * 1000 * 10;
    return _b;
}

/* rxgk_util.c */
void zero_rxgkdata(RXGK_Data *data);
afs_int32 copy_rxgkdata(RXGK_Data *out, RXGK_Data *in);
afs_uint32 rxgk_make_k0(afs_uint32 *minor_status, gss_ctx_id_t gss_ctx,
			RXGK_Data *client_nonce, RXGK_Data *server_nonce,
			int enctype, gss_buffer_t key);
afs_int32 rxgk_nonce(RXGK_Data *nonce, int len);
void print_data(void *p, int len);

/* rxgk_crypto.c */
/* rxgk_key is an opaque type to wrap our RFC3961 implementation's concept
 * of a key.  It has (at least) the keyblock and length, kvno, and enctype. */
typedef void * rxgk_key;
afs_int32 dummy_getkey(void *rock, afs_int32 kvno, afs_int32 enctype,
		       rxgk_key *key);
afs_int32 make_key(rxgk_key *key_out, void *raw_key, afs_int32 length,
		   afs_int32 enctype);
afs_int32 get_server_key(rxgk_key *key, afs_int32 *kvno, afs_int32 *enctype);
void release_key(rxgk_key *key);
afs_int32 encrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			 RXGK_Data *out);
afs_int32 decrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			 RXGK_Data *out);
afs_int32 derive_tk(rxgk_key *tk, rxgk_key k0, afs_uint32 epoch,
		    afs_uint32 cid, rxgkTime start_time,
		    afs_uint32 key_number);

/* rxgk_server.c */
typedef afs_int32 (*rxgk_getkey_func)(void *rock, afs_int32 kvno,
				      afs_int32 enctype, rxgk_key *key);
struct rx_securityClass * rxgk_NewServerSecurityObject(void *getkey_rock,
						       rxgk_getkey_func getkey);

/* rxgk_client.c */
struct rx_securityClass *rxgk_NewClientSecurityObject(RXGK_Level level,
						      afs_int32 enctype,
						      rxgk_key k0,
						      RXGK_Data *token);

#endif /* OPENAFS_RXGK_H */
