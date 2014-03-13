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

/* RX-internal headers we depend on. */
#include <rx/rx_opaque.h>
#include <rx/rx_identity.h>

/* Get the current timestamp. */
static_inline rxgkTime RXGK_NOW(void)
{
    struct timeval tv;
    osi_GetTime(&tv);
    return (rxgkTime)tv.tv_sec * 10000000 + (rxgkTime)tv.tv_usec * 10;
}

/* rxgk_key is an opaque type to wrap our RFC3961 implementation's concept
 * of a key.  It has (at least) the keyblock and length, kvno, and enctype. */
typedef void * rxgk_key;

typedef afs_int32 (*rxgk_getkey_func)(void *rock, afs_int32 *kvno,
				      afs_int32 *enctype, rxgk_key *key);

/* Indices for the service-specific data we attach to the rxgk service. */
#define RXGK_NEG_SSPECIFIC_GETKEY	0
#define RXGK_NEG_SSPECIFIC_GSS		1

/* rxgk_server.c */
struct rx_securityClass * rxgk_NewServerSecurityObject(void *getkey_rock,
						       rxgk_getkey_func getkey);
afs_int32 rxgk_set_getkey_specific(struct rx_service *svc,
				   rxgk_getkey_func getkey, void *getkey_rock);
afs_int32 rxgk_NewService_SecObj(u_short port, struct rx_service **service_out,
				 char *serviceName,
				 struct rx_securityClass **secObjs,
				 int nsecObjs, rxgk_getkey_func getkey,
				 void *getkey_rock);
afs_int32 rxgk_NewEphemeralService_SecObj(u_short port,
					  struct rx_service **service_out,
					  char *serviceName,
					  struct rx_securityClass **secObjs,
					  int nsecObjs);
afs_int32 rxgk_service_get_long_term_key(struct rx_call *acall, rxgk_key *key,
					 afs_int32 *kvno, afs_int32 *enctype);
afs_int32 rxgk_GetServerInfo(struct rx_connection *conn, RXGK_Level *level,
			     rxgkTime *expiry, struct rx_identity **identity);
/* rxgk_client.c */
struct rx_securityClass *rxgk_NewClientSecurityObject(RXGK_Level level,
						      afs_int32 enctype,
						      rxgk_key k0,
						      RXGK_Data *token,
						      afsUUID *uuid);
struct rx_securityClass *rxgk_NegotiateSecurityObject(RXGK_Level level,
						      afsUUID *uuid,
						      u_short port, char *svc,
						      char *hostname,
						      afs_uint32 addr);

/* rxgk_crypto_XXX.c */
afs_int32 rxgk_make_key(rxgk_key *key_out, void *raw_key, afs_int32 length,
			afs_int32 enctype);
afs_int32 rxgk_copy_key(rxgk_key key_in, rxgk_key *key_out);
afs_int32 rxgk_random_key(afs_int32 enctype, rxgk_key *key_out);
void rxgk_release_key(rxgk_key *key);
afs_int32 rxgk_mic_length(rxgk_key key, size_t *out);
afs_int32 rxgk_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			  struct rx_opaque *out);
afs_int32 rxgk_check_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
				RXGK_Data *mic);
afs_int32 rxgk_encrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			      struct rx_opaque *out);
afs_int32 rxgk_decrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			      struct rx_opaque *out);
afs_int32 rxgk_derive_tk(rxgk_key *tk, rxgk_key k0, afs_uint32 epoch,
			 afs_uint32 cid, rxgkTime start_time,
			 afs_uint32 key_number);
afs_int32 rxgk_cipher_expansion(rxgk_key k0, int *len_out);
afs_int32 rxgk_nonce(struct rx_opaque *nonce, int len);
afs_int32 rxgk_combine_keys(rxgk_key k0, rxgk_key k1, afs_int32 enctype,
			    rxgk_key *kn);
afs_int32 rxgk_combine_keys_data(RXGK_Data *k0_data, afs_int32 e0,
				 RXGK_Data *k1_data, afs_int32 e1,
				 RXGK_Data *kn_data, afs_int32 en);

/* rxgk_token.c */
afs_int32 rxgk_make_token(struct rx_opaque *out, RXGK_TokenInfo *info,
			  struct rx_opaque *k0, rxgkTime start,
			  PrAuthName *identities, int nids, rxgk_key key,
			  afs_int32 kvno, afs_int32 enctype);
afs_int32 rxgk_print_token(struct rx_opaque *out, RXGK_TokenInfo *input_info,
			   struct rx_opaque *k0, rxgk_key key, afs_int32 kvno,
			   afs_int32 enctype);
afs_int32 rxgk_print_token_and_key(struct rx_opaque *out, RXGK_Level level,
				   rxgk_key key, afs_int32 kvno,
				   afs_int32 enctype, rxgk_key *k0_out);
afs_int32 rxgk_extract_token(RXGK_Data *tc, RXGK_Token *out,
                             rxgk_getkey_func getkey, void *rock);

/* rxgk_gss.c */
#ifndef KERNEL
afs_int32 rxgk_get_token(char *sname, char *hostname, afs_uint32 addr,
			 u_short port, RXGK_Level level,
			 RXGK_TokenInfo *return_info, rxgk_key *return_k0,
			 RXGK_Data *return_token);
afs_int32 rxgk_set_gss_specific(struct rx_service *svc, char *svcname,
				char *host, char *keytab);
#endif

#endif /* OPENAFS_RXGK_H */
