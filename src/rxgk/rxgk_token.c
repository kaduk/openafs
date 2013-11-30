/* rxgk/rxgk_token.c - Token generation/manuipluation routines for RXGK */
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
 * Routines to generate, encode, and encrypt rxgk tokens.
 */

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <errno.h>

#include <rx/rxgk.h>

#include "rxgk_private.h"

/*
 * Copy the fields from a TokenInfo to a Token.
 * Token is not a complete superset of TokenInfo; errorcode is ignored.
 */
static void
tokeninfo_to_token(RXGK_Token *token, RXGK_TokenInfo *info)
{

    token->enctype = info->enctype;
    token->level = info->level;
    token->lifetime = info->lifetime;
    token->bytelife = info->bytelife;
    token->expirationtime = info->expiration;
    return;
}

/*
 * Take the input RXGK_Token and XDR-encode it, returning the result in
 * packed_token.  The caller is responsible for freeing the memory contained
 * in packed_token.
 *
 * Returns RX errors.
 */
static afs_int32
pack_token(RXGK_Token *token, RXGK_Data *packed_token)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	dprintf(2, "xdrlen for Token says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    packed_token->val = xdr_alloc(len);
    if (packed_token->val == NULL) {
	dprintf(2, "Couldn't allocate for encoding Token\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    packed_token->len = len;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, packed_token->val, len, XDR_ENCODE);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	dprintf(2, "xdrmem for Token says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    ret = 0;

out:
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Take the input TokenContainer and XDR-encode it, returning the result
 * in 'out'.  The caller is responsible for freeing the memory contained
 * in 'out'.
 *
 * Returns RX errors.
 */
static afs_int32
pack_container(RXGK_TokenContainer *container, RXGK_Data *out)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	dprintf(2, "xdrlen for TokenContainer says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    out->val = xdr_alloc(len);
    if (out->val == NULL) {
	dprintf(2, "Couldn't allocate for encoding TokenContainer\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    out->len = len;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, out->val, len, XDR_ENCODE);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	dprintf(2, "xdrmem for TokenContainer says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    ret = 0;

out:
    xdr_destroy(&xdrs);
    return ret;
}

/*
 * Take the input token, encode it, encrypt that blob, populate a
 * TokenContainer with the encrypted token, kvno, and enctype, and encode
 * the resulting TokenContainer into 'out'.
 *
 * Returns RX errors.
 */
static afs_int32
pack_wrap_token(rxgk_key server_key, afs_int32 kvno, afs_int32 enctype,
		RXGK_Token *token, RXGK_Data *out)
{
    RXGK_Data packed_token, encrypted_token;
    RXGK_TokenContainer container;
    afs_int32 ret;

    zero_rxgkdata(&packed_token);
    zero_rxgkdata(&encrypted_token);
    zero_rxgkdata(out);
    container.encrypted_token.len = 0;
    container.encrypted_token.val = NULL;

    /* XDR-encode the token in to packed_token. */
    ret = pack_token(token, &packed_token);
    if (ret != 0)
	goto out;

    ret = encrypt_in_key(server_key, RXGK_SERVER_ENC_TOKEN, &packed_token,
			 &encrypted_token);
    if (ret != 0)
	goto out;
    ret = rx_opaque_populate(&container.encrypted_token, encrypted_token.val,
			     encrypted_token.len);
    if (ret != 0)
	goto out;
    container.kvno = kvno;
    container.enctype = enctype;

    /* Now the token container is populated; time to encode it into 'out'. */
    ret = pack_container(&container, out);
    if (ret != 0)
	goto out;

out:
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packed_token);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &encrypted_token);
    xdr_free((xdrproc_t)xdr_RXGK_TokenContainer, &container);
    return ret;
}

/*
 * Create a token from the specified TokenInfo, key, start time, and list
 * of identities.  Encrypts the token and stores it as an rx_opaque.
 * Returns RX errors.
 */
afs_int32
make_token(struct rx_opaque *out, RXGK_TokenInfo *info, gss_buffer_t k0,
	   rxgkTime start, PrAuthName *identities, int nids, rxgk_key key,
	   afs_int32 kvno, afs_int32 enctype)
{
    RXGK_Token token;
    afs_int32 ret;

    memset(&token, 0, sizeof(token));

    /* Get the tokeninfo values from the authoritative source. */
    tokeninfo_to_token(&token, info);

    /* Create the rest of the token. */
    token.starttime = start;
    token.K0.val = xdr_alloc(k0->length);
    if (token.K0.val == NULL)
	return RXGEN_SS_MARSHAL;
    memcpy(token.K0.val, k0->value, k0->length);
    token.K0.len = k0->length;
    token.identities.len = nids;
    token.identities.val = identities;
    ret = pack_wrap_token(key, kvno, enctype, &token, out);
    xdr_free((xdrproc_t)xdr_RXGK_Token, &token);
    return ret;
}

/*
 * Print a token (with empty identity list) where the master key (k0)
 * already exists, and encrypt it in the specified key/kvno/enctype.
 */
#define DEFAULT_LIFETIME	(60 * 60 * 10)
#define DEFAULT_BYTELIFE	(1024 * 1024 * 1024)
#define RXGK_NEVERDATE		0x7fffffffffffffffll
afs_int32
print_token(struct rx_opaque *out, gss_buffer_t k0, rxgk_key key,
	    afs_int32 kvno, afs_int32 enctype)
{
    RXGK_TokenInfo info;
    rxgkTime start;

    memset(&info, 0, sizeof(info));
    start = RXGK_NOW();

    info.enctype = enctype;
    info.level = RXGK_LEVEL_CRYPT;
    info.lifetime = DEFAULT_LIFETIME;
    info.bytelife = DEFAULT_BYTELIFE;
    info.expiration = RXGK_NEVERDATE;

    start = RXGK_NOW();
    return make_token(out, &info, k0, start, NULL, 0, key, kvno, enctype);
}

/*
 * Print a token (with empty identity list) with a random master key,
 * and encrypt it in the specified key/kvno/enctype.  Return the master
 * key as well as the token, so that the token is usable.  The random key
 * is chosen of the same enctype as the token-encrypting key.
 * The caller must free k0 with release_key().
 */
afs_int32
print_token_and_key(struct rx_opaque *out, rxgk_key key, afs_int32 kvno,
		    afs_int32 enctype, rxgk_key *k0_out)
{
    rxgk_key k0;
    afs_int32 ret;

    *k0_out = NULL;
    ret = random_key(enctype, &k0);
    if (ret != 0)
	return ret;
    ret = print_token(out, k0, key, kvno, enctype);
    if (ret != 0) {
	release_key(&k0);
	return ret;
    }
    *k0_out = k0;
    return 0;
}
