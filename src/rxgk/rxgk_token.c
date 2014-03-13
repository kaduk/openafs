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
 * Routines to generate, encode, encrypt, decode, and decrypt rxgk tokens.
 */


#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <rx/rx.h>
#include <rx/xdr.h>
#include <rx/rx_opaque.h>
#include <rx/rxgk.h>
#include <errno.h>

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
pack_token(RXGK_Token *token, struct rx_opaque *packed_token)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(packed_token, 0, sizeof(*packed_token));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	dprintf(2, "xdrlen for Token says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    ret = rx_opaque_alloc(packed_token, len);
    if (ret != 0)
	goto out;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, packed_token->val, len, XDR_ENCODE);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	rx_opaque_freeContents(packed_token);
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
pack_container(RXGK_TokenContainer *container, struct rx_opaque *out)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(out, 0, sizeof(*out));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	dprintf(2, "xdrlen for TokenContainer says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    ret = rx_opaque_alloc(out, len);
    if (ret != 0)
	goto out;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, out->val, len, XDR_ENCODE);
    if (!xdr_RXGK_TokenContainer(&xdrs, container)) {
	rx_opaque_freeContents(out);
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
		RXGK_Token *token, struct rx_opaque *out)
{
    struct rx_opaque packed_token = RX_EMPTY_OPAQUE;
    struct rx_opaque encrypted_token = RX_EMPTY_OPAQUE;
    RXGK_TokenContainer container;
    afs_int32 ret;

    memset(&container.encrypted_token, 0, sizeof(container.encrypted_token));
    memset(out, 0, sizeof(*out));

    /* XDR-encode the token in to packed_token. */
    ret = pack_token(token, &packed_token);
    if (ret != 0)
	goto out;

    ret = rxgk_encrypt_in_key(server_key, RXGK_SERVER_ENC_TOKEN, &packed_token,
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
    rx_opaque_freeContents(&packed_token);
    rx_opaque_freeContents(&encrypted_token);
    rx_opaque_freeContents(&container.encrypted_token);
    return ret;
}

/*
 * Create a token from the specified TokenInfo, key, start time, and list
 * of identities.  Encrypts the token and stores it as an rx_opaque.
 * Returns RX errors.
 */
afs_int32
rxgk_make_token(struct rx_opaque *out, RXGK_TokenInfo *info,
		struct rx_opaque *k0, rxgkTime start, PrAuthName *identities,
		int nids, rxgk_key key, afs_int32 kvno, afs_int32 enctype)
{
    RXGK_Token token;
    afs_int32 ret;

    memset(&token, 0, sizeof(token));

    /* Get the tokeninfo values from the authoritative source. */
    tokeninfo_to_token(&token, info);

    /* Create the rest of the token. */
    token.start_time = start;
    ret = rx_opaque_populate(&token.K0, k0->val, k0->len);
    if (ret != 0)
	return ret;
    if (nids < 0)
	return RXGK_INCONSISTENCY;
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
rxgk_print_token(struct rx_opaque *out, RXGK_TokenInfo *input_info,
		 struct rx_opaque *k0, rxgk_key key, afs_int32 kvno,
		 afs_int32 enctype)
{
    RXGK_TokenInfo info;
    rxgkTime start;

    memset(&info, 0, sizeof(info));
    start = RXGK_NOW();

    info.enctype = input_info->enctype;
    info.level = input_info->level;
    info.lifetime = DEFAULT_LIFETIME;
    info.bytelife = DEFAULT_BYTELIFE;
    info.expiration = RXGK_NEVERDATE;

    start = RXGK_NOW();
    return rxgk_make_token(out, &info, k0, start, NULL, 0, key, kvno, enctype);
}

/*
 * Print a token (with empty identity list) with a random master key,
 * and encrypt it in the specified key/kvno/enctype.  Return the master
 * key as well as the token, so that the token is usable.  The random key
 * is chosen of the same enctype as the token-encrypting key.
 * The caller must free k0 with release_key().
 */
afs_int32
rxgk_print_token_and_key(struct rx_opaque *out, RXGK_Level level, rxgk_key key,
			 afs_int32 kvno, afs_int32 enctype, rxgk_key *k0_out)
{
    rxgk_key k0;
    RXGK_TokenInfo info;
    afs_int32 ret;

    memset(&info, 0, sizeof(info));
    *k0_out = NULL;
    ret = rxgk_random_key(enctype, &k0);
    if (ret != 0)
	return ret;
    info.level = level;
    info.enctype = enctype;
    info.lifetime = DEFAULT_LIFETIME;
    info.bytelife = DEFAULT_BYTELIFE;
    info.expiration = RXGK_NEVERDATE;
    ret = rxgk_print_token(out, &info, k0, key, kvno, enctype);
    if (ret != 0) {
	rxgk_release_key(&k0);
	return ret;
    }
    *k0_out = k0;
    return 0;
}

/*
 * Helper functions for rxgk_extract_token.
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
	      afs_int32 enctype, rxgk_getkey_func getkey, void *rock)
{
    rxgk_key service_key;
    struct rx_opaque enctoken = RX_EMPTY_OPAQUE;
    afs_int32 ret;

    service_key = NULL;

    if (kvno <= 0 || enctype <= 0)
	return RXGK_BAD_TOKEN;

    ret = getkey(rock, &kvno, &enctype, &service_key);
    if (ret != 0)
	goto cleanup;
    /* Must alias for type compliance */
    enctoken.val = encopaque->val;
    enctoken.len = encopaque->len;
    ret = rxgk_decrypt_in_key(service_key, RXGK_SERVER_ENC_TOKEN, &enctoken,
			      out);
    if (ret != 0)
	goto cleanup;

cleanup:
    rxgk_release_key(&service_key);
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

/*
 * Given an XDR-encoded RXGK_TokenContainer, extract/decrypt the contents
 * into an RXGK_Token.
 *
 * The caller must free the returned token with xdr_free.
 */
afs_int32
rxgk_extract_token(RXGK_Data *tc, RXGK_Token *out, rxgk_getkey_func getkey,
		   void *rock)
{
    RXGK_TokenContainer container;
    struct rx_opaque packed_token = RX_EMPTY_OPAQUE;
    afs_int32 ret;

    memset(&container, 0, sizeof(container));

    ret = unpack_container(&container, tc);
    if (ret != 0)
	goto cleanup;
    ret = decrypt_token(&packed_token, &container.encrypted_token,
			container.kvno, container.enctype, getkey, rock);
    if (ret != 0)
	goto cleanup;
    ret = unpack_token(out, &packed_token);
    if (ret != 0)
	goto cleanup;

cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_TokenContainer, &container);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packed_token);
    return ret;
}
