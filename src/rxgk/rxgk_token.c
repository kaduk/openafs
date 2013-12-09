/* rxgk/rxgk_token.c - Token generation/manuipluation routines for RXGK */
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
pack_token(struct rx_opaque *out, RXGK_Token *token)
{
    XDR xdrs;
    afs_int32 ret;
    u_int len;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(out, 0, sizeof(*out));
    xdrlen_create(&xdrs);
    if (!xdr_RXGK_Token(&xdrs, token)) {
	dprintf(2, "xdrlen for Token says it is invalid\n");
	ret = RXGEN_SS_MARSHAL;
	goto out;
    }
    len = xdr_getpos(&xdrs);

    ret = rx_opaque_alloc(out, len);
    if (ret != 0)
	goto out;

    xdr_destroy(&xdrs);
    xdrmem_create(&xdrs, out->val, len, XDR_ENCODE);
    if (!xdr_RXGK_Token(&xdrs, token)) {
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

    memset(&container, 0, sizeof(container));
    memset(out, 0, sizeof(*out));

    /* XDR-encode the token in to packed_token. */
    ret = pack_token(&packed_token, token);
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

out:
    rx_opaque_freeContents(&packed_token);
    rx_opaque_freeContents(&encrypted_token);
    rx_opaque_freeContents(&container.encrypted_token);
    return ret;
}

/**
 * Create an rxgk token
 *
 * Create a token from the specified TokenInfo, key, start time, and lists
 * of identities.  Encrypts the token and stores it as an rx_opaque.
 * Consumes and frees its 'identities' argument; the caller should not attempt
 * to free the storage for the array of PrAuthNames or its contents.
 *
 * @param[out] out	The encoded rxgk token (RXGK_TokenContainer).
 * @param[in] info	RXGK_Tokeninfo describing the token to be produced.
 * @param[in] k0	The token master key.
 * @param[in,out] identities	The list of identities to be included in the
 *				token.  This parameter is consumed by
 *				rxgk_make_token on a successful return and
 *				should not be freed by the caller.
 * @param[in]	nids	The number of identities in the identities list.
 * @param[in]	key	The token-encrypting key to use.
 * @param[in]	kvno	The kvno of key.
 * @param[in]	enctype	The enctype of key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_make_token(struct rx_opaque *out, RXGK_TokenInfo *info,
		struct rx_opaque *k0, PrAuthName *identities,
		int nids, rxgk_key key, afs_int32 kvno, afs_int32 enctype)
{
    RXGK_Token token;
    afs_int32 ret;

    memset(&token, 0, sizeof(token));

    /* Get the tokeninfo values from the authoritative source. */
    tokeninfo_to_token(&token, info);

    /* Create the rest of the token. */
    ret = rx_opaque_populate(&token.K0, k0->val, k0->len);
    if (ret != 0)
	return ret;
    if (nids < 0)
	return RXGK_INCONSISTENCY;
    token.identities.len = (afs_uint32)nids;
    token.identities.val = identities;
    ret = pack_wrap_token(key, kvno, enctype, &token, out);
    if (ret != 0)
	return ret;
    xdr_free((xdrproc_t)xdr_RXGK_Token, &token);
    return 0;
}

/* This lifetime is in seconds. */
#define DEFAULT_LIFETIME	(60 * 60 * 10)
/* The bytelife is log_2(bytes). */
#define DEFAULT_BYTELIFE	30
/* 0 is reserved by draft-wilkinson-afs3-rxgk-afs as "does not expire" */
#define RXGK_NEVERDATE		0
/**
 * Create a printed rxgk token
 *
 * Print a token (with empty identity list) where the master key (k0)
 * already exists, and encrypt it in the specified key/kvno/enctype.
 *
 * @param[out] out	The printed token (RXGK_TokenContainer).
 * @param[in] input_info	Parameters describing the token to be printed.
 * @param[in] k0	The master key to use for the token.
 * @param[in] key	The token-encrypting key.
 * @param[in] kvno	The kvno of key.
 * @param[in] enctype	The enctype of key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_print_token(struct rx_opaque *out, RXGK_TokenInfo *input_info,
		 struct rx_opaque *k0, rxgk_key key, afs_int32 kvno,
		 afs_int32 enctype)
{
    RXGK_TokenInfo info;

    memset(&info, 0, sizeof(info));

    info.enctype = input_info->enctype;
    info.level = input_info->level;
    info.lifetime = DEFAULT_LIFETIME;
    info.bytelife = DEFAULT_BYTELIFE;
    info.expiration = RXGK_NEVERDATE;

    return rxgk_make_token(out, &info, k0, NULL, 0, key, kvno, enctype);
}

/**
 * Print an rxgk token with random key, returning key and token
 *
 * Print a token (with empty identity list) with a random master key,
 * and encrypt it in the specified key/kvno/enctype.  Return the master
 * key as well as the token, so that the token is usable.  The random key
 * is chosen of the same enctype as the token-encrypting key.
 *
 * The caller must free k0 with release_key().
 *
 * @param[out] out	The printed token (RXGK_TokenContainer).
 * @param[in] level	The security level for which the token will be valid.
 * @param[in] key	The token-encrypting key.
 * @param[in] kvno	The kvno of key.
 * @param[in] enctype	The enctype of key and k0.
 * @param[out] k0_out	The token master key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_print_token_and_key(struct rx_opaque *out, RXGK_Level level, rxgk_key key,
			 afs_int32 kvno, afs_int32 enctype, rxgk_key *k0_out)
{
    struct rx_opaque k0_data = RX_EMPTY_OPAQUE;
    rxgk_key k0 = NULL;
    RXGK_TokenInfo info;
    ssize_t len;
    afs_int32 ret;

    memset(&info, 0, sizeof(info));
    *k0_out = NULL;
    len = etype_to_len(enctype);
    if (len < 0)
	return RXGK_BADETYPE;
    ret = rxgk_nonce(&k0_data, len);
    if (ret != 0)
	return ret;
    ret = rxgk_make_key(&k0, k0_data.val, k0_data.len, enctype);
    if (ret != 0)
	goto cleanup;
    info.level = level;
    info.enctype = enctype;
    info.lifetime = DEFAULT_LIFETIME;
    info.bytelife = DEFAULT_BYTELIFE;
    info.expiration = RXGK_NEVERDATE;
    ret = rxgk_make_token(out, &info, &k0_data, NULL, 0, key, kvno, enctype);
    if (ret != 0)
	goto cleanup;
    *k0_out = k0;
    k0 = NULL;
cleanup:
    rx_opaque_freeContents(&k0_data);
    rxgk_release_key(&k0);
    return ret;
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
decrypt_token(RXGK_Data *out, struct rx_opaque *enctoken, afs_int32 kvno,
	      afs_int32 enctype, rxgk_getkey_func getkey, void *rock)
{
    rxgk_key service_key = NULL;
    afs_int32 ret;

    if (kvno <= 0 || enctype <= 0)
	return RXGK_BAD_TOKEN;

    ret = getkey(rock, &kvno, &enctype, &service_key);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_decrypt_in_key(service_key, RXGK_SERVER_ENC_TOKEN, enctoken,
			      out);

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

/**
 * Extract a cleartext RXGK_Token from a packed RXGK_TokenContainer
 *
 * Given an XDR-encoded RXGK_TokenContainer, extract/decrypt the contents
 * into an RXGK_Token.
 *
 * The caller must free the returned token with xdr_free.
 *
 * @param[in] tc	The RXGK_TokenContainer to unpack.
 * @param[out] out	The extracted RXGK_Token.
 * @param[in] getkey	The getkey function used to decrypt the token.
 * @param[in] rock	Data to pass to getkey.
 * @return rxgk error codes.
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

cleanup:
    xdr_free((xdrproc_t)xdr_RXGK_TokenContainer, &container);
    xdr_free((xdrproc_t)xdr_RXGK_Data, &packed_token);
    return ret;
}

static void
combine_tokeninfo(RXGK_Token *t0, RXGK_Token *t1, RXGK_TokenInfo *info)
{
    if (t0->lifetime == 0)
	info->lifetime = t1->lifetime;
    else if (t1->lifetime == 0)
	info->lifetime = t0->lifetime;
    else
	info->lifetime = min(t0->lifetime, t1->lifetime);
    if (t0->bytelife == 0)
	info->bytelife = t1->bytelife;
    else if (t1->bytelife == 0)
	info->bytelife = t0->bytelife;
    else
	info->bytelife = min(t0->bytelife, t1->bytelife);
    if (t0->expirationtime == 0)
	info->expiration = t1->expirationtime;
    else if (t1->expirationtime == 0)
	info->expiration = t0->expirationtime;
    else
	info->expiration = min(t0->expirationtime, t1->expirationtime);
    return;
}

static afs_int32
process_combineoptions(RXGK_CombineOptions *options, RXGK_TokenInfo *info)
{
    if (options->enctypes.len == 0)
	return RXGK_BADETYPE;
    info->enctype = options->enctypes.val[0];
    if (options->levels.len == 0)
	return RXGK_BADLEVEL;
    info->level = options->levels.val[0];
    return 0;
}

static afs_int32
copy_id(struct PrAuthName *out, struct PrAuthName *in)
{
    afs_int32 ret;

    out->kind = in->kind;
    ret = rx_opaque_copy(&out->data, &in->data);
    if (ret != 0)
	return ret;
    ret = rx_opaque_copy(&out->display, &in->display);
    if (ret != 0) {
	rx_opaque_freeContents(&out->data);
	return ret;
    }

    return 0;
}

afs_int32
copy_ids(struct PrAuthName *out, struct PrAuthName *in, u_int n)
{
    afs_int32 ret;
    u_int i;

    for(i = 0; i < n; ++i) {
	ret = copy_id(out + i, in + i);
	if (ret != 0) {
	    n = i + 1;
	    goto cleanup;
	}
    }
    return 0;

cleanup:
    for(i = 0; i < n; ++i) {
	xdr_free((xdrproc_t)xdr_PrAuthName, out + i);
    }
    memset(out, 0, n * sizeof(struct PrAuthName));
    return ret;
}

/**
 * Concatenate two lists of PrAuthNames
 *
 * Concatenate the lists of PrAuthNames in id0 and id1 (of lengths nid0 and
 * nid1), returning the list in *ids_out and the length of the output list
 * in *nid_out.
 *
 * Callers are responsible for freeing ids_out and its contents.
 *
 * @param[in] id0	The first list of names to concatenate.
 * @param[in] nid0	The length of id0.
 * @param[in] id1	The second list of names to concatenate.
 * @param[in] nid1	The length of id1.
 * @param[out] ids_out	The output list of names.
 * @param[out] nid_out	The length of ids_out.
 * @return com_err errors.
 */
afs_int32
join_ids(struct PrAuthName *id0, u_int nid0, struct PrAuthName *id1,
	 u_int nid1, struct PrAuthName **ids_out, int *nid_out)
{
    afs_int32 ret;
    int nid, i;
    struct PrAuthName *ids;

    *nid_out = -1;
    *ids_out = NULL;

    nid = nid0 + nid1;
    /* XXX arbitrary limit not really supported by protocol spec */
    if (nid > 200 || nid0 == 0 || nid1 == 0)
	return RXGK_BAD_TOKEN;

    ids = xdr_alloc(nid * sizeof(struct PrAuthName));
    if (ids == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    memset(ids, 0, nid * sizeof(struct PrAuthName));

    ret = copy_ids(ids, id0, nid0);
    if (ret != 0)
	goto cleanup;
    ret = copy_ids(ids + nid0, id1, nid1);
    if (ret != 0)
	goto cleanup;

    /* Success; transfer ownership of the storage to the caller. */
    *nid_out = nid;
    *ids_out = ids;
    ids = NULL;

cleanup:
    if (ids != NULL) {
	for(i = 0; i < nid; ++i) {
	    xdr_free((xdrproc_t)xdr_PrAuthName, ids + i);
	}
	rxi_Free(ids, nid * sizeof(struct PrAuthName));
    }
    return ret;
}

/**
 * Perform the common aspects of CombineTokens and AFSCombineTokens
 *
 * Produce the derived key for the new token, process the combineoptions,
 * and make the new token.  The caller is responsible for having already
 * performed any identity combination that is necessary.
 *
 * Like rxgk_make_token, this function eats the supplied PrAuthName arrays
 * and frees the underlying storage during cleanup.
 *
 * @param[in] z_call	The call from which a token-encrypting key is obtained.
 * @param[in] t0	The first token to be combined.
 * @param[in] t1	The second token to be combined (or empty).
 * @param[in] options	The RXGK_CombineOptions to be used.
 * @param[out] new_token	The constructed token.
 * @param[out] info	Information describing new_token.
 * @param[in] user_ids	The list of identities to be put into new_token.
 *			The caller must have already populated this array,
 *			and this array is consumed by rxgk_combinetokens_common.
 *			The caller must not attempt to free user_ids or its
 *			contents.
 * @param[in] nuid	The length of user_ids.
 * @return rxgk error codes.
 */
afs_int32
rxgk_combinetokens_common(struct rx_call *z_call, RXGK_Token *t0,
			  RXGK_Token *t1, RXGK_CombineOptions *options,
			  RXGK_Data *new_token, RXGK_TokenInfo *info,
			  struct PrAuthName *user_ids, afs_int32 nuid,
			  rxgk_key encrypt_key, afs_int32 kvno,
			  afs_int32 enctype)
{
    RXGK_TokenInfo localinfo;
    struct rx_opaque kn = RX_EMPTY_OPAQUE;
    rxgkTime now;
    afs_int32 ret;

    memset(&localinfo, 0, sizeof(localinfo));
    now = RXGK_NOW();

    if (t0->expirationtime == 0 || t1->expirationtime == 0) {
	/* Refuse to combine a token that never expires. */
	ret = RXGK_BAD_TOKEN;
	goto cleanup;
    }
    if (t0->identities.len == 0 || t1->identities.len == 0) {
	/* Refuse to combine a printed token. */
	ret = RXGK_BAD_TOKEN;
	goto cleanup;
    }
    if (t0->expirationtime < now || t1->expirationtime < now) {
	ret = RXGK_EXPIRED;
	goto cleanup;
    }
    combine_tokeninfo(t0, t1, &localinfo);
    ret = process_combineoptions(options, &localinfo);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_combine_keys_data(&t0->K0, t0->enctype, &t1->K0, t1->enctype,
				 &kn, localinfo.enctype);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_make_token(new_token, &localinfo, &kn, user_ids, nuid,
			  encrypt_key, kvno, enctype);

cleanup:
    rxgk_release_key(&encrypt_key);
    rx_opaque_freeContents(&kn);
    return ret;
}
