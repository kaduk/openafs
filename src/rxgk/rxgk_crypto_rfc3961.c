/* rxgk/rxgk_crypto_rfc3961.c - Wrappers for RFC3961 crypto usd in RXGK. */
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
 * Wrappers for the RFC3961 crypto routines used by RXGK, and
 * helpers.  This implementation uses the in-tree rfc3961 library, but
 * we do not expose those types in our interface so as to be
 * compatible with other backends in the future.
 *
 * This is what an rxgk_key really is, but it's void* to consumers:
 * typedef krb5_keyblock * rxgk_key;
 *
 * Public functions in this file should return RXGK error codes, converting
 * from the krb5 error codes used internally.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <errno.h>

#include <rx/rx.h>
#include <rx/rxgk.h>
#include <afs/rfc3961.h>
#include <assert.h>

#include "rxgk_private.h"

/* Convenience macro, reduces the diff if an MIT krb5 backend were to be made. */
#define deref_keyblock_enctype(k)	krb5_keyblock_get_enctype(k)

/*
 * Convert krb5 error code to RXGK error code.  Don't let the krb5 codes escape.
 */
static_inline afs_int32
ktor(afs_int32 err)
{

    if (err >= ERROR_TABLE_BASE_RXGK && err < (ERROR_TABLE_BASE_RXGK + 256))
	return err;
    switch (err) {
	case 0:
	    return 0;
	default:
	    return RXGK_INCONSISTENCY;
    }
}

/*
 * Convert a krb5 enctype to a krb5 checksum type.  Each enctype has a
 * mandatory (to implement) checksum type, which can be chosen when
 * computing a checksum by passing 0 for the type parameter.  However,
 * we must separately compute the length of a checksum on a message in
 * order to verify a packet at RXGK_LEVEL_AUTH, and MIT krb5 does not
 * expose a way to get the mandatory checksum type for a given enctype.
 * So, we get to do it ourselves.
 */
static_inline afs_int32
etoc(afs_int32 etype)
{
    switch(etype) {
	case ETYPE_DES_CBC_CRC:
	    return CKSUMTYPE_RSA_MD5_DES;
	case ETYPE_DES_CBC_MD4:
	    return CKSUMTYPE_RSA_MD4_DES;
	case ETYPE_DES_CBC_MD5:
	    return CKSUMTYPE_RSA_MD5_DES;
	case ETYPE_DES3_CBC_SHA1:
	    return CKSUMTYPE_HMAC_SHA1_DES3;
	case ETYPE_ARCFOUR_MD4:
	    return CKSUMTYPE_HMAC_MD5_ENC;
	case ETYPE_AES128_CTS_HMAC_SHA1_96:
	    return CKSUMTYPE_HMAC_SHA1_96_AES_128;
	case ETYPE_AES256_CTS_HMAC_SHA1_96:
	    return CKSUMTYPE_HMAC_SHA1_96_AES_256;
#if 0
	case ETYPE_CAMELLIA128_CTS_CMAC:
	    return CKSUMTYPE_CMAC_CAMELLIA128;
	case ETYPE_CAMELLIA256_CTS_CMAC:
	    return CKSUMTYPE_CMAC_CAMELLIA256;
#endif
	default:
	    return -1;
    }
}

/*
 * Return the number of octets of input needed for a key of the given etype,
 * or -1 on error.
 */
static ssize_t
etype_to_len(int etype)
{
    krb5_context ctx;
    krb5_error_code code;
    size_t bits;

    code = krb5_init_context(&ctx);
    if (code != 0)
	return -1;
    code = krb5_enctype_keybits(ctx, etype, &bits);
    krb5_free_context(ctx);
    if (code != 0)
	return -1;
    return (bits + 7) / 8;
}

/*
 * Take a raw key from some external source and produce an rxgk_key from it.
 * The raw_key and length are not an RXGK_Data because in some cases they will
 * come from a gss_buffer and there's no real need to do the conversion.
 * The caller must use release_key to deallocate memory allocated for the
 * new rxgk_key.
 */
afs_int32
rxgk_make_key(rxgk_key *key_out, void *raw_key, afs_int32 length,
	      afs_int32 enctype)
{
    krb5_keyblock *new_key;
    krb5_context ctx;
    krb5_error_code ret;

    /* Must initialize before we return. */
    *key_out = NULL;

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    new_key = rxi_Alloc(sizeof(*new_key));
    /* free with krb5_free_keyblock_contents + rxi_Free */
    ret = krb5_keyblock_init(ctx, enctype, raw_key, length, new_key);
    if (ret != 0) {
	free(new_key);
	goto out;
    }
    *key_out = (rxgk_key)new_key;
out:
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Copy a given key.  The caller must use release_key to deallocate the memory
 * allocated for the new rxgk_key.
 */
afs_int32
rxgk_copy_key(rxgk_key key_in, rxgk_key *key_out)
{
    krb5_keyblock *keyblock;

    keyblock = key_in;
    return rxgk_make_key(key_out, keyblock->keyvalue.data,
			 keyblock->keyvalue.length, keyblock->keytype);
}

/*
 * Generate a random key.  The caller must use release_key to deallocate the
 * memory allocated for the new rxgk_key.
 */
afs_int32
rxgk_random_key(afs_int32 enctype, rxgk_key *key_out)
{
    krb5_keyblock *keyblock;
    void *buf;
    krb5_context ctx;
    krb5_error_code ret;
    ssize_t len;

    buf = keyblock = NULL;

    if (key_out == NULL)
	return RXGK_INCONSISTENCY;

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    keyblock = rxi_Alloc(sizeof(*keyblock));
    if (keyblock == NULL)
	goto out;
    len = etype_to_len(enctype);
    buf = rxi_Alloc(len);
    if (buf == NULL)
	goto out;
    krb5_generate_random_block(buf, (size_t)len);
    ret = krb5_keyblock_init(ctx, enctype, buf, len, keyblock);
    if (ret != 0)
	goto out;

    *key_out = keyblock;
    keyblock = NULL;

out:
    krb5_free_context(ctx);
    rxi_Free(buf, sizeof(len));
    rxi_Free(keyblock, sizeof(*keyblock));
    return ktor(ret);
}

/*
 * Call into the underlying library to release any storage allocated for
 * the rxgk_key, and null out the key pointer.
 */
void
rxgk_release_key(rxgk_key *key)
{
    krb5_context ctx;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)*key;

    if (key == NULL)
	return;

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return;
    krb5_free_keyblock_contents(ctx, keyblock);
    rxi_Free(keyblock, sizeof(*keyblock));
    krb5_free_context(ctx);
    *key = NULL;
}

/*
 * Determine the length of a checksum (MIC) using the specified key.
 */
afs_int32
rxgk_mic_length(rxgk_key key, size_t *out)
{
    krb5_context ctx;
    krb5_cksumtype cstype;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;
    size_t len;

    *out = 0;

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);
    cstype = etoc(enctype);
    if (cstype == -1) {
	ret = RXGK_BADETYPE;
	goto cleanup;
    }
    ret = krb5_checksumsize(ctx, cstype, &len);
    if (ret != 0)
	goto cleanup;
    *out = len;

cleanup:
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Call into the RFC 3961 encryption framework to obtain a Message Integrity
 * Check of a buffer using the specified key and key usage.  It is assumed
 * that the rxgk_key structure includes the enctype information needed to
 * determine which crypto routine to call.
 * The output buffer is allocated with xdr_alloc and must be freed by the
 * caller.
 */
afs_int32
rxgk_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		struct rx_opaque *out)
{
    krb5_context ctx;
    Checksum cksum;
    krb5_cksumtype cstype;
    krb5_crypto crypto = NULL;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;
    size_t len;

    memset(&cksum, 0, sizeof(cksum));
    memset(out, 0, sizeof(*out));

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);
    cstype = etoc(enctype);
    if (cstype == -1) {
	ret = RXGK_BADETYPE;
	goto cleanup;
    }
    ret = krb5_checksumsize(ctx, cstype, &len);
    if (ret != 0)
	goto cleanup;
    out->val = xdr_alloc(len);
    if (out->val == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    out->len = len;
    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    ret = krb5_create_checksum(ctx, crypto, usage, cstype, in->val, in->len,
			       &cksum);
    if (ret != 0)
	goto cleanup;
    /* sanity check */
    if (len != cksum.checksum.length) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    memcpy(out->val, cksum.checksum.data, len);

cleanup:
    free_Checksum(&cksum);
    krb5_crypto_destroy(ctx, crypto);
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Call into the RFC 3961 encryption framework to verify a message integrity
 * check on a message, using the specified key with the specified key usage.
 * It is assumed that the rxgk_key structure includes the enctype information
 * needed to determine which particular crypto routine to call.
 */
afs_int32
rxgk_check_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		      RXGK_Data *mic)
{
    krb5_context ctx;
    Checksum cksum;
    krb5_crypto crypto = NULL;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;

    memset(&cksum, 0, sizeof(cksum));

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);
    cksum.cksumtype = etoc(enctype);
    cksum.checksum.data = mic->val;
    cksum.checksum.length = mic->len;
    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    ret = krb5_verify_checksum(ctx, crypto, usage, in->val, in->len, &cksum);
    if (ret != 0) {
	ret = RXGK_SEALED_INCON;
	goto cleanup;
    }

cleanup:
    krb5_crypto_destroy(ctx, crypto);
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Call into the RFC 3961 encryption framework to encrypt a buffer in the
 * specified key with the specified key usage.  It is assumed that the
 * rxgk_key structure includes the enctype information needed to determine
 * which particular crypto routine to call.
 * The output buffer is allocated with xdr_alloc and must be freed by the
 * caller.
 */
afs_int32
rxgk_encrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		    struct rx_opaque *out)
{
    krb5_context ctx;
    krb5_crypto crypto;
    krb5_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;

    memset(&kd_out, 0, sizeof(kd_out));
    memset(out, 0, sizeof(*out));

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);
    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    ret = krb5_encrypt(ctx, crypto, usage, in->val, in->len, &kd_out);
    if (ret != 0)
	goto cleanup;
    ret = rx_opaque_populate(out, kd_out.data, kd_out.length);
    if (ret != 0)
	goto cleanup;

cleanup:
    krb5_crypto_destroy(ctx, crypto);
    krb5_data_free(&kd_out);
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Call into the RFC 3961 encryption framework to decrypt a buffer with the
 * specified key with the specified key usage.  It is assumed that the
 * rxgk_key structure includes the enctype information needed to determine
 * which particular crypto routine to call.
 * The output buffer is allocated with xdr_alloc and must be freed by the
 * caller.
 */
afs_int32
rxgk_decrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		    struct rx_opaque *out)
{
    krb5_context ctx;
    krb5_crypto crypto;
    krb5_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;

    memset(out, 0, sizeof(*out));
    memset(&kd_out, 0, sizeof(kd_out));

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);

    /* output will be smaller than input */
    ret = rx_opaque_alloc(out, in->len);
    if (ret != 0) {
	krb5_free_context(ctx);
	return ktor(ret);
    }

    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    ret = krb5_decrypt(ctx, crypto, usage, in->val, in->len, &kd_out);
    if (ret != 0)
	goto cleanup;
    memcpy(out->val, kd_out.data, kd_out.length);
    out->len = kd_out.length;

cleanup:
    krb5_crypto_destroy(ctx, crypto);
    krb5_data_free(&kd_out);
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Helper for derive_tk.
 * Assumes the caller has already allocated space in 'out'.
 */
static afs_int32
PRFplus(krb5_data *out, krb5_enctype enctype, rxgk_key k0,
	ssize_t desired_len, void *seed, size_t seed_len)
{
    krb5_context ctx;
    krb5_crypto crypto = NULL;
    krb5_data prf_in, prf_out;
    krb5_error_code ret;
    krb5_keyblock *keyblock = k0;
    unsigned char *pre_key;
    size_t block_len;
    afs_uint32 nn, iterations, dummy;

    memset(&prf_in, 0, sizeof(prf_in));
    memset(&prf_out, 0, sizeof(prf_out));
    pre_key = NULL;

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    prf_in.data = rxi_Alloc(sizeof(nn) + seed_len);
    if (prf_in.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    prf_in.length = sizeof(nn) + seed_len;
    memcpy((unsigned char *)prf_in.data + sizeof(nn), seed, seed_len);
    nn = 1;
    dummy = htonl(nn);
    memcpy(prf_in.data, &dummy, sizeof(dummy));
    ret = krb5_crypto_prf(ctx, crypto, &prf_in, &prf_out);
    if (ret != 0)
	goto cleanup;
    block_len = prf_out.length;

    iterations = (desired_len + block_len - 1) / block_len;
    pre_key = rxi_Alloc(iterations * block_len);
    if (pre_key == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    memcpy(pre_key + (nn - 1) * block_len, prf_out.data, block_len);

    /* We already did the first iteration of the loop, to get block_len. */
    for(nn = 2; nn <= iterations; ++nn) {
	dummy = htonl(nn);
	memcpy(prf_in.data, &dummy, sizeof(dummy));
	krb5_data_free(&prf_out);
	ret = krb5_crypto_prf(ctx, crypto, &prf_in, &prf_out);
	if (ret != 0)
	    goto cleanup;
	memcpy(pre_key + (nn - 1) * block_len, prf_out.data, block_len);
    }
    memcpy(out->data, pre_key, desired_len);

cleanup:
    krb5_crypto_destroy(ctx, crypto);
    krb5_data_free(&prf_out);
    krb5_free_context(ctx);
    rxi_Free(prf_in.data, sizeof(nn) + seed_len);
    if (pre_key != NULL)
	rxi_Free(pre_key, iterations * block_len);
    return ktor(ret);
}

/*
 * Given a connection master key k0, derive a transport key tk from the master
 * key and connection parameters.
 *
 * TK = random-to-key(PRF+(K0, L, epoch || cid || start_time || key_number))
 * using the RFC4402 PRF+, i.e., the ordinal of the application of the
 * pseudo-random() function is stored in a 32-bit field, not an 8-bit field
 * as in RFC6112.
 */
struct seed_data {
    afs_uint32 epoch;
    afs_uint32 cid;
    afs_uint32 time_hi;
    afs_uint32 time_lo;
    afs_uint32 key_number;
} __attribute__((packed));
afs_int32
rxgk_derive_tk(rxgk_key *tk, rxgk_key k0, afs_uint32 epoch, afs_uint32 cid,
	       rxgkTime start_time, afs_uint32 key_number)
{
    krb5_enctype enctype;
    krb5_data pre_key;
    krb5_keyblock *keyblock = k0;
    struct seed_data seed;
    ssize_t ell;
    afs_int32 ret;

    memset(&pre_key, 0, sizeof(pre_key));
    memset(&seed, 0, sizeof(seed));
    assert(sizeof(seed) == 20);

    enctype = deref_keyblock_enctype(keyblock);
    ell = etype_to_len(enctype);

    seed.epoch = htonl(epoch);
    seed.cid = htonl(cid);
    seed.time_hi = htonl((afs_int32)(start_time / ((afs_uint64)1 << 32)));
    seed.time_lo = htonl((afs_int32)(start_time & (afs_uint64)0xffffffffu));
    seed.key_number = htonl(key_number);

    pre_key.data = rxi_Alloc(ell);
    if (pre_key.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    pre_key.length = ell;
    ret = PRFplus(&pre_key, enctype, k0, ell, &seed, sizeof(seed));
    if (ret != 0)
	goto cleanup;

    ret = rxgk_make_key(tk, pre_key.data, ell, enctype);
    if (ret != 0)
	goto cleanup;

cleanup:
    rxi_Free(pre_key.data, ell);
    return ret;
}

/*
 * Determine the maximum ciphertext expansion for a given enctype.
 */
afs_int32
rxgk_cipher_expansion(rxgk_key k0, int *len_out)
{
    krb5_context ctx;
    krb5_crypto crypto;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = k0;
    size_t len;

    *len_out = -1;

    enctype = deref_keyblock_enctype(keyblock);
    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    len = krb5_crypto_overhead(ctx, crypto);
    *len_out = len;

cleanup:
    krb5_crypto_destroy(ctx, crypto);
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Allocate and fill the buffer in nonce with len bytes of random data.
 */
afs_int32
rxgk_nonce(struct rx_opaque *nonce, int len)
{

    if (rx_opaque_alloc(nonce, len) != 0)
	return RXGEN_SS_MARSHAL;

    krb5_generate_random_block(nonce->val, len);
    return 0;
}

afs_int32
rxgk_combine_keys(rxgk_key k0, rxgk_key k1, afs_int32 enctype, rxgk_key *kn)
{
    krb5_context ctx;
    krb5_crypto c0 = NULL, c1 = NULL;
    krb5_data pepper0, pepper1;
    krb5_enctype e0, e1;
    krb5_keyblock *kb0 = k0, *kb1 = k1, *kbn = NULL;
    afs_int32 ret;

    *kn = NULL;
    memset(&pepper0, 0, sizeof(pepper0));
    memset(&pepper1, 0, sizeof(pepper1));

    e0 = deref_keyblock_enctype(kb0);
    e1 = deref_keyblock_enctype(kb1);
    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    ret = krb5_crypto_init(ctx, kb0, e0, &c0);
    if (ret != 0)
	goto cleanup;
    ret = krb5_crypto_init(ctx, kb1, e1, &c1);
    if (ret != 0)
	goto cleanup;
    kbn = rxi_Alloc(sizeof(*kbn));
    if (kbn == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    pepper0.data = "AFS";
    pepper0.length = 3;
    pepper1.data = "rxgk";
    pepper1.length = 4;
    ret = krb5_crypto_fx_cf2(ctx, c0, c1, &pepper0, &pepper1, enctype, kbn);
    if (ret != 0)
	goto cleanup;
    *kn = kbn;

cleanup:
    krb5_crypto_destroy(ctx, c0);
    krb5_crypto_destroy(ctx, c1);
    krb5_free_context(ctx);
    return ret;
}

/*
 * Take the raw key data from k[01]_data, for keys of enctypes e[01],
 * and perform the KRB-FX-CF2 combination algorithm to yield the new
 * key with raw key data in kn of enctype en.
 * The caller must free the storage in *kn_data.
 *
 * Returns rxgk error codes.
 */
afs_int32
rxgk_combine_keys_data(RXGK_Data *k0_data, afs_int32 e0, RXGK_Data *k1_data,
		       afs_int32 e1, RXGK_Data *kn_data, afs_int32 en)
{
    krb5_keyblock *kbn;
    rxgk_key k0 = NULL, k1 = NULL, kn = NULL;
    afs_int32 ret;

    memset(kn_data, 0, sizeof(*kn_data));

    ret = rxgk_make_key(&k0, k0_data->val, k0_data->len, e0);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_make_key(&k1, k1_data->val, k1_data->len, e1);
    if (ret != 0)
	goto cleanup;
    ret = rxgk_combine_keys(k0, k1, en, kn);
    if (ret != 0)
	goto cleanup;
    kbn = kn;
    ret = rx_opaque_populate(kn_data, kbn->keyvalue.data, kbn->keyvalue.length);

cleanup:
    rxgk_release_key(&k0);
    rxgk_release_key(&k1);
    rxgk_release_key(&kn);
    return ret;
}
