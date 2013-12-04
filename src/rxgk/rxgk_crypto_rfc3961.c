/* rxgk/rxgk_crypto.c - Wrappers for RFC3961 crypto usd in RXGK. */
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
 * helpers.  The implementation currently uses libkrb5, but
 * we do not expose those types in our interface so as to be
 * compatible with other backends in the future.
 *
 * typedef krb5_keyblock * rxgk_key;
 *
 * Public functions in this file should return RXGK error codes, converting
 * from the krb5 error codes used internally.
 */

#include <afsconfig.h>

#include <gssapi/gssapi.h>
#include <rx/rxgk.h>

#include <afs/rfc3961.h>
#include <assert.h>

/* Some compat shims for Heimdal/MIT compatibility. */
#define deref_keyblock_enctype(k)	krb5_keyblock_get_enctype(k)

/*
 * Convert krb5 error code to RXGK error code.  Don't let the krb5 codes excape.
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

/* XXX Copied from rxgk_util.c.  Should get centralized or eliminated. */
static ssize_t
etype_to_len(int etype)
{
    /* Should use krb5_c_keylengths, but that requires a krb5_context. */

    switch(etype)
    {
	case 1: return 7;
	case 2: return 7;
	case 3: return 7;
	case 5: return 21;
	case 7: return 21;
	case 16: return 21;
	case 17: return 16;
	case 18: return 32;
	default: return -1;
    }
}

/*
 * Take a raw key from some external source and produce an rxgk_key from it.
 * The raw_key and length are not an RXGK_Data because in some cases they will
 * come from a gss_buffer and there's no real need to do the conversion.
 * The caller must use release_key to deallocate memory allocated for the
 * new rxgk_key.
 */
afs_int32
make_key(rxgk_key *key_out, void *raw_key, afs_int32 length, afs_int32 enctype)
{
    krb5_keyblock *new_key;
    krb5_context ctx;
    krb5_error_code ret;

    /* Must initialize before we return. */
    *key_out = NULL;

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    new_key = malloc(sizeof(*new_key));
    /* free with krb5_free_keyblock_contents + free */
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
copy_key(rxgk_key key_in, rxgk_key *key_out)
{
    krb5_keyblock *keyblock;

    keyblock = key_in;
    return make_key(key_out, keyblock->keyvalue.data, keyblock->keyvalue.length,
		    keyblock->keytype);
}

/*
 * Generate a random key.  The caller must use release_key to deallocate the
 * memory allocated for the new rxgk_key.
 */
afs_int32
random_key(afs_int32 enctype, rxgk_key *key_out)
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
    keyblock = malloc(sizeof(*keyblock));
    if (keyblock == NULL)
	goto out;
    len = etype_to_len(enctype);
    buf = malloc(len);
    if (buf == NULL)
	goto out;
    krb5_generate_random_block(buf, (size_t)len);
    ret = krb5_keyblock_init(ctx, enctype, buf, len, keyblock);

    *key_out = keyblock;
    keyblock = NULL;

out:
    krb5_free_context(ctx);
    free(buf);
    free(keyblock);
    return ktor(ret);
}

/*
 * Call into the underlying library to release any storage allocated for
 * the rxgk_key, and null out the key pointer.
 */
void
release_key(rxgk_key *key)
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
    free(keyblock);
    krb5_free_context(ctx);
    *key = NULL;
}

/*
 * Determine the length of a checksum (MIC) using the specified key.
 */
afs_int32
mic_length(rxgk_key key, size_t *out)
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
mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in, RXGK_Data *out)
{
    krb5_context ctx;
    Checksum cksum;
    krb5_cksumtype cstype;
    krb5_crypto crypto;
    Checksum ck_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;
    size_t len;

    memset(&cksum, 0, sizeof(cksum));
    zero_rxgkdata(out);

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
			       &ck_out);
    if (ret != 0)
	goto cleanup;
    /* sanity check */
    if (len != ck_out.checksum.length) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    memcpy(out->val, ck_out.checksum.data, len);

cleanup:
    free_Checksum(&ck_out);
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
check_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in, RXGK_Data *mic)
{
    krb5_context ctx;
    Checksum cksum;
    krb5_crypto crypto;
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
encrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in, RXGK_Data *out)
{
    krb5_context ctx;
    krb5_crypto crypto;
    krb5_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;
    size_t length;

    memset(&kd_out, 0, sizeof(kd_out));
    zero_rxgkdata(out);

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);
    ret = krb5_crypto_init(ctx, keyblock, enctype, &crypto);
    if (ret != 0)
	goto cleanup;
    ret = krb5_encrypt(ctx, crypto, usage, in->val, in->len, &kd_out);
    length = kd_out.length;
    out->val = xdr_alloc(length);
    if (out->val == NULL) {
	ret = RXGK_INCONSISTENCY;	/* Should be something better, but... */
	goto cleanup;
    }
    out->len = length;
    memcpy(out->val, kd_out.data, kd_out.length);

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
decrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in, RXGK_Data *out)
{
    krb5_context ctx;
    krb5_crypto crypto;
    krb5_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;

    zero_rxgkdata(out);
    memset(&kd_out, 0, sizeof(kd_out));

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    enctype = deref_keyblock_enctype(keyblock);

    /* output will be smaller than input */
    out->val = kd_out.data = xdr_alloc(in->len);
    if (kd_out.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    out->len = kd_out.length = in->len;

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
    krb5_crypto crypto;
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
    prf_in.data = malloc(sizeof(nn) + seed_len);
    if (prf_in.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    prf_in.length = sizeof(nn) + seed_len;
    memcpy(prf_in.data + sizeof(nn), seed, seed_len);
    nn = 1;
    dummy = htonl(nn);
    memcpy(prf_in.data, &dummy, sizeof(dummy));
    ret = krb5_crypto_prf(ctx, crypto, &prf_in, &prf_out);
    if (ret != 0)
	goto cleanup;
    block_len = prf_out.length;

    iterations = (desired_len + block_len - 1) / block_len;
    pre_key = malloc(iterations * block_len);
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
    free(prf_in.data);
    free(pre_key);
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
derive_tk(rxgk_key *tk, rxgk_key k0, afs_uint32 epoch, afs_uint32 cid,
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

    pre_key.data = malloc(ell);
    if (pre_key.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto cleanup;
    }
    pre_key.length = ell;
    ret = PRFplus(&pre_key, enctype, k0, ell, &seed, sizeof(seed));
    if (ret != 0)
	goto cleanup;

    ret = make_key(tk, pre_key.data, ell, enctype);
    if (ret != 0)
	goto cleanup;

cleanup:
    free(pre_key.data);
    return ret;
}

/*
 * Determine the maximum ciphertext expansion for a given enctype.
 * Loop over plaintext size until the expansion repeats, and keep a running
 * maximum to be returned.
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
