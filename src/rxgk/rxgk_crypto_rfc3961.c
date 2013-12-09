/* rxgk/rxgk_crypto_rfc3961.c - Wrappers for RFC3961 crypto usd in RXGK. */
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
 * Wrappers for the RFC3961 crypto routines used by RXGK, and
 * helpers.  This implementation uses the in-tree rfc3961 library, but
 * we do not expose those types in our interface so as to be
 * compatible with other backends in the future.  It should be possible
 * to backend to an out-of-tree krb5 library or the kernel's crypto
 * framework using this API.
 *
 * Public functions in this file should return RXGK error codes, because
 * error codes from these functions can end up on the wire.  This will
 * entail converting from any krb5 error codes that are used internally.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#ifdef KERNEL
# include "afs/sysincludes.h"
# include "afsincludes.h"
#else
# include <errno.h>
#endif

#include <rx/rx.h>
#include <rx/rxgk.h>
#include <afs/rfc3961.h>
#include <afs/opr.h>

#include "rxgk_private.h"

/*
 * This is what an rxgk_key really is, but it's void* to consumers:
 * typedef struct rxgk_keyblock * rxgk_key;
 */
struct rxgk_keyblock {
    krb5_context ctx;
    krb5_keyblock key;
};

/* Convenience macro; reduces the diff if an MIT krb5 backend is made. */
#define deref_keyblock_enctype(k)	krb5_keyblock_get_enctype(k)

/**
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

/**
 * Convert a krb5 enctype to a krb5 checksum type.
 *
 * Each enctype has a mandatory (to implement) checksum type, which can be
 * chosen when computing a checksum by passing 0 for the type parameter.
 * However, we must separately compute the length of a checksum on a message in
 * order to extract the checksum from a packet at RXGK_LEVEL_AUTH, and Heimdal
 * krb5 does not expose a way to get the mandatory checksum type for a given
 * enctype.  So, we get to do it ourselves.
 *
 * @return -1 on failure, otherwise the checksum type.
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
	default:
	    return -1;
    }
}

/**
 * Get the number of octets of input needed for a key of the given etype,
 *
 * @return -1 on error, or the number of octets of input needed on success.
 */
ssize_t
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

/**
 * Take a raw key from some external source and produce an rxgk_key from it.
 *
 * The raw_key and length are not an RXGK_Data because in some cases they will
 * come from a gss_buffer and there's no real need to do the conversion.
 * The caller must use rxgk_release_key to deallocate memory allocated for the
 * new rxgk_key.
 *
 * This routine checks whether the length of the  supplied key data matches
 * the key generation seed length for the requested enctype, in which case
 * the RFC 3961 random_to_key operation is performed, or if it is the
 * actual (output) key length, in which case the key data is used as-is.
 *
 * @param key_out	the returned rxgk_key.
 * @param raw_key	a pointer to the octet stream of the key input data.
 * @param length	the length of raw_key (in octets).
 * @param enctype	the RFC 3961 enctype of the key being constructed.
 * @return rxgk error codes.
 */
afs_int32
rxgk_make_key(rxgk_key *key_out, void *raw_key, afs_uint32 length,
	      afs_int32 enctype)
{
    struct rxgk_keyblock *new_key = NULL;
    krb5_context ctx = NULL;
    krb5_error_code ret;
    size_t full_length;
    ssize_t input_length;

    /* Must initialize before we return. */
    *key_out = NULL;

    new_key = rxi_Alloc(sizeof(*new_key));
    if (new_key == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }
    ret = krb5_init_context(&new_key->ctx);
    if (ret != 0)
	goto done;
    ret = krb5_enctype_keysize(new_key->ctx, enctype, &full_length);
    if (ret != 0)
	goto done;
    input_length = etype_to_len(enctype);
    if (input_length < 0) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }
    if (length == full_length) {
	/* free with krb5_free_keyblock_contents + rxi_Free */
	ret = krb5_keyblock_init(ctx, enctype, raw_key, length, &new_key->key);
    } else if (length == input_length) {
	/* free with krb5_free_keyblock_contents + rxi_Free */
	ret = krb5_random_to_key(ctx, enctype, raw_key, length, &new_key->key);
    } else {
	ret = RXGK_BADETYPE;
    }
    if (ret != 0)
	goto done;
    *key_out = (rxgk_key)new_key;
 done:
    if (ret != 0 && new_key != NULL) {
	krb5_free_context(new_key->ctx);
	rxi_Free(new_key, sizeof(*new_key));
    }
    return ktor(ret);
}

/**
 * Copy a given key.
 *
 * The caller must use rxgk_release_key to deallocate the memory allocated
 * for the new rxgk_key.
 *
 * @param[in] key_in	The key to be copied.
 * @param[out] key_out	A copy of key_in.
 * @return rxgk error codes.
 */
afs_int32
rxgk_copy_key(rxgk_key key_in, rxgk_key *key_out)
{
    struct rxgk_keyblock *keyblock;

    keyblock = key_in;
    return rxgk_make_key(key_out, keyblock->key.keyvalue.data,
			 keyblock->key.keyvalue.length, keyblock->key.keytype);
}

/**
 * Generate a random key.
 *
 * The caller must use rxgk_release_key to deallocate the memory allocated
 * for the new rxgk_key.
 *
 * @param[in] enctype	The RFC 3961 enctype of the key to be generated.
 * @param[out] key_out	The random rxgk key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_random_key(afs_int32 enctype, rxgk_key *key_out)
{
    void *buf;
    krb5_error_code ret;
    ssize_t len;

    buf = NULL;

    if (key_out == NULL)
	return RXGK_INCONSISTENCY;

    len = etype_to_len(enctype);
    if (len < 0)
	return RXGK_INCONSISTENCY;
    buf = rxi_Alloc(len);
    if (buf == NULL)
	return RXGK_INCONSISTENCY;
    krb5_generate_random_block(buf, (size_t)len);
    ret = rxgk_make_key(key_out, buf, len, enctype);
    rxi_Free(buf, len);
    return ret;
}

/**
 * Release the storage underlying an rxgk key
 *
 * Call into the underlying library to release any storage allocated for
 * the rxgk_key, and null out the key pointer.
 */
void
rxgk_release_key(rxgk_key *key)
{
    struct rxgk_keyblock *keyblock;

    if (key == NULL)
	return;
    keyblock = *key;

    krb5_free_keyblock_contents(keyblock->ctx, &keyblock->key);
    krb5_free_context(keyblock->ctx);
    rxi_Free(keyblock, sizeof(*keyblock));
    *key = NULL;
}

/**
 * Determine the length of a checksum (MIC) using the specified key.
 *
 * @param[in] key	The rxgk_key being queried.
 * @param[out] out	The length of a checksum made using key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_mic_length(rxgk_key key, size_t *out)
{
    krb5_cksumtype cstype;
    krb5_enctype enctype;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = (struct rxgk_keyblock *)key;
    size_t len;

    *out = 0;

    enctype = deref_keyblock_enctype(&keyblock->key);
    cstype = etoc(enctype);
    if (cstype == -1) {
	ret = RXGK_BADETYPE;
	goto done;
    }
    ret = krb5_checksumsize(keyblock->ctx, cstype, &len);
    if (ret != 0)
	goto done;
    *out = len;

 done:
    return ktor(ret);
}

/**
 * Obtain the RFC 3961 Message Integrity Check of a buffer
 *
 * Call into the RFC 3961 encryption framework to obtain a Message Integrity
 * Check of a buffer using the specified key and key usage.  It is assumed
 * that the rxgk_key structure includes the enctype information needed to
 * determine which crypto routine to call.
 *
 * The output buffer is allocated with rx_opaque_populate() and must be freed
 * by the caller (with rx_opaque_freeContents()).
 *
 * @param[in] key	The key used to key the MIC.
 * @param[in] usage	The key usage value to use (from rxgk_int.h).
 * @param[in] in	The input buffer to be MICd.
 * @param[out] out	The MIC.
 * @return rxgk error codes.
 */
afs_int32
rxgk_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		RXGK_Data *out)
{
    Checksum cksum;
    krb5_cksumtype cstype;
    krb5_crypto crypto = NULL;
    krb5_enctype enctype;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = (struct rxgk_keyblock *)key;
    size_t len;

    memset(&cksum, 0, sizeof(cksum));
    memset(out, 0, sizeof(*out));

    enctype = deref_keyblock_enctype(&keyblock->key);
    cstype = etoc(enctype);
    if (cstype == -1) {
	ret = RXGK_BADETYPE;
	goto done;
    }
    ret = krb5_checksumsize(keyblock->ctx, cstype, &len);
    if (ret != 0)
	goto done;
    ret = krb5_crypto_init(keyblock->ctx, &keyblock->key, enctype, &crypto);
    if (ret != 0)
	goto done;
    ret = krb5_create_checksum(keyblock->ctx, crypto, usage, cstype, in->val,
			       in->len, &cksum);
    if (ret != 0)
	goto done;
    /* sanity check */
    if (len != cksum.checksum.length) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }
    ret = rx_opaque_populate(out, cksum.checksum.data, len);

 done:
    free_Checksum(&cksum);
    if (crypto != NULL)
	krb5_crypto_destroy(keyblock->ctx, crypto);
    return ktor(ret);
}

/**
 * Verify the RFC 3961 Message Integrity Check on a message
 *
 * Call into the RFC 3961 encryption framework to verify a message integrity
 * check on a message, using the specified key with the specified key usage.
 * It is assumed that the rxgk_key structure includes the enctype information
 * needed to determine which particular crypto routine to call.
 *
 * @param[in] key	The key keying the checksum.
 * @param[in] usage	The key usage for the checksum.
 * @param[in] in	The buffer which was checksummed.
 * @param[in] mic	The MIC to be verified.
 * @return rxgk error codes.
 */
afs_int32
rxgk_check_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		      RXGK_Data *mic)
{
    Checksum cksum;
    krb5_crypto crypto = NULL;
    krb5_enctype enctype;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = (struct rxgk_keyblock *)key;

    memset(&cksum, 0, sizeof(cksum));

    enctype = deref_keyblock_enctype(&keyblock->key);
    cksum.cksumtype = etoc(enctype);
    ret = krb5_crypto_init(keyblock->ctx, &keyblock->key, enctype, &crypto);
    if (ret != 0)
	goto done;
    cksum.checksum.data = mic->val;
    cksum.checksum.length = mic->len;
    ret = krb5_verify_checksum(keyblock->ctx, crypto, usage, in->val, in->len,
			       &cksum);
    /* Un-alias the storage to avoid a double-free. */
    cksum.checksum.data = NULL;
    cksum.checksum.length = 0;
    if (ret != 0) {
	ret = RXGK_SEALED_INCON;
    }

 done:
    free_Checksum(&cksum);
    if (crypto != NULL)
	krb5_crypto_destroy(keyblock->ctx, crypto);
    return ktor(ret);
}

/**
 * Encrypt a buffer in a key using the RFC 3961 framework
 *
 * Call into the RFC 3961 encryption framework to encrypt a buffer with
 * specified key and key usage.  It is assumed that the rxgk_key structure
 * includes the enctype information needed to determine which particular
 * crypto routine to call.
 *
 * The output buffer is allocated with rx_opaque_populate() and must be freed
 * by the caller (with rx_opaque_freeContents()).
 *
 * @param[in] key	The key used to encrypt the message.
 * @param[in] usage	The key usage for the encryption.
 * @param[in] in	The buffer being encrypted.
 * @param[out] out	The encrypted form of the message.
 * @return rxgk error codes.
 */
afs_int32
rxgk_encrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		    RXGK_Data *out)
{
    krb5_crypto crypto = NULL;
    krb5_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = (struct rxgk_keyblock *)key;

    memset(&kd_out, 0, sizeof(kd_out));
    memset(out, 0, sizeof(*out));

    enctype = deref_keyblock_enctype(&keyblock->key);
    ret = krb5_crypto_init(keyblock->ctx, &keyblock->key, enctype, &crypto);
    if (ret != 0)
	goto done;
    ret = krb5_encrypt(keyblock->ctx, crypto, usage, in->val, in->len, &kd_out);
    if (ret != 0)
	goto done;
    ret = rx_opaque_populate(out, kd_out.data, kd_out.length);

 done:
    if (crypto != NULL)
	krb5_crypto_destroy(keyblock->ctx, crypto);
    krb5_data_free(&kd_out);
    return ktor(ret);
}

/**
 * Decrypt a buffer using a given key in the RFC 3961 framework
 *
 * Call into the RFC 3961 encryption framework to decrypt a buffer with the
 * specified key with the specified key usage.  It is assumed that the
 * rxgk_key structure includes the enctype information needed to determine
 * which particular crypto routine to call.
 *
 * The output buffer is allocated with rx_opaque_populate() and must be freed
 * by the caller (with rx_opaque_freeContents()).
 *
 * @param[in] key	The key to use for the decryption.
 * @param[in] usage	The key usage used for the encryption.
 * @param[in] in	The encrypted message.
 * @param[out] out	The decrypted message.
 * @return rxgk error codes.
 */
afs_int32
rxgk_decrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
		    RXGK_Data *out)
{
    krb5_crypto crypto = NULL;
    krb5_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = (struct rxgk_keyblock *)key;

    memset(out, 0, sizeof(*out));
    memset(&kd_out, 0, sizeof(kd_out));

    enctype = deref_keyblock_enctype(&keyblock->key);
    ret = krb5_crypto_init(keyblock->ctx, &keyblock->key, enctype, &crypto);
    if (ret != 0)
	goto done;
    ret = krb5_decrypt(keyblock->ctx, crypto, usage, in->val, in->len, &kd_out);
    if (ret != 0)
	goto done;
    ret = rx_opaque_populate(out, kd_out.data, kd_out.length);

 done:
    if (crypto != NULL)
	krb5_crypto_destroy(keyblock->ctx, crypto);
    krb5_data_free(&kd_out);
    return ktor(ret);
}

/*
 * Helper for derive_tk.
 * Assumes the caller has already allocated space in 'out'.
 */
static afs_int32
PRFplus(krb5_data *out, krb5_enctype enctype, rxgk_key k0,
	void *seed, size_t seed_len)
{
    krb5_crypto crypto = NULL;
    krb5_data prf_in, prf_out;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = k0;
    unsigned char *pre_key = NULL;
    size_t block_len;
    size_t desired_len = out->length;
    afs_uint32 n_iter, iterations, dummy;

    memset(&prf_in, 0, sizeof(prf_in));
    memset(&prf_out, 0, sizeof(prf_out));

    ret = krb5_crypto_init(keyblock->ctx, &keyblock->key, enctype, &crypto);
    if (ret != 0)
	goto done;
    prf_in.data = rxi_Alloc(sizeof(n_iter) + seed_len);
    if (prf_in.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }
    prf_in.length = sizeof(n_iter) + seed_len;
    memcpy((unsigned char *)prf_in.data + sizeof(n_iter), seed, seed_len);
    ret = krb5_crypto_prf_length(keyblock->ctx, enctype, &block_len);
    if (ret != 0)
	goto done;
    /* We need desired_len/block_len iterations, rounded up. */
    iterations = (desired_len + block_len - 1) / block_len;
    pre_key = rxi_Alloc(iterations * block_len);
    if (pre_key == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }

    for(n_iter = 1; n_iter <= iterations; ++n_iter) {
	dummy = htonl(n_iter);
	memcpy(prf_in.data, &dummy, sizeof(dummy));
	krb5_data_free(&prf_out);
	ret = krb5_crypto_prf(keyblock->ctx, crypto, &prf_in, &prf_out);
	if (ret != 0)
	    goto done;
	memcpy(pre_key + (n_iter - 1) * block_len, prf_out.data, block_len);
    }
    memcpy(out->data, pre_key, desired_len);
    out->length = desired_len;

 done:
    if (crypto != NULL)
	krb5_crypto_destroy(keyblock->ctx, crypto);
    krb5_data_free(&prf_out);
    rxi_Free(prf_in.data, sizeof(n_iter) + seed_len);
    if (pre_key != NULL)
	rxi_Free(pre_key, iterations * block_len);
    return ktor(ret);
}

struct seed_data {
    afs_uint32 epoch;
    afs_uint32 cid;
    afs_uint32 time_hi;
    afs_uint32 time_lo;
    afs_uint32 key_number;
} __attribute__((packed));
/**
 * Compute a transport key tk given a master key k0
 *
 * Given a connection master key k0, derive a transport key tk from the master
 * key and connection parameters.
 *
 * TK = random-to-key(PRF+(K0, L, epoch || cid || start_time || key_number))
 * using the RFC4402 PRF+, i.e., the ordinal of the application of the
 * pseudo-random() function is stored in a 32-bit field, not an 8-bit field
 * as in RFC6112.
 *
 * @param[out] tk		The derived transport key.
 * @param[in] k0		The token master key.
 * @param[in] epoch		The rx epoch of the connection.
 * @param[in] cid		The rx connection id of the connection.
 * @param[in] start_time	The start_time of the connection.
 * @param[in] key_number	The current key number of the connection.
 * @return rxgk error codes.
 */
afs_int32
rxgk_derive_tk(rxgk_key *tk, rxgk_key k0, afs_uint32 epoch, afs_uint32 cid,
	       rxgkTime start_time, afs_uint32 key_number)
{
    krb5_enctype enctype;
    krb5_data pre_key;
    struct rxgk_keyblock *keyblock = k0;
    struct seed_data seed;
    ssize_t ell;
    afs_int32 ret;

    memset(&pre_key, 0, sizeof(pre_key));
    memset(&seed, 0, sizeof(seed));

    opr_StaticAssert(sizeof(seed) == 20);
    enctype = deref_keyblock_enctype(&keyblock->key);
    ell = etype_to_len(enctype);
    if (ell < 0)
	return RXGK_INCONSISTENCY;

    seed.epoch = htonl(epoch);
    seed.cid = htonl(cid);
    seed.time_hi = htonl((afs_int32)(start_time / ((afs_int64)1 << 32)));
    seed.time_lo = htonl((afs_uint32)(start_time & (afs_uint64)0xffffffffu));
    seed.key_number = htonl(key_number);

    pre_key.data = rxi_Alloc(ell);
    if (pre_key.data == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }
    pre_key.length = ell;
    ret = PRFplus(&pre_key, enctype, k0, &seed, sizeof(seed));
    if (ret != 0)
	goto done;

    ret = rxgk_make_key(tk, pre_key.data, ell, enctype);
    if (ret != 0)
	goto done;

 done:
    rxi_Free(pre_key.data, ell);
    return ret;
}

/**
 * Determine the maximum ciphertext expansion for a given enctype.
 *
 * @param[in] k0	The rxgk key to be used.
 * @param[out] len_out	The maximum ciphertext expansion, in octets.
 * @return rxgk error codes.
 */
afs_int32
rxgk_cipher_expansion(rxgk_key k0, afs_uint32 *len_out)
{
    krb5_crypto crypto = NULL;
    krb5_enctype enctype;
    krb5_error_code ret;
    struct rxgk_keyblock *keyblock = k0;
    size_t len;

    *len_out = 0;

    enctype = deref_keyblock_enctype(&keyblock->key);
    ret = krb5_crypto_init(keyblock->ctx, &keyblock->key, enctype, &crypto);
    if (ret != 0)
	goto done;
    len = krb5_crypto_overhead(keyblock->ctx, crypto);
    *len_out = len;

 done:
    if (crypto != NULL)
	krb5_crypto_destroy(keyblock->ctx, crypto);
    return ktor(ret);
}

/**
 * Allocate and fill the buffer in nonce with len bytes of random data.
 *
 * @param[out] nonce	The buffer of random data.
 * @param[in] len	The number of octets of random data to produce.
 * @return rx error codes.
 */
afs_int32
rxgk_nonce(RXGK_Data *nonce, afs_uint32 len)
{

    if (rx_opaque_alloc(nonce, len) != 0)
	return RXGK_INCONSISTENCY;

    krb5_generate_random_block(nonce->val, len);
    return 0;
}

/**
 * Apply KRB-FX-CF2 as for RXGK_CombineTokens and RXGK_AFSCombineTokens
 *
 * Given two rxgk keys, combine them using the KRB-FX-CF2 algorithm with
 * the pepper strings specified for this use in rxgk, producing a third
 * key which is not determinable unless both input keys are known.
 *
 * The caller must free kn with rxgk_release_key().
 *
 * @param[in] k0	The first key to be combined.
 * @param[in] k1	The second key to be combined.
 * @param[in] enctype	The enctype of the kn to be produced.
 * @param[out] kn	The output key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_combine_keys(rxgk_key k0, rxgk_key k1, afs_int32 enctype, rxgk_key *kn_out)
{
    krb5_crypto c0 = NULL, c1 = NULL;
    krb5_data pepper0, pepper1;
    krb5_enctype e0, e1;
    struct rxgk_keyblock *kb0 = k0;
    struct rxgk_keyblock *kb1 = k1;
    struct rxgk_keyblock *kbn = NULL;
    rxgk_key kn = NULL;
    afs_int32 ret;

    *kn_out = NULL;
    memset(&pepper0, 0, sizeof(pepper0));
    memset(&pepper1, 0, sizeof(pepper1));

    e0 = deref_keyblock_enctype(&kb0->key);
    e1 = deref_keyblock_enctype(&kb1->key);
    ret = krb5_crypto_init(kb0->ctx, &kb0->key, e0, &c0);
    if (ret != 0)
	goto done;
    ret = krb5_crypto_init(kb1->ctx, &kb1->key, e1, &c1);
    if (ret != 0)
	goto done;
    kbn = rxi_Alloc(sizeof(*kbn));
    if (kbn == NULL) {
	ret = RXGK_INCONSISTENCY;
	goto done;
    }
    kn = kbn;
    ret = krb5_init_context(&kbn->ctx);
    if (ret != 0)
	goto done;
    pepper0.data = "AFS";
    pepper0.length = 3;
    pepper1.data = "rxgk";
    pepper1.length = 4;
    ret = krb5_crypto_fx_cf2(kb0->ctx, c0, c1, &pepper0, &pepper1, enctype,
			     &kbn->key);
    if (ret != 0)
	goto done;
    *kn_out = kbn;
    kbn = kn = NULL;

 done:
    if (c0 != NULL)
	krb5_crypto_destroy(kb0->ctx, c0);
    if (c1 != NULL)
	krb5_crypto_destroy(kb1->ctx, c1);
    rxgk_release_key(&kn);
    return ret;
}

/**
 * Apply KRB-FX-CF2 on keys as RXGK_Data
 *
 * Take the raw key data from k[01]_data, for keys of enctypes e[01],
 * and perform the KRB-FX-CF2 combination algorithm to yield the new
 * key with raw key data in kn of enctype en.
 * The caller must free the storage in *kn_data.
 *
 * @param[in] k0_data	The raw bytes as input data for the first key.
 * @param[in] e0	The enctype of the first key to be combined.
 * @param[in] k1_data	The raw bytes as input data for the second key.
 * @param[in] e1	The enctype of the second key to be combined.
 * @param[out] kn_data	The raw bytes of the output key.
 * @param[in] en	The enctype of the output key.
 * @return rxgk error codes.
 */
afs_int32
rxgk_combine_keys_data(RXGK_Data *k0_data, afs_int32 e0, RXGK_Data *k1_data,
		       afs_int32 e1, RXGK_Data *rkn_data, afs_int32 en)
{
    struct rxgk_keyblock *kbn;
    rxgk_key k0 = NULL, k1 = NULL, kn = NULL;
    afs_int32 ret;

    memset(rkn_data, 0, sizeof(*rkn_data));

    ret = rxgk_make_key(&k0, k0_data->val, k0_data->len, e0);
    if (ret != 0)
	goto done;
    ret = rxgk_make_key(&k1, k1_data->val, k1_data->len, e1);
    if (ret != 0)
	goto done;
    ret = rxgk_combine_keys(k0, k1, en, &kn);
    if (ret != 0)
	goto done;
    kbn = kn;
    ret = rx_opaque_populate(rkn_data, kbn->key.keyvalue.data,
			     kbn->key.keyvalue.length);

 done:
    rxgk_release_key(&k0);
    rxgk_release_key(&k1);
    rxgk_release_key(&kn);
    return ret;
}
