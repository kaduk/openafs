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

#include <krb5.h>

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
	case KRB5_RCACHE_BADVNO:
	case KRB5_CCACHE_BADVNO:
	case KRB5_KEYTAB_BADVNO:
	case KRB5_BAD_ENCTYPE:
	    return RXGK_BADKEYNO;
	case KRB5_CRYPTO_INTERNAL:
	case KRB5_BAD_MSIZE:
	case KRB5_BADMSGTYPE:
	    return RXGK_SEALED_INCON;
	default:
	    return RXGK_INCONSISTENCY;
    }
}

/*
 * Hack of a function implementing the rxgk_getkey_func typedef.
 * Always uses a hardcoded "cell-wide" identity in a hardcoded file, loading
 * the key from file every time.
 */
afs_int32
dummy_getkey(void *rock, afs_int32 kvno, afs_int32 enctype, rxgk_key *key)
{
    if (kvno <= 0)
	return RXGK_BADKEYNO;
    if (enctype <= 0)
	return RXGK_BADETYPE;
    return get_server_key(key, &kvno, &enctype);
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
#ifdef HAVE_KRB5_INIT_KEYBLOCK
    /* free with krb5_free_keyblock */
    ret = krb5_init_keyblock(ctx, enctype, length, &new_key);
    if (ret != 0)
	goto out;
    memcpy(new_key->contents, raw_key, length);
#elif defined(HAVE_KRB5_KEYBLOCK_INIT)
    new_key = malloc(sizeof(*new_key));
    /* free with krb5_free_keyblock_contents + free */
    ret = krb5_keyblock_init(ctx, enctype, raw_key, length, new_key)
    if (ret != 0) {
	free(new_key);
	goto out;
    }
#else
#error "No RFC3961 implementation available"
#endif
    *key_out = (rxgk_key)new_key;
out:
    krb5_free_context(ctx);
    return ktor(ret);
}

/*
 * Get the long-term key of the AFS service principal for the cell, which
 * is afs-rxgk@_afs.[cellname] by default.  The location of the keytab
 * should be taken from the server configuration.  We attempt to extract
 * the specified kvno and enctype, unless zero is specified, when we extract
 * the default key/enctype from the keytab (what the krb5 library gives us).
 */
afs_int32
get_server_key(rxgk_key *key, afs_int32 *kvno, afs_int32 *enctype)
{
    krb5_context ctx;
    krb5_error_code ret;
    krb5_keyblock *keyblock;
    krb5_keytab keytab;
    krb5_keytab_entry entry;
    krb5_principal principal;

    *key = NULL;

    memset(&keytab, 0, sizeof(keytab));
    memset(&entry, 0, sizeof(entry));
    memset(&principal, 0, sizeof(principal));

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);
    ret = krb5_kt_resolve(ctx, "FILE:/Users/kaduk/openafs/perfluence.keytab",
			  &keytab);
    if (ret != 0)
	goto out;
    ret = krb5_parse_name(ctx, "afs-rxgk/_afs.perfluence.mit.edu", &principal);
    if (ret != 0)
	goto out;
    ret = krb5_kt_get_entry(ctx, keytab, principal, *kvno, *enctype, &entry);
    if (ret != 0)
	goto out;
    /* We have different memory-allocation agreements for MIT and Heimdal. */
#ifdef HAVE_KRB5_INIT_KEYBLOCK
    ret = krb5_copy_keyblock(ctx, &entry.key, &keyblock);
    if (ret != 0)
	goto out;
    *enctype = entry.key.enctype;
#elif defined(HAVE_KRB5_KEYBLOCK_INIT)
    keyblock = malloc(sizeof(*keyblock));
    if (keyblock == NULL)
	goto out;
    ret = krb5_copy_keyblock_contents(ctx, entry.keyblock, keyblock);
    if (ret != 0)
	goto out;
    *enctype = krb5_keyblock_get_enctype(&entry.keyblock);
#endif
    *kvno = entry.vno;

    *key = keyblock;
out:
    (void)krb5_free_keytab_entry_contents(ctx, &entry);
    krb5_free_principal(ctx, principal);
    (void)krb5_kt_close(ctx, keytab);
    krb5_free_context(ctx);
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
#ifdef HAVE_KRB5_INIT_KEYBLOCK
    krb5_free_keyblock(ctx, keyblock);
#elif defined(HAVE_KRB5_KEYBLOCK_INIT)
    krb5_free_keyblock_contents(ctx, keyblock)
    free(keyblock);
#endif
    krb5_free_context(ctx);
    *key = NULL;
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
    krb5_data kd_in;
    krb5_enc_data kd_out;
    krb5_enctype enctype;
    krb5_error_code ret;
    krb5_keyblock *keyblock = (krb5_keyblock *)key;
    size_t length;

    kd_in.data = NULL;
    kd_out.ciphertext.data = NULL;
    zero_rxgkdata(out);

    ret = krb5_init_context(&ctx);
    if (ret != 0)
	return ktor(ret);

    kd_in.length = in->len;
    kd_in.data = in->val;

#ifdef HAVE_KRB5_INIT_KEYBLOCK
    enctype = keyblock->enctype;
#elif defined(HAVE_KRB5_KEYBLOCK_INIT)
    enctype = krb5_keyblock_get_enctype(keyblock);
#endif

    ret = krb5_c_encrypt_length(ctx, enctype, in->len, &length);
    if (ret != 0)
	goto out;
    out->val = xdr_alloc(length);
    if (out->val == NULL) {
	ret = RXGK_INCONSISTENCY;	/* Should be something better, but... */
	goto out;
    }
    kd_out.ciphertext.length = length;
    kd_out.ciphertext.data = out->val;

    ret = krb5_c_encrypt(ctx, keyblock, usage, NULL, &kd_in, &kd_out);

out:
    krb5_free_context(ctx);
    return ktor(ret);
}
