/* rxgk/rxgk_util.c - utility functions for RXGK use */
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
 * Utility functions for RXGK use.  Includes routines to zero-fill
 * data types or create data types, as well as some processing that is
 * common to both clients and servers.
 */

#include <gssapi/gssapi.h>
#include <rx/rxgk.h>
#include <hcrypto/rand.h>

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

void
zero_rxgkdata(RXGK_Data *data)
{
    data->len = 0;
    data->val = NULL;
}

afs_uint32
rxgk_make_k0(afs_uint32 *minor_status, gss_ctx_id_t gss_ctx,
	     RXGK_Data *client_nonce, RXGK_Data *server_nonce, int enctype,
	     gss_buffer_t key)
{
    gss_buffer_desc seed;
    ssize_t len;
    afs_uint32 ret;

    len = etype_to_len(enctype);
    if (len == -1)
	return GSS_S_FAILURE;
    seed.length = client_nonce->len + server_nonce->len;
    seed.value = malloc(seed.length);
    if (seed.value == NULL)
	return GSS_S_FAILURE;
    memcpy(seed.value, client_nonce->val, client_nonce->len);
    memcpy(seed.value + client_nonce->len, server_nonce->val, server_nonce->len);

    ret = gss_pseudo_random(minor_status, gss_ctx, GSS_C_PRF_KEY_FULL,
			    &seed, len, key);

    free(seed.value);
    return ret;
}

afs_int32
rxgk_nonce(RXGK_Data *nonce, int len)
{

    zero_rxgkdata(nonce);
    nonce->val = xdr_alloc(len);
    if (nonce->val == NULL)
	return RXGEN_SS_MARSHAL;
    nonce->len = len;

    /* RAND_bytes returns 1 on success, sigh. */
    if (RAND_bytes(nonce->val, len) != 1) {
	dprintf(2, "no random data for server_nonce\n");
	return RXGEN_SS_MARSHAL;
    }
    return 0;
}

void
print_data(void *p, int len)
{
    unsigned char *data;
    unsigned char c;
    int i;

    data = p;
    for(i = 0; i < len; ++i) {
	c = *(data + i);
	if (isascii(c))
	    putchar(c);
	else
	    putchar('?');
    }
    printf("\n");
}
