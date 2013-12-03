/* rxgk/prauthname.c - Routines for manipulating PrAuthName objects */
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
 * Utility routines relating to objects of type PrAuthName.
 * Provide for comparing, copying, freeing, etc., such objects.
 */

#include <afsconfig.h>
#include <afs/param.h>

#ifndef KERNEL
# include <roken.h>
#else
# include "afs/sysincludes.h"
# include "afsincludes.h"
#endif

#include <rx/rx.h>
#include <rx/rx_opaque.h>
#include <rx/rx_prname.h>

PrAuthName *
rx_prname_new(void *data, size_t datalen, void *display, size_t displaylen,
	      afs_int32 kind)
{
    PrAuthName *tmp;
    int code;

    tmp = rxi_Alloc(sizeof(*tmp));
    if (tmp == NULL)
	return NULL;
    code = rx_opaque_populate(&tmp->data, data, datalen);
    if (code != 0)
	goto cleanup;
    code = rx_opaque_populate(&tmp->display, display, displaylen);
    if (code != 0)
	goto cleanup;
    tmp->kind = kind;
    return tmp;
cleanup:
    rx_prname_freeContents(tmp);
    return NULL;
}

PrAuthName *
rx_prname_copyalloc(PrAuthName *in)
{
    PrAuthName *tmp;

    tmp = rxi_Alloc(sizeof(*tmp));
    if (tmp == NULL)
	return NULL;
    if (rx_prname_copy(tmp, in) != 0) {
	rxi_Free(tmp, sizeof(*tmp));
	return NULL;
    }
    return tmp;
}

afs_int32
rx_prname_copy(PrAuthName *out, PrAuthName *in)
{
    int ret;

    memset(out, 0, sizeof(*out));
    
    ret = rx_opaque_copy(&out->data, &in->data);
    if (ret != 0)
	goto cleanup;
    ret = rx_opaque_copy(&out->display, &in->display);
    if (ret != 0)
	goto cleanup;
    out->kind = in->kind;
    return 0;

cleanup:
    rx_prname_freeContents(out);
    return ret;
}

/*
 * Returns 1 if two PrAuthNames are the same identity.
 * Returns 0 if otherwise, or an error occurs.
 * Do not permit zero-length or empty (NULL) identities to compare as equal,
 * for security.  rxgk printed tokens use empty identities.
 */
afs_int32
rx_prname_equal(PrAuthName *n1, PrAuthName *n2)
{
    if (n1 == NULL || n2 == NULL)
	return 0;
    if (n1->data.len == n2->data.len && n1->data.len != 0 &&
	memcmp(n1->data.val, n2->data.val, n1->data.len) == 0)
	return 1;
    return 0;
}

/*
 * Get the display (printable) form of a name.
 * Returns 0 on success.  On success, *out is set to a NUL-terminated
 * string with the display name.  out must be freed by the caller,
 * with rx_prname_display_free().
 */
afs_int32
rx_prname_display(PrAuthName *name, char **out)
{
    char *tmp;

    *out = NULL;
    tmp = rxi_Alloc(name->display.len + 1);
    if (tmp == NULL)
	return ENOMEM;
    memcpy(tmp, name->display.val, name->display.len);
    tmp[name->display.len] = '\0';
    *out = tmp;
    return 0;
}

PrAuthName *
rx_prnamelist_copyalloc(PrAuthName *in, size_t len)
{
    PrAuthName *tmp;

    tmp = rxi_Alloc(len * sizeof(*in));
    if (tmp == NULL)
	return NULL;
    if (rx_prnamelist_copy(tmp, in, len) != 0) {
	rxi_Free(tmp, sizeof(*tmp));
	return NULL;
    }
    return tmp;
}

afs_int32
rx_prnamelist_copy(PrAuthName *out, PrAuthName *in, size_t len)
{
    int ret;
    size_t i;

    /* A bit dubious, but there should be some check here to avoid overflow
     * when size_t is 32 bits and to avoid excessive resource use otherwise. */
    if (len > 1024 * 1024)
	return EOVERFLOW;
    memset(out, 0, len * sizeof(*out));
    for(i = 0; i < len; ++i) {
	ret = rx_prname_copy(out + i, in + i);
	if (ret != 0)
	    goto cleanup;
    }
    return 0;

cleanup:
    for(i = 0; i < len; ++i)
	rx_prname_freeContents(in + i);
    return ret;
}

/*
 * Returns 1 if to lists of PrAuthNames represent the same identities in
 * the same order, that is, the same "compound identity".
 * Returns 0 if otherwise or an error occurs.
 * Lists of length zero do not compare as equal, for security.
 */
afs_int32
rx_prnamelist_equal(PrAuthName *n1, size_t l1, PrAuthName *n2, size_t l2)
{
    size_t i;

    if (l1 != l2 || l1 == 0 || n1 == NULL || n2 == NULL)
	return 0;
    for(i = 0; i < l1; ++i)
	if (rx_prname_equal(n1 + i, n2 + i) == 0)
	    return 0;
    return 1;
}

/*
 * Convert a list of PrAuthNames into a displayable string.
 * Returns 0 on success; *out is populated with the NUL-terminated string.
 * On success, the caller is responsible for freeing out with
 * rx_prname_display_free().
 * Zero-length lists cannot be displayed, and will return an error.
 * Individual components of the list are separated by a ':'.
 */
afs_int32
rx_prnamelist_display(PrAuthName *names, size_t len, char **out)
{
    char *tmp, *p;
    size_t total, i;

    *out = NULL;
    if (len == 0)
	return RX_EOF;
    total = 0;
    for(i = 0; i < len; ++i)
	total += names[i].display.len;
    tmp = rxi_Alloc(total + len + 1);	/* separator; NUL terminated */
    if (tmp == NULL)
	return ENOMEM;
    p = tmp;
    for(i = 0; i < len; ++i) {
	memcpy(p, names[i].display.val, names[i].display.len);
	p += names[i].display.len;
	*p++ = ':';
    }
    tmp[total] = '\0';
    return 0;
}

void
rx_prname_freeContents(PrAuthName *name)
{
    rx_opaque_freeContents(&name->data);
    rx_opaque_freeContents(&name->display);
    name->kind = 0;
}

void
rx_prnamelist_freeContents(PrAuthName *name, size_t len)
{
    size_t i;

    for(i = 0; i < len; ++i)
	rx_prname_freeContents(name + i);
}

void
rx_prname_display_free(char **name)
{
    size_t len;

    if (name == NULL || *name == NULL)
	return;
    len = strlen(*name) + 1;
    rxi_Free(*name, len);
    *name = NULL;
}
