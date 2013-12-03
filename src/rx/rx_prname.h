/* rx/rx_prname.h - Helpers for PrAuthName manipulation */
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
 * Declarations for routines to copy, create, compare, free, etc.
 * objects of type PrAuthName.
 */

#ifndef RX_PRNAME_H
#define RX_PRNAME_H

struct PrAuthName {
    afs_int32 kind;
    struct rx_opaque data;
    struct rx_opaque display;
};
typedef struct PrAuthName PrAuthName;

PrAuthName *rx_prname_new(void *data, size_t datalen, void *display,
			  size_t displaylen, afs_int32 kind);
PrAuthName *rx_prname_copyalloc(PrAuthName *in);
afs_int32 rx_prname_copy(PrAuthName *out, PrAuthName *in);
PrAuthName *rx_prnamelist_copyalloc(PrAuthName *in, size_t len);
afs_int32 rx_prnamelist_copy(PrAuthName *out, PrAuthName *in, size_t len);
void rx_prname_freeContents(PrAuthName *name);
void rx_prnamelist_freeContents(PrAuthName *name, size_t len);

#endif /* RX_PRNAME_H */
