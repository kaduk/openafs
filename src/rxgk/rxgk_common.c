/* rxgk/rxgk_common.c - Security object routines common to client and server */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
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
 * Security object routines common to client and server
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

/* OS-specific system headers go here */

#include <rx/rx.h>
#include <rx/rx_packet.h>
#include <rx/xdr.h>

#include "rxgk_private.h"

/* Discard the security object, freeing resources */
int
rxgk_Close(struct rx_securityClass *aobj)
{
    /* XXXBJK */
    return 0;
}

/* Create a new connection */
int
rxgk_NewConnection(struct rx_securityClass *aobj,
		   struct rx_connection *aconn)
{
    /* XXXBJK */
    return 0;
}

/* Destroy a connection, freeing resources */
int
rxgk_DestroyConnection(struct rx_securityClass *aobj,
		       struct rx_connection *aconn)
{
    /* XXXBJK */
    return 0;
}

/* Decode a packet from the wire format */
int
rxgk_CheckPacket(struct rx_securityClass *aobj, struct rx_call *acall,
		 struct rx_packet *apacket)
{
    /* XXXBJK */
    return 0;
}

/* Encode a packet to go on the wire */
int
rxgk_PreparePacket(struct rx_securityClass *aobj, struct rx_call *acall,
		   struct rx_packet *apacket)
{
    /* XXXBJK */
    return 0;
}

/* Retrieve statistics about this connection */
int
rxgk_GetStats(struct rx_securityClass *aobj, struct rx_connection *aconn,
	      struct rx_securityObjectStats *astats)
{
    /* XXXBJK */
    return 0;
}
