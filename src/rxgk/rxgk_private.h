/* rxgk_prototypes.h - Declarations of RXGK-internal routines */
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
 * Prototypes for routines internal to RXGK.
 */

#ifndef RXGK_PROTOTYPES_H
#define RXGK_PROTOTYPES_H

typedef enum {
    RXGK_CLIENT,
    RXGK_SERVER,
    RXGK_DEAD
} rxgk_type;


/*
 * rgxk_server.c
 */

/*
 * type is common to client and server, and must be aliasable.
 * Per-connection flags, and a way to get a decryption key for what the client
 * sends us.
 */
struct rxgk_sprivate {
    rxgk_type type;
    afs_int32 flags;
    void *rock;
    rxgk_getkey_func getkey;
};

int rxgk_CheckAuthentication(struct rx_securityClass *aobj,
			     struct rx_connection *aconn);
int rxgk_CreateChallenge(struct rx_securityClass *aobj,
			 struct rx_connection *aconn);
int rxgk_GetChallenge(struct rx_securityClass *aobj,
		      struct rx_connection *aconn, struct rx_packet *apacket);
int rxgk_CheckResponse(struct rx_securityClass *aobj,
		       struct rx_connection *aconn, struct rx_packet *apacket);
int rxgk_SetConfiguration(struct rx_securityClass *aobj,
			  struct rx_connection *aconn,
			  rx_securityConfigVariables atype,
			  void *avalue, void **currentValue);

/*
 * rxgk_common.c
 */

int rxgk_Close(struct rx_securityClass *aobj);
int rxgk_NewConnection(struct rx_securityClass *aobj,
		       struct rx_connection *aconn);
int rxgk_DestroyConnection(struct rx_securityClass *aobj,
			   struct rx_connection *aconn);
int rxgk_CheckPacket(struct rx_securityClass *aobj, struct rx_call *acall,
		     struct rx_packet *apacket);
int rxgk_PreparePacket(struct rx_securityClass *aobj, struct rx_call *acall,
		       struct rx_packet *apacket);
int rxgk_GetStats(struct rx_securityClass *aobj, struct rx_connection *aconn,
		  struct rx_securityObjectStats *astats);

/*
 * rxgk_client.c
 */
int rxgk_GetResponse(struct rx_securityClass *aobj,
		     struct rx_connection *aconn, struct rx_packet *apacket);

#endif /* RXGK_PROTOTYPES_H */
