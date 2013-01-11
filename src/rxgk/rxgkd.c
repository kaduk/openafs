/* rxgk/rxgkd.c - Standalone daemon for servicing RXGK RPCs */
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
 * Dummy standalone daemon for servicing RXGK RPCs.
 * This is a minimal implementation for use during development;
 * best practice is to have existing servers register the RXGK services
 * themselves.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <rx/rx.h>
#include <rx/rxgk.h>

int
main(int argc, char *argv[])
{
    struct rx_service *service;
    struct rx_securityClass *secobj;
    int ret;
    u_short port = 8888;
    u_short svc = 34567;

    ret = rx_Init(htons(port));
    if (ret != 0) {
	dprintf(2, "Could not initialize rx\n");
	exit(1);
    }

    secobj = rxnull_NewServerSecurityObject();

    service = rx_NewService(port, svc, "rxgkd", &secobj, 1 /* nSecObjs */,
			    RXGK_ExecuteRequest);
    if (service == NULL) {
	dprintf(2, "Registering service failed\n");
        exit(1);
    }

    rx_SetMinProcs(service, 2);
    rx_SetMaxProcs(service, 2);

    rx_StartServer(TRUE);

    dprintf(2, "rxgkd still running after StartServer\n");
    exit(0);
}
