/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>


#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include "sample.h"

#define N_SECURITY_OBJECTS 1

static void Quit(char *);

int
main(int argc, char **argv)
{
    struct rx_securityClass *(securityObjects[N_SECURITY_OBJECTS]);
    struct rx_service *service;

    /* Initialize Rx, telling it port number this server will use for its single service */
    if (rx_Init(SAMPLE_SERVER_PORT) < 0)
	Quit("rx_init");

    /* Create a single security object, in this case the null security object, for unauthenticated connections, which will be used to control security on connections made to this server */
    securityObjects[RX_SECIDX_NULL] = rxnull_NewServerSecurityObject();
    if (securityObjects[RX_SECIDX_NULL] == (struct rx_securityClass *)0)
	Quit("rxnull_NewServerSecurityObject");

    /* Instantiate a single sample service.  The rxgen-generated procedure which is called to decode requests is passed in here (TEST_ExecuteRequest). */
    service =
	rx_NewService(0, SAMPLE_SERVICE_ID, "sample", securityObjects,
		      N_SECURITY_OBJECTS, TEST_ExecuteRequest);
    if (service == (struct rx_service *)0)
	Quit("rx_NewService");

    rx_StartServer(1);		/* Donate this process to the server process pool */
    Quit("StartServer returned?");

    return 0;
}

int
STEST_Add(struct rx_call *call, int a, int b, int *result)
{
    printf("TEST_Add(%d,%d)\n", a, b);
    *result = a + b;
    return 0;
}

int
STEST_Sub(struct rx_call *call, int a, int b, int *result)
{
    printf("TEST_Sub(%d,%d)\n", a, b);
    *result = a - b;
    return 0;
}

static void
Quit(char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(1);
}
