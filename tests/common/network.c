#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/cellconfig.h>
#include <rx/rx.h>

#include <tests/tap/basic.h>
#include "common.h"

/*!
 * Check if the current machine's hostname resolves to the loopback
 * network.
 */
int
afstest_IsLoopbackNetworkDefault(void)
{
    char hostname[MAXHOSTCHARS];
    afs_uint32 addr;
    struct hostent *host;

    gethostname(hostname, sizeof(hostname));
    host = gethostbyname(hostname);
    memcpy(&addr, host->h_addr, sizeof(addr));

    return(rx_IsLoopbackAddr(ntohl(addr)));
}

/*!
 * Skips all TAP tests if the current machine's hostname resolves to the
 * loopback network.
 */
int
afstest_SkipTestsIfLoopbackNetIsDefault(void)
{
    int retval;

    retval = afstest_IsLoopbackNetworkDefault();
    if (retval == 1) {
	skip_all("Default IP address is on the loopback network!\n");
    }
    return retval;
}
