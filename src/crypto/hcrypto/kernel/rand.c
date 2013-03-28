/* A trivial implementation of hcrypto's RAND interface for
 * kernel use */

#include <config.h>
#include <evp.h>
#include <evp-hcrypto.h>
#include <aes.h>
#include <sha.h>

const RAND_METHOD *hc_rand_unix_method = NULL;

/* This mutex is used to synchronize hcrypto operations in the kernel. */
afs_kmutex_t hckernel_mutex;

void
RAND_seed(const void *indata, size_t size)
{
#if 1 || defined(AFS_AIX_ENV) || defined(AFS_DFBSD_ENV) || defined(AFS_HPUX_ENV) || defined(AFS_SGI_ENV) || defined(UKERNEL)
    const RAND_METHOD *m = RAND_fortuna_method();
    m->seed(indata, size);
#else
    /* Do nothing; we use the kernel's RNG */
    return;
#endif
}

int
RAND_bytes(void *outdata, size_t size)
{
    if (size == 0)
	return 0;
#if 1 || defined(AFS_AIX_ENV) || defined(AFS_DFBSD_ENV) || defined(AFS_HPUX_ENV) || defined(AFS_SGI_ENV) || defined(UKERNEL)
    const RAND_METHOD *m = RAND_fortuna_method();
    return m->bytes(outdata, size);
#else
    if (osi_readRandom(outdata, size))
	return 0;
#endif
    return 1;
}
