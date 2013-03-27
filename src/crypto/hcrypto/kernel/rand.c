/* A trivial implementation of hcrypto's RAND interface for
 * kernel use */

#include <config.h>
#include <evp.h>
#include <evp-hcrypto.h>
#include <aes.h>
#include <sha.h>

void
RAND_seed(const void *indata, size_t size)
{
#if defined(AFS_AIX_ENV) || defined(AFS_DFBSD_ENV) || defined(AFS_HPUX_ENV) || defined(AFS_SGI_ENV) || defined(UKERNEL)
    RAND_METHOD *m = RAND_fortuna_method();
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
#if defined(AFS_AIX_ENV) || defined(AFS_DFBSD_ENV) || defined(AFS_HPUX_ENV) || defined(AFS_SGI_ENV) || defined(UKERNEL)
    RAND_METHOD *m = RAND_fortuna_method();
    return m->bytes(outdata, size);
#else
    if (osi_readRandom(outdata, size))
	return 0;
#endif
    return 1;
}
