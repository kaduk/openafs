#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <err.h>

/* Need to get some of the static functions, for testing. */
#include "rxgk_crypto_rfc3961.c"

int main(void)
{
    rxgk_key k0, k1;
    krb5_data outbuf;
    unsigned char storage[32];
    afs_int32 ret;

    outbuf.data = storage;

    /* test 1 */
    ret = rxgk_make_key(&k0, 
	    "\xae\x27\x2e\x7c\xde\xc8\x6a\xc5\x13\x8c\xdb\x19\x6d\x8e\x29\x7d",
	    16, 17);
    if (ret != 0)
	errx(1, "Couldn't make test1 key");
    ret = PRFplus(&outbuf, 17, k0, 12,
	    "\x00\x03\x06\x09\x0C\x0F\x12\x15\x18\x1B\x1E\x21\x24\x27\x2A\x2D"
	    "\x30\x33\x36\x39\x3C\x3F\x42\x45", 24);
    if (ret != 0)
	errx(1, "PRFplus failed for test1");
    if (outbuf.length != 12 || memcmp(outbuf.data,
	    "\x44\x96\x17\x09\x26\x2a\xf9\xd5\x26\x18\x86\xa9", 12) != 0)
	errx(1, "test1 produced the wrong output");

    /* test 2 */
    ret = rxgk_make_key(&k1,
	    "\x67\xab\x1c\xfe\xf3\x5e\x4c\x27\xff\xde\xac\x60\x38\x5a\x3e\x9c",
	    16, 17);
    if (ret != 0)
	errx(1, "couldn't make test2 key");
    ret = PRFplus(&outbuf, 17, k1, 32,
	    "\x00\x03\x06\x09\x0C\x0F\x12\x15\x18\x1B\x1E\x21\x24\x27\x2A\x2D"
	    "\x30\x33\x36\x39\x3C\x3F\x42\x45", 24);
    if (ret != 0)
	errx(1, "PRFplus failed for test2");
    if (outbuf.length != 32 || memcmp(outbuf.data,
	    "\xa2\x78\xf9\x7a\x10\x2c\xa8\x09\x6f\x1a\x26\x08\xe1\x6c\xa0\x79"
	    "\xc9\xb4\x63\x10\x29\xd9\x07\x42\xd9\x27\xbf\xc7\x55\xf0\x3d\x1e",
	    32) != 0)
	errx(1, "test2 produced the wrong output");

    return 0;
}
