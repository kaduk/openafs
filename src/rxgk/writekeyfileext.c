#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int fd;
    ssize_t ret;
    unsigned char buf[80];

    fd = open("/Users/kaduk/etc/openafs/KeyFileExt", O_CREAT | O_RDWR, 0600);
    if (fd == -1) {
	printf("open failed\n");
	exit(1);
    }
    printf("got fd %i\n", (int)fd);
    memset(buf, 0, 48);
    buf[3] = 1;		/* version number */
    buf[7] = 1;		/* number of keys */
    buf[11] = 16;	/* meta-data length */
    buf[15] = 1;	/* type (rxgk) */
    buf[19] = 2;	/* kvno */
    buf[23] = 17;	/* enctype (aes128-sha1) */
    buf[27] = 16;	/* keylen */
    buf[28] = 0xZZ;	/* key data */
    buf[29] = 0xZZ;
    buf[30] = 0xZZ;
    buf[31] = 0xZZ;
    buf[32] = 0xZZ;
    buf[34] = 0xZZ;
    buf[35] = 0xZZ;
    buf[36] = 0xZZ;
    buf[37] = 0xZZ;
    buf[38] = 0xZZ;
    buf[39] = 0xZZ;
    buf[40] = 0xZZ;
    buf[41] = 0xZZ;
    buf[42] = 0xZZ;
    buf[42] = 0xZZ;
    buf[43] = 0xZZ;
    buf[44] = 0xZZ;
    buf[45] = 0xZZ;
    buf[46] = 0xZZ;
    buf[47] = 0xZZ;
    ret = write(fd, buf+4, 44);
    printf("write wrote %i bytes errno %i\n", (int)ret, errno);
    close(fd);
    return 0;
}
