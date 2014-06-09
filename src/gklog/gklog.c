/*
 * Copyright (C) 1990,1991,2014 by the Massachusetts Institute of Technology.
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

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <afs/ktc.h>
#include <afs/token.h>

#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <afs/venus.h>
#include <afs/dirpath.h>
#include <afs/afsutil.h>

#include <sys/errno.h>

#include <rx/rxgk.h>

/*
 * Why doesn't AFS provide these prototypes?
 */

extern int pioctl(char *, afs_int32, struct ViceIoctl *, afs_int32);

/*
 * Other prototypes
 */

static int
get_cellconfig(const char *config, char *cell,
	       struct afsconf_cell *cellconfig, char **local_cell)
{
    int status = 0;
    struct afsconf_dir *configdir;

    memset(cellconfig, 0, sizeof(*cellconfig));

    *local_cell = malloc(MAXCELLCHARS);
    if (*local_cell == NULL) {
	fprintf(stderr, "can't allocate memory for local cell name\n");
	exit(1);
    }

    if (!(configdir = afsconf_Open(config))) {
	fprintf(stderr,
		"can't get afs configuration (afsconf_Open(%s))\n",
		config);
	exit(1);
    }

    if (afsconf_GetLocalCell(configdir, *local_cell, MAXCELLCHARS)) {
	fprintf(stderr, "can't determine local cell.\n");
	exit(1);
    }

    if ((cell == NULL) || (cell[0] == 0))
	cell = *local_cell;

    /* XXX - This function modifies 'cell' by passing it through lcstring */
    if (afsconf_GetCellInfo(configdir, cell, NULL, cellconfig)) {
	fprintf(stderr, "Can't get information about cell %s.\n",
		cell);
	status = 1;
    }

    afsconf_Close(configdir);

    return(status);
}


/*
 * Log to a cell.  If the cell has already been logged to, return without
 * doing anything.  Otherwise, log to it and mark that it has been logged
 * to.
 */
static int
auth_to_cell(const char *config, struct afsconf_cell *cellconf, char *cell)
{
    struct ktc_tokenUnion rxgkToken;
    struct ktc_setTokenData *btoken;
    RXGK_TokenInfo info;
    struct rx_opaque token, k0;
    char *host;
    int code;

    memset(&rxgkToken, 0, sizeof(rxgkToken));
    btoken = NULL;

    /* First, try to get any existing tokens, so we can preserve any
     * rxkad tokens that might be sitting there. */
    code = ktc_GetTokenEx(cellconf->name, &btoken);
    if (code != 0 || btoken == NULL) {
	/* If that fails, just build a new one. */
	btoken = token_buildTokenJar(cellconf->name);
	if (btoken == NULL) {
	    code = ENOMEM;
	    goto out;
	}
    }

    code = asprintf(&host, "_afs.%s", cellconf->name);
    if (code < 0)
	goto out;
    code = rxgk_get_token("afs-rxgk", host,
			  cellconf->hostAddr[0].sin_addr.s_addr, htons(7003),
			  RXGK_LEVEL_CRYPT, &info, &k0, &token);
    if (code != 0)
	goto out;

    rxgkToken.ktc_tokenUnion_u.at_gk.gk_viceid = 0;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_enctype = info.enctype;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_level = info.level;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_lifetime = info.lifetime;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_bytelife = info.bytelife;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_expiration = info.expiration;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_k0.gk_k0_val = k0.val;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_k0.gk_k0_len = k0.len;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_token.gk_token_val = token.val;
    rxgkToken.ktc_tokenUnion_u.at_gk.gk_token.gk_token_len = token.len;
    rxgkToken.at_type = AFSTOKEN_UNION_GK;

    /* replace will replace any other rxgk token if present, or add
     * if none are found.  Exactly the right thing. */
    code = token_replaceToken(btoken, &rxgkToken);
    if (code) {
	printf("Add Token failed with %d\n", code);
	goto out;
    }

    code = ktc_SetTokenEx(btoken);
    if (code) {
	printf("failed to set token\n");
    }

out:
    return(code);
}

int
main(int argc, char *argv[])
{
    char *cell, *local_cell;
    struct afsconf_cell cellconf;
    int code;


    memset(&cellconf, 0, sizeof(cellconf));

    if (argc > 2) {
	printf("gklog can only log to one cell at a time\n");
	exit(1);
    }
    if (argc == 2) {
	cell = argv[1];
    } else {
	/* With no arguments, we log to the local cell. */
	cell = NULL;
    }
    code = rx_Init(0);
    if (code != 0) {
	printf("failed to initialize rx\n");
	exit(code);
    }
    get_cellconfig(AFSDIR_CLIENT_ETC_DIRPATH, cell, &cellconf, &local_cell);
    code = auth_to_cell(AFSDIR_CLIENT_ETC_DIRPATH, &cellconf, cell);
    if (code != 0) {
	printf("failed to authenticate to cell %s\n", cell);
	exit(code);
    }

    exit(code);
}
