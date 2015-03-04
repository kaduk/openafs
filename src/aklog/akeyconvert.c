/* prototype/prototype.c - <<< One-line description of file >>> */
/* aklog/akeyconvert.c - migrate keys from rxkad.keytab to KeyFileExt */
/*
 * Copyright (C) 2015 by the Massachusetts Institute of Technology.
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
 * Helper for migrations from OpenAFS 1.6.x to OpenAFS 1.8.x when
 * the rxkad-k5 extension is in use.
 *
 * Read keys from the current rxkad.keytab and add them to the
 * KeyFileExt, creating it if necessary.  Detect duplicated
 * kvno/enctype keys, which are possible when attached to different
 * principals in the rxkad.keytab, but are not possible in the
 * KeyFileExt.
 *
 * The implementation reads the entire keytab contents into memory,
 * then successively sorts by principal, kvno, and enctype (using
 * a stable sort for the latter two) to facilitate selecting the
 * newest kvno for each principal and avoiding duplicate kvno/enctype
 * values.  The direction of sort is chosen so as to hopefully put
 * the more often used keys at the beginning of the file.
 *
 * By default, only copy the latest key for each principal, but
 * provide an option to copy all keys.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <sys/errno.h>
#include <string.h>

#include <afs/cellconfig.h>
#include <afs/dirpath.h>
#include <afs/keys.h>
#include <afs/opr.h>

#include <stdio.h>

#define KERBEROS_APPLE_DEPRECATED(x)
#include <krb5/krb5.h>
#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#elif HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#elif HAVE_KRB5_COM_ERR_H
# include <krb5/com_err.h>
#else
# error com_err is required for akeyconvert
#endif

/* XXX MIT-specific */
#if 0
#define	deref_entry_keylen(x)	((x).key.length)
#define	deref_entry_keyval(x)	((x).key.contents)
#define	deref_entry_enctype(x)	((x).key.enctype)
#else
#define deref_entry_keylen(x)	((x).keyblock.keyvalue.length)
#define deref_entry_keyval(x)	((x).keyblock.keyvalue.data)
#define deref_entry_enctype(x)	((x).keyblock.keytype)
#endif

/*
 * Convert keytab entry to the AFS typedKey format, allocating
 * storage for the output.
 *
 * Returns 0 on success.
 */
static afs_int32
ktent_to_typedKey(krb5_keytab_entry entry, struct afsconf_typedKey **out)
{
    struct rx_opaque key;
    afs_int32 enctype;

    key.len = deref_entry_keylen(entry);
    key.val = deref_entry_keyval(entry);
    enctype = deref_entry_enctype(entry);
    if (enctype == 1 /* ETYPE_DES_CBC_CRC */ ||
	enctype == 2 /* ETYPE_DES_CBC_MD4 */ ||
	enctype == 3 /* ETYPE_DES_CBC_MD5 */) {
	*out = afsconf_typedKey_new(afsconf_rxkad, entry.vno, 0, &key);
	if (*out == NULL)
	    return ENOMEM;
	else
	    return 0;
    }
    /* else, an rxkad_krb5 key */
    *out = afsconf_typedKey_new(afsconf_rxkad_krb5, entry.vno,
				deref_entry_enctype(entry),
				&key);
    if (*out == NULL)
	return ENOMEM;
    else
	return 0;
}

static void
usage(void)
{
    fprintf(stderr, "usage: akeyconvert [-all]\n");
    exit(1);
}

static int
princ_sort(const void *aa, const void *bb)
{
    const krb5_keytab_entry *a, *b;
    char *name1 = NULL, *name2 = NULL;
    krb5_boolean equal;
    krb5_context ctx;
    int ret;

    a = aa;
    b = bb;

    opr_Verify(krb5_init_context(&ctx) == 0);
    equal = krb5_principal_compare(ctx, a->principal, b->principal);
    if (equal) {
	ret = 0;
	goto out;
    }
    opr_Verify(krb5_unparse_name(ctx, a->principal, &name1) == 0);
    opr_Verify(krb5_unparse_name(ctx, b->principal, &name2) == 0);
    ret = strcmp(name1, name2);
    if (ret != 0)
	goto out;

    /* We shouldn't get here, but cannot return equality even if we do. */
    if (a < b)
	ret = -1;
    else
	ret = 1;
out:
    krb5_free_unparsed_name(ctx, name1);
    krb5_free_unparsed_name(ctx, name2);
    krb5_free_context(ctx);
    return ret;
}

static int
kvno_sort(const void *aa, const void *bb)
{
    const krb5_keytab_entry *a, *b;

    a = aa;
    b = bb;

    if (a->vno == b->vno)
	return 0;
    else if (a->vno > b->vno)
	return -1;
    else
	return 1;
}

static int
etype_sort(const void *aa, const void *bb)
{
    const krb5_keytab_entry *a, *b;

    a = aa;
    b = bb;

    if (deref_entry_enctype(*a) == deref_entry_enctype(*b))
	return 0;
    else if (deref_entry_enctype(*a) > deref_entry_enctype(*b))
	return -1;
    else
	return 1;
}

static afs_int32
slurp_keytab(krb5_context ctx, char *kt_path, krb5_keytab_entry **ents_out,
	     int *nents)
{
    krb5_keytab kt = NULL;
    krb5_keytab_entry entry, *ents;
    krb5_kt_cursor cursor = NULL;
    afs_int32 code;
    int n = 0, i;

    *ents_out = NULL;
    *nents = 0;

    code = krb5_kt_resolve(ctx, kt_path, &kt);
    if (code)
	return code;

    code = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (code != 0)
	goto out;
    while ((code = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
	++n;
	krb5_free_keytab_entry_contents(ctx, &entry);
    }
    krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (code != 0 && code != KRB5_KT_END)
	goto out;

    ents = calloc(n, sizeof(*ents));
    if (ents == NULL) {
	code = ENOMEM;
	goto out;
    }
    code = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (code != 0)
	goto out;
    i = 0;
    while ((code = krb5_kt_next_entry(ctx, kt, ents + i, &cursor)) == 0) {
	if (i++ == n) {
	    /* Out of space; bail early */
	    fprintf(stderr, "Warning: keytab size changed during processing\n");
	    break;
	}
    }
    krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (code != 0 && code != KRB5_KT_END)
	goto out;
    
    code = 0;
    *nents = n;
    *ents_out = ents;
out:
    krb5_kt_close(ctx, kt);
    return code;
}

/*
 * Sort the keytab by kvno and enctype.
 * This lets us detect duplicate kvno/enctype pairs that were usable
 * in rxkad.keytab but not representable in the KeyFileExt.
 */
static void
kesort_keytab(krb5_keytab_entry *ents, int nent)
{
    qsort(ents, nent, sizeof(*ents), &etype_sort);
    mergesort(ents, nent, sizeof(*ents), &kvno_sort);
}

/*
 * Check for duplicate kvno/enctype pairs (across different principals).
 *
 * This is a fatal error, but emit a diagnostic for all instances before
 * exiting.
 *
 * Requires the input array (ents) to be sorted by kvno and enctype.
 */
static afs_int32
check_dups(struct afsconf_dir *dir, krb5_keytab_entry *ents, int nents)
{
    int i, old_kvno = 0, old_etype = 0;
    afs_int32 code = 0;

    for (i = 0; i < nents; ++i) {
	if (old_kvno == ents[i].vno &&
	    old_etype == deref_entry_enctype(ents[i])) {
	    fprintf(stderr, "Duplicate kvno/enctype %i/%i\n", old_kvno,
		    old_etype);
	    code = AFSCONF_KEYINUSE;
	}
	old_kvno = ents[i].vno;
	old_etype = deref_entry_enctype(ents[i]);
    }
    if (code)
	fprintf(stderr, "FATAL: duplicate key identifiers found.\n");
    return code;
}

/*
 * Go through the list of keytab entries and write them to the KeyFileExt.
 *
 * If do_all is set, write all entries; otherwise, only write the highest
 * kvno for each principal.
 *
 * Emit a diagnostic for kvno/enctype pairs which are already in the
 * KeyFileExt (and thus cannot be added), but continue on.
 */
static afs_int32
convert_kt(struct afsconf_dir *dir, krb5_context ctx, krb5_keytab_entry *ents,
	   int nents, int do_all)
{
    int i, n;
    krb5_const_principal old_princ;
    struct afsconf_typedKey *key = NULL;
    afsconf_keyType type;
    afs_int32 best_kvno = 0, code;

#if HAVE_KRB5_ANONYMOUS_PRINCIPAL
    old_princ = krb5_anonymous_principal();
#elif HAVE_KRB5_MAKE_PRINCIPAL
    code = krb5_make_principal(ctx, &old_princ, KRB5_WELLKNOWN_REALM,
			       KRB5_WELLKNOWN_NAME, KRB5_ANON_NAME, NULL);
    if (code)
	goto out;
#else
# error "no way to produce sigil principal"
#endif
    n = 0;
    for (i = 0; i < nents; ++i) {
	if (!krb5_principal_compare(ctx, old_princ, ents[i].principal)) {
	    best_kvno = ents[i].vno;
	    printf("new best_kvno %i\n", best_kvno);
	}
	if (krb5_principal_compare(ctx, old_princ, ents[i].principal) &&
	    best_kvno != ents[i].vno && !do_all)
	    continue;
	old_princ = ents[i].principal;
	code = ktent_to_typedKey(ents[i], &key);
	if (code)
	    goto out;
	afsconf_typedKey_values(key, &type, NULL, NULL, NULL);
	if (type == afsconf_rxkad) {
	    fprintf(stderr,
		    "Cannot add single-DES keys to KeyFileExt, continuing\n");
	    continue;
	}
	code = afsconf_AddTypedKey(dir, key, 0);
	if (code == AFSCONF_KEYINUSE) {
	    fprintf(stderr,
		    "Key already exists for kvno %i enctype %i, continuing\n",
		    ents[i].vno, deref_entry_enctype(ents[i]));
	    continue;
	} else if (code) {
	    goto out;
	}
	n++;
	afsconf_typedKey_put(&key);
    }
    code = 0;
    printf("Wrote %i keys\n", n);
out:
    if (key != NULL)
	afsconf_typedKey_put(&key);
    return code;
}

int
main(int argc, char *argv[])
{
    char *kt_path = NULL;
    krb5_context ctx = NULL;
    krb5_keytab_entry *ents;
    struct afsconf_dir *dir;
    afs_int32 code;
    int do_all = 0, i, nents;

    /* parse arguments */
    for (i = 1; i < argc; ++i) {
	if (strcmp(argv[i], "-all") == 0)
	    do_all = 1;
	else
	    usage();
    }

    code = krb5_init_context(&ctx);
    if (code)
	return -1;

    dir = afsconf_Open(AFSDIR_SERVER_ETC_DIR);
    if (dir == NULL) {
	fprintf(stderr, "Failed to open server config directory\n");
	code = -1;
	goto out;
    }

    code = asprintf(&kt_path, "%s/%s", dir->name, AFSDIR_RXKAD_KEYTAB_FILE);
    if (code < 0) {
	kt_path = NULL;
	code = ENOMEM;
	goto out;
    }
    code = slurp_keytab(ctx, kt_path, &ents, &nents);
    if (code) {
	fprintf(stderr, "failed to read keytab\n");
	goto out;
    }

    kesort_keytab(ents, nents);

    /* Check for duplicates before sorting by prinipal. */
    code = check_dups(dir, ents, nents);
    if (code)
	goto out;

    mergesort(ents, nents, sizeof(*ents), &princ_sort);

    code = convert_kt(dir, ctx, ents, nents, do_all);
    if (code)
	goto out;

out:
    free(kt_path);
    krb5_free_context(ctx);
    afsconf_Close(dir);
    return code;
}
