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

#include <afs/procmgmt.h>
#include <roken.h>

#include <stddef.h>

#include <lwp.h>
#include <rx/rx.h>
#include <afs/audit.h>
#include <afs/afsutil.h>
#include <afs/fileutil.h>
#include <afs/opr.h>
#include <opr/lock.h>
#include <opr/queue.h>
#include <lock.h>

#include "bnode.h"
#include "bnode_internal.h"
#include "bosprototypes.h"

#ifndef WCOREDUMP
#define WCOREDUMP(x) ((x) & 0200)
#endif

#define BNODE_LWP_STACKSIZE	(16 * 1024)
#define BNODE_ERROR_COUNT_MAX   16   /* maximum number of retries */

#ifdef AFS_PTHREAD_ENV
static pthread_t bproc_pid;
static pthread_t sighand_pid;
static opr_cv_t bproc_cv;
static opr_mutex_t bproc_mutex;
#else
static PROCESS bproc_pid;	/**< pid of waker-upper */
#endif
struct opr_queue allBnodes;		/**< List of all bnodes */
struct Lock allBnodes_lock;
struct Lock newBnodes_lock;		/**< Protects head of bnode list */
static struct opr_queue allProcs;	/**< List of all processes for which we're waiting */
struct Lock allProcs_lock;
static struct opr_queue allTypes;	/**< List of all registered type handlers */

static struct bnode_stats {
    int weirdPids;
} bnode_stats;

extern const char *DoCore;
extern const char *DoPidFiles;
#ifndef AFS_NT40_ENV
extern char **environ;		/* env structure */
#endif

int hdl_notifier(struct bnode_proc *tp);
static int bnode_DeleteNoLock(struct bnode *abnode);
extern void bozo_insecureme(int sig);

/* Remember the name of the process, if any, that failed last */
static void
RememberProcName(struct bnode_proc *ap)
{
    struct bnode *tbnodep;

    tbnodep = ap->bnode;
    if (tbnodep->lastErrorName) {
	free(tbnodep->lastErrorName);
	tbnodep->lastErrorName = NULL;
    }
    if (ap->coreName)
	tbnodep->lastErrorName = strdup(ap->coreName);
}

/* utility for use by BOP_HASCORE functions to determine where a core file might
 * be stored.
 */
int
bnode_CoreName(struct bnode *abnode, char *acoreName, char *abuffer)
{
    if (DoCore) {
	strcpy(abuffer, DoCore);
	strcat(abuffer, "/");
	strcat(abuffer, AFSDIR_CORE_FILE);
    } else
	strcpy(abuffer, AFSDIR_SERVER_CORELOG_FILEPATH);
    if (acoreName) {
	strcat(abuffer, acoreName);
	strcat(abuffer, ".");
    }
    strcat(abuffer, abnode->name);
    return 0;
}

/* save core file, if any */
static void
SaveCore(struct bnode *abnode, struct bnode_proc
	 *aproc)
{
    char tbuffer[256];
    struct stat tstat;
    afs_int32 code = 0;
    char *corefile = NULL;
#ifdef BOZO_SAVE_CORES
    struct timeval Start;
    struct tm *TimeFields;
    char FileName[256];
#endif

    /* Linux always appends the PID to core dumps from threaded processes, so
     * we have to scan the directory to find core files under another name. */
    if (DoCore) {
	strcpy(tbuffer, DoCore);
	strcat(tbuffer, "/");
	strcat(tbuffer, AFSDIR_CORE_FILE);
    } else
	code = stat(AFSDIR_SERVER_CORELOG_FILEPATH, &tstat);
    if (code) {
        DIR *logdir;
        struct dirent *file;
        unsigned long pid;
	const char *coredir = AFSDIR_LOGS_DIR;

	if (DoCore)
	  coredir = DoCore;

	logdir = opendir(coredir);
        if (logdir == NULL)
            return;
        while ((file = readdir(logdir)) != NULL) {
            if (strncmp(file->d_name, "core.", 5) != 0)
                continue;
            pid = atol(file->d_name + 5);
            if (pid == aproc->pid) {
                asprintf(&corefile, "%s/%s", coredir, file->d_name);
                if (corefile == NULL) {
                    closedir(logdir);
                    return;
                }
                code = 0;
                break;
            }
        }
        closedir(logdir);
    } else {
	corefile = strdup(tbuffer);
    }
    if (code)
	return;

    bnode_CoreName(abnode, aproc->coreName, tbuffer);
#ifdef BOZO_SAVE_CORES
    FT_GetTimeOfDay(&Start, 0);
    TimeFields = localtime(&Start.tv_sec);
    sprintf(FileName, "%s.%d%02d%02d%02d%02d%02d", tbuffer,
	    TimeFields->tm_year + 1900, TimeFields->tm_mon + 1, TimeFields->tm_mday,
	    TimeFields->tm_hour, TimeFields->tm_min, TimeFields->tm_sec);
    strcpy(tbuffer, FileName);
#endif
    rk_rename(corefile, tbuffer);
    free(corefile);
}

int
bnode_GetString(struct bnode *abnode, char *abuffer,
		afs_int32 alen)
{
    return BOP_GETSTRING(abnode, abuffer, alen);
}

int
bnode_GetParm(struct bnode *abnode, afs_int32 aindex,
	      char *abuffer, afs_int32 alen)
{
    return BOP_GETPARM(abnode, aindex, abuffer, alen);
}

int
bnode_GetStat(struct bnode *abnode, afs_int32 * astatus)
{
    return BOP_GETSTAT(abnode, astatus);
}

int
bnode_RestartP(struct bnode *abnode)
{
    return BOP_RESTARTP(abnode);
}

static void
bnode_Lock(struct bnode *abnode)
{
#ifdef AFS_PTHREAD_ENV
    opr_mutex_enter(&abnode->mutex);
#endif
    return;
}

static void
bnode_Unlock(struct bnode *abnode)
{
#ifdef AFS_PTHREAD_ENV
    opr_mutex_exit(&abnode->mutex);
#endif
    return;
}

static int
bnode_Check(struct bnode *abnode)
{
    opr_Assert(abnode->refCount > 0);

    bnode_Lock(abnode);
    if (abnode->flags & BNODE_WAIT) {
	abnode->flags &= ~BNODE_WAIT;
#ifdef AFS_PTHREAD_ENV
	opr_cv_signal(&abnode->cv);
#else
	LWP_NoYieldSignal(abnode);
#endif
    }
    bnode_Unlock(abnode);
    return 0;
}

/* tell if an instance has a core file */
int
bnode_HasCore(struct bnode *abnode)
{
    return BOP_HASCORE(abnode);
}

static void
bnode_Wait(struct bnode *abnode)
{
    opr_Assert(abnode->refCount > 0);

    abnode->flags |= BNODE_WAIT;
#ifdef AFS_PTHREAD_ENV
    do {
	opr_cv_wait(&abnode->cv, &abnode->mutex);
    } while (abnode->flags & BNODE_WAIT);
#else
    LWP_WaitProcess(abnode);
#endif
}

/* wait for all bnodes to stabilize */
int
bnode_WaitAll(void)
{
    struct opr_queue *cursor, *store;
    afs_int32 code = 0;

    ObtainReadLock(&newBnodes_lock);

    ObtainReadLock(&allBnodes_lock);
    for (opr_queue_Scan(&allBnodes, cursor)) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	bnode_Hold(tb);
    }
    ReleaseReadLock(&allBnodes_lock);

    for (opr_queue_Scan(&allBnodes, cursor)) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	code = bnode_WaitStatus(tb, tb->goal);
	if (code)
	    goto out;
    }

  out:
    for (opr_queue_ScanSafe(&allBnodes, cursor, store)) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	bnode_Release(tb);
    }
    ReleaseReadLock(&newBnodes_lock);

    return code;
}

/* wait until bnode status is correct */
int
bnode_WaitStatus(struct bnode *abnode, int astatus)
{
    afs_int32 code;
    afs_int32 stat;

    opr_Assert(abnode->refCount > 0);

    while (1) {
	/* get the status */
	code = BOP_GETSTAT(abnode, &stat);
	if (code)
	    return code;

	/* otherwise, check if we're done */
	if (stat == astatus)
	    return 0;		/* done */
	bnode_Lock(abnode);
	if (astatus != abnode->goal) {
	    bnode_Unlock(abnode);
	    return -1;		/* no longer our goal, don't keep waiting */
	}
	/* otherwise, block */
	bnode_Wait(abnode);
	bnode_Unlock(abnode);
    }
}

int
bnode_ResetErrorCount(struct bnode *abnode)
{
    opr_Assert(abnode->refCount > 0);

    abnode->errorStopCount = 0;
    abnode->errorStopDelay = 0;
    return 0;
}

int
bnode_SetStat(struct bnode *abnode, int agoal)
{
    opr_Assert(abnode->refCount > 0);

    abnode->goal = agoal;
    bnode_Check(abnode);
    ObtainWriteLock(&allProcs_lock);
    BOP_SETSTAT(abnode, agoal);		/* might call bnode_NewProc() */
    ReleaseWriteLock(&allProcs_lock);
    abnode->flags &= ~BNODE_ERRORSTOP;
    return 0;
}

int
bnode_SetGoal(struct bnode *abnode, int agoal)
{
    opr_Assert(abnode->refCount > 0);

    abnode->goal = agoal;
    bnode_Check(abnode);
    return 0;
}

int
bnode_SetFileGoal(struct bnode *abnode, int agoal)
{
    opr_Assert(abnode->refCount > 0);

    if (abnode->fileGoal == agoal)
	return 0;		/* already done */
    ObtainReadLock(&allBnodes_lock);
    abnode->fileGoal = agoal;
    WriteBozoFile(0);
    ReleaseReadLock(&allBnodes_lock);
    return 0;
}

/* apply a function to all bnodes in the system */
int
bnode_ApplyInstanceNoLock(int (*aproc) (struct bnode *tb, void *), void *arock)
{
    struct opr_queue *cursor, *store;
    afs_int32 code = 0;

    ObtainReadLock(&allBnodes_lock);
    for (opr_queue_Scan(&allBnodes, cursor)) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	bnode_Hold(tb);
    }
    ReleaseReadLock(&allBnodes_lock);

    for (opr_queue_Scan(&allBnodes, cursor )) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	code = (*aproc) (tb, arock);
	if (code)
	    goto out;
    }

  out:
    for (opr_queue_ScanSafe(&allBnodes, cursor, store)) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	bnode_Release(tb);
    }
    return code;
}

int
bnode_ApplyInstance(int (*aproc) (struct bnode *tb, void *), void *arock)
{
    afs_int32 code;

    ObtainReadLock(&newBnodes_lock);
    code = bnode_ApplyInstanceNoLock(aproc, arock);
    ReleaseReadLock(&newBnodes_lock);
    return code;
}

struct bnode *
bnode_FindInstanceNoLock(char *aname)
{
    struct opr_queue *cursor;

    for (opr_queue_Scan(&allBnodes, cursor)) {
	struct bnode *tb = opr_queue_Entry(cursor, struct bnode, q);

	if (!strcmp(tb->name, aname))
	    return tb;
    }
    return NULL;
}

struct bnode *
bnode_FindInstance(char *aname)
{
    struct bnode *tb;

    ObtainReadLock(&allBnodes_lock);
    tb = bnode_FindInstanceNoLock(aname);
    if (tb)
	bnode_Hold(tb);
    ReleaseReadLock(&allBnodes_lock);
    return tb;
}

static struct bnode_type *
FindType(char *aname)
{
    struct opr_queue *cursor;

    for (opr_queue_Scan(&allTypes, cursor)) {
	struct bnode_type *tt = opr_queue_Entry(cursor, struct bnode_type, q);

	if (!strcmp(tt->name, aname))
	    return tt;
    }
    return NULL;
}

int
bnode_Register(char *atype, struct bnode_ops *aprocs, int anparms)
{
    struct opr_queue *cursor;
    struct bnode_type *tt = NULL;

    for (opr_queue_Scan(&allTypes, cursor), tt = NULL) {
	tt = opr_queue_Entry(cursor, struct bnode_type, q);
	if (!strcmp(tt->name, atype))
	    break;
    }
    if (!tt) {
	tt = calloc(1, sizeof(struct bnode_type));
        opr_queue_Init(&tt->q);
	opr_queue_Prepend(&allTypes, &tt->q);
	tt->name = atype;
    }
    tt->ops = aprocs;
    return 0;
}

afs_int32
bnode_Create(char *atype, char *ainstance, struct bnode ** abp, char *ap1,
	     char *ap2, char *ap3, char *ap4, char *ap5, char *notifier,
	     int fileGoal, int rewritefile)
{
    struct bnode_type *type;
    struct bnode *tb;
    char *notifierpath = NULL;
    struct stat tstat;
    afs_int32 code = 0;

    ObtainWriteLock(&newBnodes_lock);
    ObtainWriteLock(&allBnodes_lock);
    if (bnode_FindInstanceNoLock(ainstance)) {
	code = BZEXISTS;
	goto out_err;
    }
    type = FindType(atype);
    if (!type) {
	code = BZBADTYPE;
	goto out_err;
    }

    if (notifier && strcmp(notifier, NONOTIFIER)) {
	/* construct local path from canonical (wire-format) path */
	if (ConstructLocalBinPath(notifier, &notifierpath)) {
	    bozo_Log("BNODE-Create: Notifier program path invalid '%s'\n",
		     notifier);
	    code = BZNOCREATE;
	    goto out_err;
	}

	if (stat(notifierpath, &tstat)) {
	    bozo_Log("BNODE-Create: Notifier program '%s' not found\n",
		     notifierpath);
	    free(notifierpath);
	    code = BZNOCREATE;
	    goto out_err;
	}
    }
    tb = (*type->ops->create) (ainstance, ap1, ap2, ap3, ap4, ap5);
    if (!tb) {
	free(notifierpath);
	code = BZNOCREATE;
	goto out_err;
    }
    tb->notifier = notifierpath;
    *abp = tb;
    tb->type = type;

    /* The fs_create above calls bnode_InitBnode() which always sets the
     ** fileGoal to BSTAT_NORMAL .... overwrite it with whatever is passed into
     ** this function as a parameter... */
    tb->fileGoal = fileGoal;

    /* Leave a ref on the bnode after creation, the caller will release it. */
    bnode_Hold(tb);

    if (rewritefile != 0)
	WriteBozoFile(0);

    ReleaseWriteLock(&allBnodes_lock);
    ReleaseWriteLock(&newBnodes_lock);

    bnode_SetStat(tb, tb->goal);	/* nudge it once */
    goto out;

  out_err:
    ReleaseWriteLock(&allBnodes_lock);
    ReleaseWriteLock(&newBnodes_lock);
  out:
    return code;
}

int
bnode_DeleteName(char *ainstance)
{
    struct bnode *abnode;
    int code, stat;

    ObtainWriteLock(&allBnodes_lock);
    abnode = bnode_FindInstanceNoLock(ainstance);
    if (!abnode) {
	code = BZNOENT;
        goto out;
    }

    /* make sure the bnode is idle before zapping */
    code = BOP_GETSTAT(abnode, &stat);
    if (code) {
	goto out;
    }
    if (stat != BSTAT_SHUTDOWN) {
	code = BZBUSY;
	goto out;
    }

    code = bnode_DeleteNoLock(abnode);

  out:
    ReleaseWriteLock(&allBnodes_lock);
    return code;
}

int
bnode_Hold(struct bnode *abnode)
{
    opr_Assert(allBnodes_lock.readers_reading > 0
               || allBnodes_lock.excl_locked == WRITE_LOCK);
    abnode->refCount++;
    return 0;
}

int
bnode_Release(struct bnode *abnode)
{
    opr_Assert(abnode->refCount > 0);
    abnode->refCount--;
    if (abnode->refCount == 0 && abnode->flags & BNODE_DELETE) {
	ObtainWriteLock(&allBnodes_lock);
	bnode_DeleteNoLock(abnode);
	ReleaseWriteLock(&allBnodes_lock);
    }
    return 0;
}

static int
bnode_DeleteNoLock(struct bnode *abnode)
{
    afs_int32 code;

    opr_Assert(allBnodes_lock.excl_locked == WRITE_LOCK);

    if (abnode->refCount != 0) {
	abnode->flags |= BNODE_DELETE;
	return 0;
    }
    abnode->flags &= ~BNODE_DELETE;

    /* all clear to zap */
    opr_queue_Remove(&abnode->q);
    free(abnode->name);		/* do this first, since bnode fields may be bad after BOP_DELETE */
    code = BOP_DELETE(abnode);	/* don't play games like holding over this one */
    WriteBozoFile(0);
    return code;
}

int
bnode_Delete(struct bnode *abnode)
{
    afs_int32 code;

    ObtainWriteLock(&allBnodes_lock);
    code = bnode_DeleteNoLock(abnode);
    ReleaseWriteLock(&allBnodes_lock);
    return code;
}

/* function to tell if there's a timeout coming up */
int
bnode_PendingTimeout(struct bnode *abnode)
{
    return (abnode->flags & BNODE_NEEDTIMEOUT);
}

/* function called to set / clear periodic bnode wakeup times */
int
bnode_SetTimeout(struct bnode *abnode, afs_int32 atimeout)
{
    if (atimeout != 0) {
	abnode->nextTimeout = FT_ApproxTime() + atimeout;
	abnode->flags |= BNODE_NEEDTIMEOUT;
	abnode->period = atimeout;
#ifdef AFS_PTHREAD_ENV
	opr_cv_signal(&bproc_cv);
#else
	IOMGR_Cancel(bproc_pid);
#endif
    } else {
	abnode->flags &= ~BNODE_NEEDTIMEOUT;
    }
    return 0;
}

/* used by new bnode creation code to format bnode header */
int
bnode_InitBnode(struct bnode *abnode, struct bnode_ops *abnodeops,
		char *aname)
{
    opr_Assert(allBnodes_lock.excl_locked == WRITE_LOCK);

    /* format the bnode properly */
    memset(abnode, 0, sizeof(struct bnode));
    opr_queue_Init(&abnode->q);
#ifdef AFS_PTHREAD_ENV
    opr_cv_init(&abnode->cv);
    opr_mutex_init(&abnode->mutex);
#endif
    abnode->ops = abnodeops;
    abnode->name = strdup(aname);
    if (!abnode->name)
	return ENOMEM;
    abnode->flags = BNODE_ACTIVE;
    abnode->fileGoal = BSTAT_NORMAL;
    abnode->goal = BSTAT_SHUTDOWN;

    /* put the bnode at the end of the list so we write bnode file in same order */
    opr_queue_Append(&allBnodes, &abnode->q);

    return 0;
}

static void
bnode_DeleteProc(struct bnode_proc *aproc, int atimeout, int astatus)
{
    struct bnode *abnode = aproc->bnode;

    /* count restarts in last 30 seconds */
    if (atimeout > abnode->rsTime + 30) {
	/* it's been 30 seconds we've been counting */
	abnode->rsTime = atimeout;
	abnode->rsCount = 0;
    }

    if (WIFSIGNALED(astatus) == 0) {
	/* exited, not signalled */
	aproc->lastExit = WEXITSTATUS(astatus);
	aproc->lastSignal = 0;
	if (aproc->lastExit) {
	    abnode->errorCode = aproc->lastExit;
	    abnode->lastErrorExit = FT_ApproxTime();
	    RememberProcName(aproc);
	    abnode->errorSignal = 0;
	}
	if (aproc->coreName)
	    bozo_Log("%s:%s exited with code %d\n", abnode->name,
		     aproc->coreName, aproc->lastExit);
	else
	    bozo_Log("%s exited with code %d\n", abnode->name,
		     aproc->lastExit);
    } else {
	/* Signal occurred, perhaps spurious due to shutdown request.
	 * If due to a shutdown request, don't overwrite last error
	 * information.
	 */
	aproc->lastSignal = WTERMSIG(astatus);
	aproc->lastExit = 0;
	if (aproc->lastSignal != SIGQUIT
	    && aproc->lastSignal != SIGTERM
	    && aproc->lastSignal != SIGKILL) {
	    abnode->errorSignal = aproc->lastSignal;
	    abnode->lastErrorExit = FT_ApproxTime();
	    RememberProcName(aproc);
	}
	if (aproc->coreName)
	    bozo_Log("%s:%s exited on signal %d%s\n",
		     abnode->name, aproc->coreName, aproc->lastSignal,
		     WCOREDUMP(astatus) ? " (core dumped)" :
		     "");
	else
	    bozo_Log("%s exited on signal %d%s\n", abnode->name,
		     aproc->lastSignal,
		     WCOREDUMP(astatus) ? " (core dumped)" :
		     "");
	SaveCore(abnode, aproc);
    }
    abnode->lastAnyExit = FT_ApproxTime();

    if (abnode->notifier) {
	bozo_Log("BNODE: Notifier %s will be called\n",
		 abnode->notifier);
	hdl_notifier(aproc);
    }

    if (abnode->goal && abnode->rsCount++ > 10) {
	/* 10 in 30 seconds */
	if (abnode->errorStopCount >= BNODE_ERROR_COUNT_MAX) {
	    abnode->errorStopDelay = 0;	/* max reached, give up. */
	} else {
	    abnode->errorStopCount++;
	    if (!abnode->errorStopDelay) {
		abnode->errorStopDelay = 1;
	    } else {
		abnode->errorStopDelay *= 2;
	    }
	}
	abnode->flags |= BNODE_ERRORSTOP;
	bnode_SetGoal(abnode, BSTAT_SHUTDOWN);
	bozo_Log
	    ("BNODE '%s' repeatedly failed to start, perhaps missing executable.\n",
	     abnode->name);
    }
    BOP_PROCEXIT(abnode, aproc);
    bnode_Check(abnode);
    bnode_Release(abnode);	/* bnode delete can happen here */
    opr_queue_Remove(&aproc->q);
    free(aproc);
}

/**
 * Handles background processing for bosserver
 *
 * Sleeps until the next timeout or interrupt as required by the current
 * bnodes.  Also, in the case of LWP, SIGCHLD's via bnode_SoftInt() wake
 * up this routine in order to manage the child processes.  For pthreads,
 * bnode_proc's are individually managed in proc_hander().
 *
 * @param[in] unused unused
 * @return unused
 *   @retval NULL ignored
 */
static void *
bproc(void *unused)
{
#ifdef AFS_PTHREAD_ENV
    struct timespec ts;
#else
    afs_int32 code;
#endif
    struct bnode *tb;
    time_t now, nextTimeout;
    struct opr_queue *cursor;
    struct timeval tv;

#define MAXSLEEP 999999			/* maxint doesn't work in select */

    while (1) {
	/* first figure out how long to sleep */
	nextTimeout = FT_ApproxTime() + MAXSLEEP;
	ObtainWriteLock(&allBnodes_lock);
	for (opr_queue_Scan(&allBnodes, cursor)) {
	    tb = opr_queue_Entry(cursor, struct bnode, q);
	    if (tb->flags & BNODE_NEEDTIMEOUT) {
		nextTimeout = min(nextTimeout, tb->nextTimeout);
	    }
	}
	ReleaseWriteLock(&allBnodes_lock);
	/* now nextTimeout has the time at which we should wakeup next */

	/* sleep */
#ifdef AFS_PTHREAD_ENV
	ts.tv_sec = nextTimeout;
	ts.tv_nsec = 0;
	opr_cv_timedwait(&bproc_cv, &bproc_mutex, &ts);
#else
	tv.tv_sec = nextTimeout - FT_ApproxTime();
	tv.tv_usec = 0;
	if (tv.tv_sec > 0)
	    code = IOMGR_Select(0, 0, 0, 0, &tv);
	else
	    code = 0;		/* fake timeout code */
#endif

	/* figure out why we woke up; child exit or timeouts */
	FT_GetTimeOfDay(&tv, 0);	/* must do the real gettimeofday once and a while */
	now = tv.tv_sec;

	/* check all bnodes to see which ones need timeout events */
  retry:
	ObtainWriteLock(&allBnodes_lock);
	for (opr_queue_Scan(&allBnodes, cursor)) {
	    tb = opr_queue_Entry(cursor, struct bnode, q);
	    if ((tb->flags & BNODE_NEEDTIMEOUT) && now > tb->nextTimeout) {
		bnode_Hold(tb);
		ReleaseWriteLock(&allBnodes_lock);

		BOP_TIMEOUT(tb);
		bnode_Check(tb);
		if (tb->flags & BNODE_NEEDTIMEOUT) {	/* check again, BOP_TIMEOUT could change */
		    tb->nextTimeout = FT_ApproxTime() + tb->period;
		}
		bnode_Release(tb);	/* delete may occur here */
		goto retry;
	    }
	}
	ReleaseWriteLock(&allBnodes_lock);

#ifndef AFS_PTHREAD_ENV
	if (code < 0) {
	    /* signalled, probably by incoming signal */
	    while (1) {
		struct bnode_proc *tp;
		int options;
		int status;

		options = WNOHANG;
		code = waitpid((pid_t) - 1, &status, options);
		if (code == 0 || code == -1)
		    break;	/* all done */
		/* otherwise code has a process id, which we now search for */
		ObtainWriteLock(&allProcs_lock);
		for (tp = NULL, opr_queue_Scan(&allProcs, cursor), tp = NULL) {
		    tp = opr_queue_Entry(cursor, struct bnode_proc, q);

		    if (tp->pid == code) {
			/* found the pid */
			break;
		    }
		}
		if (tp)
		    bnode_DeleteProc(tp, now, status);
		else
		    bnode_stats.weirdPids++;
		ReleaseWriteLock(&allProcs_lock);
	    }
	}
#endif
    }
    return NULL;
}

static afs_int32
SendNotifierData(int fd, struct bnode_proc *tp)
{
    struct bnode *tb = tp->bnode;
    char buffer[1000], *bufp = buffer, *buf1;
    int len;

    /*
     * First sent out the bnode_proc struct
     */
    (void)sprintf(bufp, "BEGIN bnode_proc\n");
    bufp += strlen(bufp);
    (void)sprintf(bufp, "comLine: %s\n", tp->comLine);
    bufp += strlen(bufp);
    if (!(buf1 = tp->coreName))
	buf1 = "(null)";
    (void)sprintf(bufp, "coreName: %s\n", buf1);
    bufp += strlen(bufp);
    (void)sprintf(bufp, "pid: %ld\n", afs_printable_int32_ld(tp->pid));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "lastExit: %ld\n", afs_printable_int32_ld(tp->lastExit));
    bufp += strlen(bufp);
#ifdef notdef
    (void)sprintf(bufp, "lastSignal: %ld\n", afs_printable_int32_ld(tp->lastSignal));
    bufp += strlen(bufp);
#endif
    (void)sprintf(bufp, "flags: %ld\n", afs_printable_int32_ld(tp->flags));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "END bnode_proc\n");
    bufp += strlen(bufp);
    len = (int)(bufp - buffer);
    if (write(fd, buffer, len) < 0) {
	return -1;
    }

    /*
     * Now sent out the bnode struct
     */
    bufp = buffer;
    (void)sprintf(bufp, "BEGIN bnode\n");
    bufp += strlen(bufp);
    (void)sprintf(bufp, "name: %s\n", tb->name);
    bufp += strlen(bufp);
    (void)sprintf(bufp, "rsTime: %ld\n", afs_printable_int32_ld(tb->rsTime));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "rsCount: %ld\n", afs_printable_int32_ld(tb->rsCount));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "procStartTime: %ld\n", afs_printable_int32_ld(tb->procStartTime));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "procStarts: %ld\n", afs_printable_int32_ld(tb->procStarts));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "lastAnyExit: %ld\n", afs_printable_int32_ld(tb->lastAnyExit));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "lastErrorExit: %ld\n", afs_printable_int32_ld(tb->lastErrorExit));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "errorCode: %ld\n", afs_printable_int32_ld(tb->errorCode));
    bufp += strlen(bufp);
    (void)sprintf(bufp, "errorSignal: %ld\n", afs_printable_int32_ld(tb->errorSignal));
    bufp += strlen(bufp);
/*
    (void) sprintf(bufp, "lastErrorName: %s\n", tb->lastErrorName);
    bufp += strlen(bufp);
*/
    (void)sprintf(bufp, "goal: %d\n", tb->goal);
    bufp += strlen(bufp);
    (void)sprintf(bufp, "END bnode\n");
    bufp += strlen(bufp);
    len = (int)(bufp - buffer);
    if (write(fd, buffer, len) < 0) {
	return -1;
    }
    return 0;
}

int
hdl_notifier(struct bnode_proc *tp)
{
#ifndef AFS_NT40_ENV		/* NT notifier callout not yet implemented */
    int pid;
    struct stat tstat;

    if (stat(tp->bnode->notifier, &tstat)) {
	bozo_Log("BNODE: Failed to find notifier '%s'; ignored\n",
		 tp->bnode->notifier);
	return (1);
    }
    if ((pid = fork()) == 0) {
	FILE *fout;
	struct bnode *tb = tp->bnode;

#if defined(AFS_HPUX_ENV) || defined(AFS_SUN5_ENV) || defined(AFS_SGI51_ENV)
	setsid();
#elif defined(AFS_DARWIN90_ENV)
	setpgid(0, 0);
#elif defined(AFS_LINUX20_ENV) || defined(AFS_AIX_ENV)
	setpgrp();
#else
	setpgrp(0, 0);
#endif
	fout = popen(tb->notifier, "w");
	if (fout == NULL) {
	    bozo_Log("BNODE: Failed to find notifier '%s'; ignored\n",
		     tb->notifier);
	    perror(tb->notifier);
	    exit(1);
	}
	SendNotifierData(fileno(fout), tp);
	pclose(fout);
	exit(0);
    } else if (pid < 0) {
	bozo_Log("Failed to fork creating process to handle notifier '%s'\n",
		 tp->bnode->notifier);
	return -1;
    }
#endif /* AFS_NT40_ENV */
    return (0);
}

#ifdef AFS_PTHREAD_ENV
static void *
signal_handler(void *unused)
{
    pthread_t shutdown_pid;
    pthread_attr_t tattr;
    sigset_t mask;
    int sig, code;

    /* block all signals */
    sigfillset(&mask);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    /* what we want to handle */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGFPE);

    while (1) {
	code = sigwait(&mask, &sig);
	if (code)
	    continue;

        switch (sig) {
	    case SIGFPE:
		bozo_insecureme(SIGFPE);
		break;
	    case SIGQUIT:
	    case SIGTERM:
	        pthread_attr_init(&tattr);
	        pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	        pthread_create(&shutdown_pid, &tattr, bozo_ShutdownAndExit,
			       ((void *)(intptr_t) sig));
		break;
	    default:
		bozo_Log("Unhandled signal signo %d\n", sig);
		break;
	}
    }

    return NULL;
}
#else
/**
 * Cause bproc() to process state changes
 *
 * Called by IOMGR at low priority on IOMGR's stack shortly after a
 * SIGCHLD occurs.  Wakes up bproc() to handle child processes.
 *
 * @note LWP only
 *
 * @param[in] param unused
 * @return unused
 *   @retval 0 ignored
 */
void *
bnode_SoftInt(void *param)
{
    /* int asignal = (int) param; */

    IOMGR_Cancel(bproc_pid);
    return 0;
}

/**
 * Signal handler for SIGQUIT, SIGTERM, and SIGCHILD
 *
 * Called at signal interrupt level; queues function to be called
 * when IOMGR runs again.
 *
 * @note LWP only
 *
 * @param[in] asignal signal number
 * @return none
 */
void
bnode_Int(int asignal)
{
    if (asignal == SIGQUIT || asignal == SIGTERM)
	IOMGR_SoftSig(bozo_ShutdownAndExit, (void *)(intptr_t)asignal);
    else
	IOMGR_SoftSig(bnode_SoftInt, (void *)(intptr_t)asignal);
}
#endif

/* intialize the locks and queues */
int
bnode_Init(void)
{
#ifdef AFS_PTHREAD_ENV
    sigset_t mask;
#else
    struct sigaction newaction;
#endif
    afs_int32 code;
    static int initDone = 0;

    if (initDone)
	return 0;
    initDone = 1;
    opr_queue_Init(&allTypes);
    opr_queue_Init(&allProcs);
    Lock_Init(&allProcs_lock);
    opr_queue_Init(&allBnodes);
    Lock_Init(&allBnodes_lock);
    Lock_Init(&newBnodes_lock);
    memset(&bnode_stats, 0, sizeof(bnode_stats));

#ifdef AFS_PTHREAD_ENV
    opr_cv_init(&bproc_cv);
    opr_mutex_init(&bproc_mutex);

    /* sigwait() for these in signal_handler() thread */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGFPE);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
#else
    memset(&newaction, 0, sizeof(newaction));
    newaction.sa_handler = bozo_insecureme;
    code = sigaction(SIGFPE, &newaction, NULL);
    if (code)
	return errno;
    newaction.sa_handler = bnode_Int;
    code = sigaction(SIGCHLD, &newaction, NULL);
    if (code)
	return errno;
    code = sigaction(SIGQUIT, &newaction, NULL);
    if (code)
	return errno;
    code = sigaction(SIGTERM, &newaction, NULL);
    if (code)
	return errno;
#endif

    return code;
}

/* Fire up helper processes (bproc, signal handler) */
int
bnode_InitProcs(void)
{
#ifdef AFS_PTHREAD_ENV
    pthread_attr_t tattr;
#else
    PROCESS junk;
#endif
    afs_int32 code;

#ifdef AFS_PTHREAD_ENV
    pthread_attr_init(&tattr);
    pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);

    code = pthread_create(&bproc_pid, &tattr, bproc, NULL);
    if (code)
	return code;

    code = pthread_create(&sighand_pid, &tattr, signal_handler, NULL);
    if (code)
	return code;
#else
    LWP_InitializeProcessSupport(1, &junk);	/* just in case */
    IOMGR_Initialize();
    code = LWP_CreateProcess(bproc, BNODE_LWP_STACKSIZE,
			     /* priority */ 1, (void *) /* parm */ 0,
			     "bnode-manager", &bproc_pid);
    if (code)
	return code;
#endif

    return code;
}

/* free token list returned by parseLine */
int
bnode_FreeTokens(struct bnode_token *alist)
{
    struct bnode_token *nlist;
    for (; alist; alist = nlist) {
	nlist = alist->next;
	free(alist->key);
	free(alist);
    }
    return 0;
}

static int
space(int x)
{
    if (x == 0 || x == ' ' || x == '\t' || x == '\n')
	return 1;
    else
	return 0;
}

int
bnode_ParseLine(char *aline, struct bnode_token **alist)
{
    char tbuffer[256];
    char *tptr = NULL;
    int inToken;
    struct bnode_token *first, *last;
    struct bnode_token *ttok;
    int tc;

    inToken = 0;		/* not copying token chars at start */
    first = (struct bnode_token *)0;
    last = (struct bnode_token *)0;
    while (1) {
	tc = *aline++;
	if (tc == 0 || space(tc)) {	/* terminating null gets us in here, too */
	    if (inToken) {
		inToken = 0;	/* end of this token */
		*tptr++ = 0;
		ttok = malloc(sizeof(struct bnode_token));
		ttok->next = (struct bnode_token *)0;
		ttok->key = strdup(tbuffer);
		if (last) {
		    last->next = ttok;
		    last = ttok;
		} else
		    last = ttok;
		if (!first)
		    first = ttok;
	    }
	} else {
	    /* an alpha character */
	    if (!inToken) {
		tptr = tbuffer;
		inToken = 1;
	    }
	    if (tptr - tbuffer >= sizeof(tbuffer))
		return -1;	/* token too long */
	    *tptr++ = tc;
	}
	if (tc == 0) {
	    /* last token flushed 'cause space(0) --> true */
	    if (last)
		last->next = (struct bnode_token *)0;
	    *alist = first;
	    return 0;
	}
    }
}

/**
 * Creates child process assocated with a bnode process
 *
 * @param[in] param pointer to struct bnode_proc
 * @return result of the operation
 *   @retval >0 success; pid of the child process
 *   @retval <0 failure; negated errno
 */
#define	MAXVARGS	128
static pid_t
bnode_SpawnProc(struct bnode_proc *aproc)
{
    struct bnode_token *tlist = aproc->tlist, *tt;
    char *argv[MAXVARGS];
    afs_int32 pid;
    int i;

    /* convert linked list of tokens into argv structure */
    for (tt = tlist, i = 0; i < (MAXVARGS - 1) && tt; tt = tt->next, i++) {
	argv[i] = tt->key;
    }
    argv[i] = NULL;		/* null-terminated */

    pid = spawnprocve(argv[0], argv, environ, -1);
    osi_audit(BOSSpawnProcEvent, 0, AUD_STR, aproc->comLine, AUD_END);

    if (pid == -1) {
        pid = -errno;
	bozo_Log("Failed to spawn process for bnode '%s'\n", aproc->bnode->name);
    } else {
	bozo_Log("%s started pid %ld: %s\n", aproc->bnode->name, pid, aproc->comLine);
    }

    return pid;
}

/**
 * Manages child process assocated with a bnode process
 *
 * @note pthreads only
 *
 * @param[in] param pointer to struct bnode_proc
 * @return unused
 *   @retval NULL ignored
 */
#ifdef AFS_PTHREAD_ENV
static void *
proc_handler(void *param)
{
    struct bnode_proc *tproc = (struct bnode_proc *) param;
    struct timeval tv;
    int status;

    tproc->pid = bnode_SpawnProc(tproc);
    opr_mutex_enter(&tproc->mutex);
    opr_cv_signal(&tproc->started);	/* tell bnode_NewProc we started */
    opr_mutex_exit(&tproc->mutex);

    if (tproc->pid < 0)
	goto out;	

    waitpid(tproc->pid, &status, 0);
    FT_GetTimeOfDay(&tv, 0);
    ObtainWriteLock(&allProcs_lock);
    bnode_DeleteProc(tproc, tv.tv_sec, status);
    ReleaseWriteLock(&allProcs_lock);

  out:
    pthread_exit(NULL);
    return NULL;
}
#endif

int
bnode_NewProc(struct bnode *abnode, char *aexecString, char *coreName,
	      struct bnode_proc **aproc)
{
#ifdef AFS_PTHREAD_ENV
    pthread_attr_t tattr;
    pthread_t tid;
#endif
    afs_int32 code;
    struct bnode_proc *tp;

    opr_Assert(allProcs_lock.excl_locked == WRITE_LOCK);

    tp = calloc(1, sizeof(struct bnode_proc));
    code = bnode_ParseLine(aexecString, &tp->tlist);	/* try parsing first */
    if (code)
	return code;
    opr_queue_Init(&tp->q);
    opr_Assert(abnode->refCount > 0);
    ObtainWriteLock(&allBnodes_lock);	// @@@ how did we find this? should already have reference so read lock is fine?
    bnode_Hold(abnode);		/* hold a ref for duration of proc */
    ReleaseWriteLock(&allBnodes_lock);
    tp->bnode = abnode;
    tp->comLine = aexecString;
    tp->coreName = coreName;	/* may be null */
    abnode->procStartTime = FT_ApproxTime();
    abnode->procStarts++;

#ifdef AFS_PTHREAD_ENV
    opr_mutex_init(&tp->mutex);
    opr_cv_init(&tp->started);

    pthread_attr_init(&tattr);
    pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
    opr_mutex_enter(&tp->mutex);
    code = pthread_create(&tid, &tattr, proc_handler, tp);
    if (code) {
	bozo_Log("Failed to create thread for bnode '%s'\n", abnode->name);
    } else {
	opr_cv_wait(&tp->started, &tp->mutex);
        code = (tp->pid > 0) ? 0 : -(tp->pid);	/* get errno from tp->pid */
    }
    opr_mutex_exit(&tp->mutex);
#else
    tp->pid = bnode_SpawnProc(tp);
    code = (tp->pid > 0) ? 0 : -(tp->pid);
#endif
    if (code) {
	bnode_FreeTokens(tp->tlist);
	free(tp);
	return code;
    }

    opr_queue_Prepend(&allProcs, &tp->q);
    *aproc = tp;
    tp->flags = BPROC_STARTED;
    tp->flags &= ~BPROC_EXITED;
    BOP_PROCSTARTED(abnode, tp);
    bnode_Check(abnode);

    return 0;
}

int
bnode_StopProc(struct bnode_proc *aproc, int asignal)
{
    int code;
    if (!(aproc->flags & BPROC_STARTED) || (aproc->flags & BPROC_EXITED))
	return BZNOTACTIVE;

    osi_audit(BOSStopProcEvent, 0, AUD_STR, (aproc ? aproc->comLine : NULL),
	      AUD_END);

    code = kill(aproc->pid, asignal);
    bnode_Check(aproc->bnode);
    return code;
}
