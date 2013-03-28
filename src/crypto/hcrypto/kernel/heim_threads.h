#define HEIMDAL_MUTEX afs_kmutex_t
#define HEIMDAL_MUTEX_INITIALIZER {0};
#define HEIMDAL_MUTEX_init(m) MUTEX_INIT(m,0,0,0)
#define HEIMDAL_MUTEX_lock(m) MUTEX_ENTER(m)
#define HEIMDAL_MUTEX_unlock(m) MUTEX_EXIT(m)
#define HEIMDAL_MUTEX_destroy(m) MUTEX_DESTROY(m)
