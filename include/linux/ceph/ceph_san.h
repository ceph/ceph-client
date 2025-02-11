#ifndef CEPHSAN_H
#define CEPHSAN_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

extern struct list_head ceph_san_list;
extern spinlock_t ceph_san_lock;

/* The ceph san log entry structure is now private to ceph_san.c.
 * Use log_cephsan() below.
 */

/* get_cephsan() and alloc_cephsan() have been removed from the public API. */

/* New log_cephsan now accepts a line number, a pointer to a u8 buffer (typically function name),
 * and an optional parameter. It uses the current task's journal_info field.
 */

#ifdef CONFIG_DEBUG_FS
#define CEPH_SAN_MAX_LOGS 256
#define LOG_BUF_SIZE 128

void cephsan_cleanup(void);
int __init cephsan_init(void);

char *get_log_cephsan(void);
#define CEPH_SAN_LOG(fmt, ...) do { \
    char *buf = get_log_cephsan(); \
    snprintf(buf, LOG_BUF_SIZE, fmt, ##__VA_ARGS__); \
} while (0)
/*
 * Internal definitions for Ceph SAN logs.
 * These definitions are not part of the public API but are required by debugfs.c.
 */
struct ceph_san_log_entry {
    char buf[LOG_BUF_SIZE];
    u64 ts;
};

struct ceph_san_tls_logger {
    u64 cephsun_sig;
    size_t head_idx;
    size_t tail_idx;
    struct list_head list;
    struct task_struct *task;
    struct ceph_mds_request *req;
    struct ceph_san_log_entry logs[CEPH_SAN_MAX_LOGS];
};
/* Macro to set the request in the TLS logger */
#define CEPH_SAN_SET_REQ(req) do { \
    struct ceph_san_tls_logger *__tls = current->journal_info; \
    if (__tls && __tls->cephsun_sig == 0xD1E7C0CE) \
        __tls->req = req; \
    else \
        current->journal_info = req; \
} while (0)
/* Macro to reset the request in the TLS logger */
#define CEPH_SAN_RESET_REQ() do { \
    struct ceph_san_tls_logger *__tls = current->journal_info; \
    if (__tls && __tls->cephsun_sig == 0xD1E7C0CE) \
        __tls->req = NULL; \
    else \
        current->journal_info = NULL; \
} while (0)

/* Macro to get the request from the TLS logger */
#define CEPH_SAN_GET_REQ() ({ \
    struct ceph_san_tls_logger *__tls = current->journal_info; \
    (__tls && __tls->cephsun_sig == 0xD1E7C0CE) ? __tls->req : current->journal_info; \
})
#else /* CONFIG_DEBUG_FS */
#define CEPH_SAN_LOG(param) do {} while (0)
#define CEPH_SAN_SET_REQ(req) do { current->journal_info = req; } while (0)
#define CEPH_SAN_RESET_REQ() do { current->journal_info = NULL; } while (0)
#define CEPH_SAN_GET_REQ() (current->journal_info)


static inline void cephsan_cleanup(void) {}
static inline int __init cephsan_init(void) { return 0; }

#endif /* CONFIG_DEBUG_FS */

#endif /* CEPHSAN_H */