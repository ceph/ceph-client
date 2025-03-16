#ifndef CEPHSAN_H
#define CEPHSAN_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "ceph_san_pagefrag.h"

DECLARE_PER_CPU(struct ceph_san_percore_logger, ceph_san_percore);
DECLARE_PER_CPU(struct cephsan_pagefrag, ceph_san_pagefrag);

#ifdef CONFIG_DEBUG_FS
#define CEPH_SAN_MAX_LOGS (8192 << 2) //4MB per core
#define LOG_BUF_SIZE 256
#define LOG_BUF_SMALL 128

void cephsan_cleanup(void);
int cephsan_init(void);

void log_cephsan(char *buf);
void log_cephsan_tls(char *buf);
int cephsan_dump_all_contexts(char *buf, size_t size);

#define CEPH_SAN_LOG(fmt, ...) do { \
    char buf[LOG_BUF_SIZE] = {0}; \
    snprintf(buf, LOG_BUF_SIZE, fmt, ##__VA_ARGS__); \
    log_cephsan(buf); \
} while (0)

#define CEPH_SAN_LOG_TLS(fmt, ...) do { \
    char buf[LOG_BUF_SIZE] = {0}; \
    snprintf(buf, LOG_BUF_SIZE, fmt, ##__VA_ARGS__); \
    log_cephsan_tls(buf); \
} while (0)

/*
 * Internal definitions for Ceph SAN logs.
 * These definitions are not part of the public API but are required by debugfs.c.
 */
struct ceph_san_log_entry {
    char comm[TASK_COMM_LEN];
    char *buf;
    u64 ts;
    pid_t pid;
    u32 len;
};

struct ceph_san_log_entry_tls {
    u64 ts;
    char *buf;
};

struct histogram {
    u64 counters[32];
};

struct ceph_san_percore_logger {
    size_t head_idx;
    struct page *pages;
    struct ceph_san_log_entry *logs;
    struct histogram histogram;
};

struct ceph_san_tls_logger {
    char comm[TASK_COMM_LEN];
    pid_t pid;
    size_t head_idx;
    struct ceph_san_log_entry_tls logs[CEPH_SAN_MAX_LOGS];
};

/* Bundled TLS context containing both logger and memory caches */
struct tls_ceph_san_context {
    u64 sig;
    struct list_head list;  /* For global list of contexts */
    struct ceph_san_tls_logger logger;
};

/* Global list of all TLS contexts and its protection lock */
extern struct list_head g_ceph_san_contexts;
extern spinlock_t g_ceph_san_contexts_lock;

#else /* CONFIG_DEBUG_FS */

#define CEPH_SAN_LOG(param) do {} while (0)
#define CEPH_SAN_LOG_TLS(param) do {} while (0)

static inline void cephsan_cleanup(void) {}
static inline int __init cephsan_init(void) { return 0; }

#endif /* CONFIG_DEBUG_FS */

#define CEPH_SAN_SET_REQ(req) do { current->journal_info = req; } while (0)
#define CEPH_SAN_RESET_REQ() do { current->journal_info = NULL; } while (0)
#define CEPH_SAN_GET_REQ() (current->journal_info)

#endif /* CEPHSAN_H */
