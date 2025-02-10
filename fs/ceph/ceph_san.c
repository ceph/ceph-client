#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include "ceph_san.h"

#ifdef CONFIG_DEBUG_FS
/* Global list and lock now hold TLS logger objects only */
LIST_HEAD(ceph_san_list);
DEFINE_SPINLOCK(ceph_san_lock);

/* The definitions for struct ceph_san_log_entry and struct ceph_san_tls_logger
 * have been moved to cephsan.h (under CONFIG_DEBUG_FS) to avoid duplication.
 */

void log_cephsan(size_t line, u8 *func, size_t opt_param) {
    struct ceph_san_tls_logger *tls;

    /* Check if the current task already has a TLS logger in its journal_info field.
     * (Note: This simplistic example assumes that current->journal_info is a valid field.)
     */
    if (current->journal_info) {
        tls = (struct ceph_san_tls_logger *)current->journal_info;
        if (tls->cephsun_sig != 0xD1E7C0CE) {
            pr_err("Ceph SAN: Invalid signature - %s(%d)\n", current->comm, current->pid);
            return;
        }
        if (tls->task != current) {
            pr_err("Ceph SAN: Task mismatch - %s(%d)\n", current->comm, current->pid);
            return;
        }
    } else {
        tls = kmalloc(sizeof(*tls), GFP_KERNEL);
        if (!tls) {
            pr_err("Ceph SAN: Failed to allocate TLS logger for %s(%d)\n", current->comm, current->pid);
            return;
        }
        tls->cephsun_sig = 0xD1E7C0CE; /* example signature */
        tls->task = current;
        tls->head_idx = 0;
        tls->tail_idx = 0;
        INIT_LIST_HEAD(&tls->list);

        spin_lock(&ceph_san_lock);
        list_add_tail(&tls->list, &ceph_san_list);
        spin_unlock(&ceph_san_lock);

        /* Set current task's journal_info pointer to the newly allocated TLS logger */
        current->journal_info = (void *)tls;
    }

    if ((tls->head_idx + 1) % CEPH_SAN_MAX_LOGS == tls->tail_idx) {
        tls->tail_idx = (tls->tail_idx + 1) % CEPH_SAN_MAX_LOGS;
    }
    tls->logs[tls->head_idx].line = line;
    tls->logs[tls->head_idx].func = func;
    tls->logs[tls->head_idx].ts = jiffies;
    tls->logs[tls->head_idx].opt_param = opt_param;
    tls->head_idx = (tls->head_idx + 1) % CEPH_SAN_MAX_LOGS;
}

/* Cleanup function to free all TLS logger objects.
 * Call this at module exit to free allocated TLS loggers.
 */
void cephsan_cleanup(void)
{
    struct ceph_san_tls_logger *tls, *tmp;

    spin_lock(&ceph_san_lock);
    list_for_each_entry_safe(tls, tmp, &ceph_san_list, list) {
         list_del(&tls->list);
         kfree(tls);
    }
    spin_unlock(&ceph_san_lock);
}
/* Initialize the Ceph SAN logging infrastructure.
 * Call this at module init to set up the global list and lock.
 */
int __init cephsan_init(void)
{
	spin_lock_init(&ceph_san_lock);
	INIT_LIST_HEAD(&ceph_san_list);
	return 0;
}

#endif /* CONFIG_DEBUG_FS */