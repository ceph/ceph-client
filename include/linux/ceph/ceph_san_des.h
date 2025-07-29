#ifndef CEPH_SAN_DES_H
#define CEPH_SAN_DES_H

#include <linux/types.h> /* For size_t */

/* Forward declaration */
struct ceph_san_log_entry;

/**
 * Reconstructs a formatted string from a buffer containing serialized values.
 * The function uses the format string to determine the types and number of values
 * to extract from the buffer.
 *
 * @param fmt Format string containing % specifiers
 * @param buffer Buffer containing serialized values
 * @param nr_args Number of arguments to process
 * @param size Size of the buffer in bytes
 * @param out Buffer to store the reconstructed string
 * @param out_size Size of the output buffer
 * @return Number of bytes written to out buffer, or negative error code on failure
 */
int ceph_san_des_reconstruct(const char *fmt, const void *buffer, size_t nr_args,
                           size_t size, char *out, size_t out_size);

/**
 * Reconstructs a formatted string from a log entry.
 * This is a wrapper around ceph_san_des_reconstruct that handles log entry parsing.
 *
 * @param entry Log entry containing serialized data
 * @param output Buffer to write the formatted string to
 * @param output_size Size of the output buffer
 * @return Length of formatted string, or negative error code on failure
 */
int ceph_san_log_reconstruct(const struct ceph_san_log_entry *entry, char *output, size_t output_size);

#endif /* CEPH_SAN_DES_H */
