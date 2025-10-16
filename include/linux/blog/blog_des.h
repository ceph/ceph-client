/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Binary Logging Deserialization
 */
#ifndef _LINUX_BLOG_DES_H
#define _LINUX_BLOG_DES_H

#include <linux/types.h> /* For size_t */

/* Forward declarations */
struct blog_log_entry;
struct blog_logger;

/**
 * blog_des_reconstruct - Reconstructs a formatted string from serialized values
 * @fmt: Format string containing % specifiers
 * @buffer: Buffer containing serialized values
 * @nr_args: Number of arguments to process
 * @size: Size of the buffer in bytes
 * @out: Buffer to store the reconstructed string
 * @out_size: Size of the output buffer
 *
 * The function uses the format string to determine the types and number of values
 * to extract from the buffer.
 *
 * Return: Number of bytes written to out buffer, or negative error code on failure
 */
int blog_des_reconstruct(const char *fmt, const void *buffer, size_t nr_args,
                          size_t size, char *out, size_t out_size);

/**
 * blog_log_reconstruct - Reconstructs a formatted string from a log entry
 * @entry: Log entry containing serialized data
 * @output: Buffer to write the formatted string to
 * @output_size: Size of the output buffer
 *
 * This is a wrapper around blog_des_reconstruct that handles log entry parsing.
 * Note: This does NOT handle client_id - the caller should handle that separately
 * using their module-specific callback.
 *
 * Return: Length of formatted string, or negative error code on failure
 */
int blog_log_reconstruct(struct blog_logger *logger, const struct blog_log_entry *entry, 
			char *output, size_t output_size);

#endif /* _LINUX_BLOG_DES_H */
