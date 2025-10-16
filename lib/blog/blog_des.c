// SPDX-License-Identifier: GPL-2.0
/*
 * Binary Logging Deserialization
 * 
 * Migrated from ceph_san_des.c with all algorithms preserved
 */

#include <linux/blog/blog_des.h>
#include <linux/blog/blog.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/align.h>
#include <linux/unaligned.h>

/**
 * blog_des_reconstruct - Reconstructs a formatted string from serialized values
 * @fmt: Format string containing % specifiers
 * @buffer: Buffer containing serialized values
 * @nr_args: Number of arguments to process (not used yet, for future)
 * @size: Size of the buffer in bytes
 * @out: Buffer to store the reconstructed string
 * @out_size: Size of the output buffer
 *
 * Return: Number of bytes written to out buffer, or negative error code on failure
 */
int blog_des_reconstruct(const char *fmt, const void *buffer, size_t nr_args,
                          size_t size, char *out, size_t out_size)
{
	const char *buf_start = (const char *)buffer;
	const char *buf_ptr = buf_start;
	const char *buf_end = buf_start + size;
	const char *fmt_ptr = fmt;
	char *out_ptr = out;
	size_t remaining = out_size - 1; /* Reserve space for null terminator */
	size_t arg_count = 0;
	int ret;

	if (!fmt || !buffer || !out || !out_size) {
		pr_err("blog_des_reconstruct: invalid parameters\n");
		return -EINVAL;
	}

	*out_ptr = '\0';

	/* Process the format string */
	while (*fmt_ptr && remaining > 0) {
		int is_long;
		int is_long_long;

		if (*fmt_ptr != '%') {
			/* Copy literal character */
			*out_ptr++ = *fmt_ptr++;
			remaining--;
			continue;
		}

		/* Skip the '%' */
		fmt_ptr++;

		/* Handle %% */
		if (*fmt_ptr == '%') {
			*out_ptr++ = '%';
			fmt_ptr++;
			remaining--;
			continue;
		}

		/* Skip flags (-+#0 space) */
		while (*fmt_ptr && (*fmt_ptr == '-' || *fmt_ptr == '+' || *fmt_ptr == '#' ||
		                   *fmt_ptr == '0' || *fmt_ptr == ' ')) {
			fmt_ptr++;
		}

		/* Skip field width (digits or *) */
		while (*fmt_ptr && (*fmt_ptr >= '0' && *fmt_ptr <= '9')) {
			fmt_ptr++;
		}
		if (*fmt_ptr == '*') {
			fmt_ptr++;
		}

		/* Skip precision (.digits or .*) */
		if (*fmt_ptr == '.') {
			fmt_ptr++;
			while (*fmt_ptr && (*fmt_ptr >= '0' && *fmt_ptr <= '9')) {
				fmt_ptr++;
			}
			if (*fmt_ptr == '*') {
				fmt_ptr++;
			}
		}

		/* Parse length modifiers (l, ll, h, hh, z) */
		is_long = 0;
		is_long_long = 0;
		
		if (*fmt_ptr == 'l') {
			fmt_ptr++;
			is_long = 1;
			if (*fmt_ptr == 'l') {
				fmt_ptr++;
				is_long_long = 1;
				is_long = 0;
			}
		} else if (*fmt_ptr == 'h') {
			fmt_ptr++;
			if (*fmt_ptr == 'h') {
				fmt_ptr++;
			}
		} else if (*fmt_ptr == 'z') {
			fmt_ptr++;
		}

		/* Parse and handle format specifier */
		switch (*fmt_ptr) {
		case 's': { /* String (inline) */
			const char *str;
			size_t str_len;
			size_t max_scan_len;

			/* Validate we have enough buffer space for at least a null terminator */
			if (buf_ptr >= buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun at string argument\n", arg_count);
				return -EFAULT;
			}

			/* String is stored inline in buffer */
			str = buf_ptr;

			/* Calculate maximum safe length to scan for null terminator */
			max_scan_len = buf_end - buf_ptr;

			/* Find string length with bounds checking */
			str_len = strnlen(str, max_scan_len);
			if (str_len == max_scan_len && str[str_len - 1] != '\0') {
				pr_err("blog_des_reconstruct (%zu): unterminated string in buffer\n", arg_count);
				return -EFAULT;
			}

			/* Advance buffer pointer with proper alignment */
			buf_ptr += round_up(str_len + 1, 4);

			/* Check if buffer advance exceeds entry bounds */
			if (buf_ptr > buf_end) {
				pr_err("blog_des_reconstruct (%zu): string extends beyond buffer bounds\n", arg_count);
				return -EFAULT;
			}

			/* Copy string to output with bounds checking */
			if (str_len > remaining)
				str_len = remaining;
			memcpy(out_ptr, str, str_len);
			out_ptr += str_len;
			remaining -= str_len;
			break;
		}

	case 'd': case 'i': { /* Integer */
		if (is_long_long) {
			long long val;
			if (buf_ptr + sizeof(long long) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading long long\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((long long *)buf_ptr);
			buf_ptr += sizeof(long long);
			ret = snprintf(out_ptr, remaining, "%lld", val);
		} else if (is_long) {
			long val;
			if (buf_ptr + sizeof(long) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading long\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((long *)buf_ptr);
			buf_ptr += sizeof(long);
			ret = snprintf(out_ptr, remaining, "%ld", val);
		} else {
			int val;
			if (buf_ptr + sizeof(int) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading int\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((int *)buf_ptr);
			buf_ptr += sizeof(int);
			ret = snprintf(out_ptr, remaining, "%d", val);
		}
			
			if (ret > 0) {
				if (ret > remaining)
					ret = remaining;
				out_ptr += ret;
				remaining -= ret;
			}
			break;
		}

	case 'u': { /* Unsigned integer */
		if (is_long_long) {
			unsigned long long val;
			if (buf_ptr + sizeof(unsigned long long) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading unsigned long long\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((unsigned long long *)buf_ptr);
			buf_ptr += sizeof(unsigned long long);
			ret = snprintf(out_ptr, remaining, "%llu", val);
		} else if (is_long) {
			unsigned long val;
			if (buf_ptr + sizeof(unsigned long) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading unsigned long\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((unsigned long *)buf_ptr);
			buf_ptr += sizeof(unsigned long);
			ret = snprintf(out_ptr, remaining, "%lu", val);
		} else {
			unsigned int val;
			if (buf_ptr + sizeof(unsigned int) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading unsigned int\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((unsigned int *)buf_ptr);
			buf_ptr += sizeof(unsigned int);
			ret = snprintf(out_ptr, remaining, "%u", val);
		}
			
			if (ret > 0) {
				if (ret > remaining)
					ret = remaining;
				out_ptr += ret;
				remaining -= ret;
			}
			break;
		}

	case 'x': case 'X': { /* Hex integer */
		const char *hex_fmt;
		if (*fmt_ptr == 'x')
			hex_fmt = is_long_long ? "%llx" : is_long ? "%lx" : "%x";
		else
			hex_fmt = is_long_long ? "%llX" : is_long ? "%lX" : "%X";

		if (is_long_long) {
			unsigned long long val;
			if (buf_ptr + sizeof(unsigned long long) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading unsigned long long\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((unsigned long long *)buf_ptr);
			buf_ptr += sizeof(unsigned long long);
			ret = snprintf(out_ptr, remaining, hex_fmt, val);
		} else if (is_long) {
			unsigned long val;
			if (buf_ptr + sizeof(unsigned long) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading unsigned long\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((unsigned long *)buf_ptr);
			buf_ptr += sizeof(unsigned long);
			ret = snprintf(out_ptr, remaining, hex_fmt, val);
		} else {
			unsigned int val;
			if (buf_ptr + sizeof(unsigned int) > buf_end) {
				pr_err("blog_des_reconstruct (%zu): buffer overrun reading unsigned int\n", arg_count);
				return -EFAULT;
			}
			val = get_unaligned((unsigned int *)buf_ptr);
			buf_ptr += sizeof(unsigned int);
			ret = snprintf(out_ptr, remaining, hex_fmt, val);
		}
			
			if (ret > 0) {
				if (ret > remaining)
					ret = remaining;
				out_ptr += ret;
				remaining -= ret;
			}
			break;
		}

	case 'p': { /* Pointer */
		void *ptr;
		
		/* Check buffer bounds before reading */
		if (buf_ptr + sizeof(void *) > buf_end) {
			pr_err("blog_des_reconstruct (%zu): buffer overrun reading pointer\n", arg_count);
			return -EFAULT;
		}

		ptr = (void *)(unsigned long)get_unaligned((unsigned long *)buf_ptr);
		buf_ptr += sizeof(void *);

		ret = snprintf(out_ptr, remaining, "%p", ptr);
		if (ret > 0) {
			if (ret > remaining)
				ret = remaining;
			out_ptr += ret;
			remaining -= ret;
		}
		break;
	}

	case 'c': { /* Character */
		char val;
		
		/* Check buffer bounds before reading */
		if (buf_ptr + sizeof(int) > buf_end) { /* chars are promoted to int */
			pr_err("blog_des_reconstruct (%zu): buffer overrun reading char\n", arg_count);
			return -EFAULT;
		}

		val = (char)get_unaligned((int *)buf_ptr);
		buf_ptr += sizeof(int);

		if (remaining > 0) {
			*out_ptr++ = val;
			remaining--;
		}
		break;
	}

		default:
			pr_err("blog_des_reconstruct (%zu): unsupported format specifier '%%%c'\n", 
			       arg_count, *fmt_ptr);
			return -EINVAL;
		}

		fmt_ptr++;
		arg_count++;
	}

	/* Null-terminate the output */
	*out_ptr = '\0';

	return out_ptr - out;
}
EXPORT_SYMBOL(blog_des_reconstruct);

/**
 * blog_log_reconstruct - Reconstructs a formatted string from a log entry
 * @entry: Log entry containing serialized data
 * @output: Buffer to write the formatted string to
 * @output_size: Size of the output buffer
 *
 * This reconstructs the log message but does NOT handle client_id.
 * The caller should handle client_id separately using their module-specific callback.
 *
 * Return: Length of formatted string, or negative error code on failure
 */
int blog_log_reconstruct(struct blog_logger *logger, const struct blog_log_entry *entry, 
			char *output, size_t output_size)
{
	struct blog_source_info *source;
	
	if (!entry || !output || !logger)
		return -EINVAL;
	
	/* Get source info */
	source = blog_get_source_info(logger, entry->source_id);
	if (!source) {
		return snprintf(output, output_size, "[unknown source %u]", entry->source_id);
	}
	
	/* Reconstruct using the format string from source */
	return blog_des_reconstruct(source->fmt, entry->buffer, 0, entry->len,
	                           output, output_size);
}
EXPORT_SYMBOL(blog_log_reconstruct);