// SPDX-License-Identifier: GPL-2.0
/*
 * BLOG record deserialization.
 */

#include "blog_des.h"
#include "blog.h"
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/align.h>
#include <linux/unaligned.h>

static inline void des_advance(int ret, char **out, size_t *remaining)
{
	if (ret > 0) {
		if ((size_t)ret > *remaining)
			ret = *remaining;
		*out += ret;
		*remaining -= ret;
	}
}

/**
 * blog_des_reconstruct - Reconstructs a formatted string from serialized values
 * @fmt: Format string containing % specifiers
 * @buffer: Buffer containing serialized values
 * @size: Size of the buffer in bytes
 * @out: Buffer to store the reconstructed string
 * @out_size: Size of the output buffer
 */
int blog_des_reconstruct(const char *fmt, const void *buffer,
			 size_t size, char *out, size_t out_size)
{
	const char *buf_start = (const char *)buffer;
	const char *buf_ptr = buf_start;
	const char *buf_end = buf_start + size;
	const char *fmt_ptr = fmt;
	char *out_ptr = out;
	/* Payload budget; snprintf() is called with remaining + 1 so the
	 * last character that still fits is not dropped for the NUL. */
	size_t remaining = out_size - 1;
	size_t arg_count = 0;
	int ret;

	if (!fmt || !buffer || !out || !out_size) {
		pr_err_ratelimited("blog_des_reconstruct: invalid params fmt=%p buffer=%p out=%p out_size=%zu\n",
			fmt, buffer, out, out_size);
		return -EINVAL;
	}

	*out_ptr = '\0';

	while (*fmt_ptr && remaining > 0) {
		int is_long;
		int is_long_long;
		int alt_form = 0;
		int dyn_width = -1;
		int dyn_precision = -1;

		if (*fmt_ptr != '%') {
			*out_ptr++ = *fmt_ptr++;
			remaining--;
			continue;
		}

		fmt_ptr++;

		if (*fmt_ptr == '%') {
			*out_ptr++ = '%';
			fmt_ptr++;
			remaining--;
			continue;
		}

		/* Skip flags (-+#0 space); remember '#' for hex/octal. */
		while (*fmt_ptr && (*fmt_ptr == '-' || *fmt_ptr == '+' || *fmt_ptr == '#' ||
				   *fmt_ptr == '0' || *fmt_ptr == ' ')) {
			if (*fmt_ptr == '#')
				alt_form = 1;
			fmt_ptr++;
		}

		/* Consume field width: digits are format-only, * is serialized */
		while (*fmt_ptr && (*fmt_ptr >= '0' && *fmt_ptr <= '9'))
			fmt_ptr++;
		if (*fmt_ptr == '*') {
			if (buf_ptr + sizeof(int) > buf_end)
				return -EBADMSG;
			dyn_width = get_unaligned((int *)buf_ptr);
			buf_ptr += sizeof(int);
			fmt_ptr++;
		}

		/* Consume precision: digits are format-only, * is serialized */
		if (*fmt_ptr == '.') {
			fmt_ptr++;
			while (*fmt_ptr && (*fmt_ptr >= '0' && *fmt_ptr <= '9'))
				fmt_ptr++;
			if (*fmt_ptr == '*') {
				if (buf_ptr + sizeof(int) > buf_end)
					return -EBADMSG;
				dyn_precision = get_unaligned((int *)buf_ptr);
				buf_ptr += sizeof(int);
				fmt_ptr++;
			}
		}

		/*
		 * dyn_width: consumed from the buffer to keep offsets
		 * aligned; output width-padding is not implemented.
		 */
		(void)dyn_width;

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
			if (*fmt_ptr == 'h')
				fmt_ptr++;
		} else if (*fmt_ptr == 'z') {
			fmt_ptr++;
			if (sizeof(size_t) == sizeof(long long))
				is_long_long = 1;
			else
				is_long = 1;
		}

		switch (*fmt_ptr) {
		case 's': {
			const char *str;
			size_t str_len;
			size_t out_len;
			size_t max_scan_len;

			if (buf_ptr >= buf_end) {
				pr_err_ratelimited("blog_des_reconstruct: string arg %zu overruns buffer (no space)\n",
					       arg_count);
				return -EBADMSG;
			}

			str = buf_ptr;
			max_scan_len = buf_end - buf_ptr;

			str_len = strnlen(str, max_scan_len);
			if (str_len == max_scan_len && str[str_len - 1] != '\0') {
				pr_err_ratelimited("blog_des_reconstruct: unterminated string at arg %zu (fmt=%s)\n",
					       arg_count, fmt);
				return -EBADMSG;
			}

			buf_ptr += round_up(str_len + 1, 4);
			if (buf_ptr > buf_end) {
				pr_err_ratelimited("blog_des_reconstruct: string arg %zu overruns buffer after copy (fmt=%s)\n",
					       arg_count, fmt);
				return -EBADMSG;
			}

			out_len = str_len;
			if (dyn_precision >= 0 && (size_t)dyn_precision < out_len)
				out_len = (size_t)dyn_precision;
			if (out_len > remaining)
				out_len = remaining;
			memcpy(out_ptr, str, out_len);
			out_ptr += out_len;
			remaining -= out_len;
			break;
		}
		case 'd':
		case 'i': {
			if (is_long_long) {
				long long val;

				if (buf_ptr + sizeof(long long) > buf_end)
					return -EBADMSG;
				val = get_unaligned((long long *)buf_ptr);
				buf_ptr += sizeof(long long);
				ret = snprintf(out_ptr, remaining + 1, "%lld", val);
			} else if (is_long) {
				long val;

				if (buf_ptr + sizeof(long) > buf_end)
					return -EBADMSG;
				val = get_unaligned((long *)buf_ptr);
				buf_ptr += sizeof(long);
				ret = snprintf(out_ptr, remaining + 1, "%ld", val);
			} else {
				int val;

				if (buf_ptr + sizeof(int) > buf_end)
					return -EBADMSG;
				val = get_unaligned((int *)buf_ptr);
				buf_ptr += sizeof(int);
				ret = snprintf(out_ptr, remaining + 1, "%d", val);
			}
			des_advance(ret, &out_ptr, &remaining);
			break;
		}
		case 'u': {
			if (is_long_long) {
				unsigned long long val;

				if (buf_ptr + sizeof(unsigned long long) > buf_end)
					return -EBADMSG;
				val = get_unaligned((unsigned long long *)buf_ptr);
				buf_ptr += sizeof(unsigned long long);
				ret = snprintf(out_ptr, remaining + 1, "%llu", val);
			} else if (is_long) {
				unsigned long val;

				if (buf_ptr + sizeof(unsigned long) > buf_end)
					return -EBADMSG;
				val = get_unaligned((unsigned long *)buf_ptr);
				buf_ptr += sizeof(unsigned long);
				ret = snprintf(out_ptr, remaining + 1, "%lu", val);
			} else {
				unsigned int val;

				if (buf_ptr + sizeof(unsigned int) > buf_end)
					return -EBADMSG;
				val = get_unaligned((unsigned int *)buf_ptr);
				buf_ptr += sizeof(unsigned int);
				ret = snprintf(out_ptr, remaining + 1, "%u", val);
			}
			des_advance(ret, &out_ptr, &remaining);
			break;
		}
		case 'o':
		case 'x':
		case 'X': {
			const char *num_fmt;

			if (*fmt_ptr == 'o')
				num_fmt = is_long_long ? (alt_form ? "%#llo" : "%llo") :
					  is_long ? (alt_form ? "%#lo" : "%lo") :
					  (alt_form ? "%#o" : "%o");
			else if (*fmt_ptr == 'x')
				num_fmt = is_long_long ? (alt_form ? "%#llx" : "%llx") :
					  is_long ? (alt_form ? "%#lx" : "%lx") :
					  (alt_form ? "%#x" : "%x");
			else
				num_fmt = is_long_long ? (alt_form ? "%#llX" : "%llX") :
					  is_long ? (alt_form ? "%#lX" : "%lX") :
					  (alt_form ? "%#X" : "%X");

			if (is_long_long) {
				unsigned long long val;

				if (buf_ptr + sizeof(unsigned long long) > buf_end)
					return -EBADMSG;
				val = get_unaligned((unsigned long long *)buf_ptr);
				buf_ptr += sizeof(unsigned long long);
				ret = snprintf(out_ptr, remaining + 1, num_fmt, val);
			} else if (is_long) {
				unsigned long val;

				if (buf_ptr + sizeof(unsigned long) > buf_end)
					return -EBADMSG;
				val = get_unaligned((unsigned long *)buf_ptr);
				buf_ptr += sizeof(unsigned long);
				ret = snprintf(out_ptr, remaining + 1, num_fmt, val);
			} else {
				unsigned int val;

				if (buf_ptr + sizeof(unsigned int) > buf_end)
					return -EBADMSG;
				val = get_unaligned((unsigned int *)buf_ptr);
				buf_ptr += sizeof(unsigned int);
				ret = snprintf(out_ptr, remaining + 1, num_fmt, val);
			}
			des_advance(ret, &out_ptr, &remaining);
			break;
		}
		case 'p': {
			void *ptr;

			if (buf_ptr + sizeof(void *) > buf_end)
				return -EBADMSG;

			ptr = (void *)(unsigned long)get_unaligned((unsigned long *)buf_ptr);
			buf_ptr += sizeof(void *);

			/*
			 * Skip kernel %p sub-specifiers (U, I, d, D, etc.).
			 * bout/boutc do not support %p extensions; call sites
			 * must pre-format them with snprintf and pass %s.
			 */
			while (fmt_ptr[1] && isalnum(fmt_ptr[1]))
				fmt_ptr++;

			ret = snprintf(out_ptr, remaining + 1, "%p", ptr);
			des_advance(ret, &out_ptr, &remaining);
			break;
		}
		case 'c': {
			char val;

			if (buf_ptr + sizeof(int) > buf_end)
				return -EBADMSG;

			val = (char)get_unaligned((int *)buf_ptr);
			buf_ptr += sizeof(int);

			if (remaining > 0) {
				*out_ptr++ = val;
				remaining--;
			}
			break;
		}
		default:
			pr_err_ratelimited("%s: unsupported format specifier '%%%c' at argument %zu\n",
				       __func__, *fmt_ptr, arg_count);
			return -EINVAL;
		}

		fmt_ptr++;
		arg_count++;
	}

	*out_ptr = '\0';

	return out_ptr - out;
}
