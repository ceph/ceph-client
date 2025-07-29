#include <linux/ceph/ceph_san_des.h>
#include <linux/ceph/ceph_san_logger.h>  /* For log entry struct and source functions */
#include <linux/string.h>   /* For strchr, strlen */
#include <linux/ctype.h>    /* For isdigit */
#include <linux/types.h>    /* For size_t */
#include <linux/kernel.h>   /* For snprintf */
#include <linux/printk.h>   /* For pr_err */
#include <linux/align.h>    /* For round_up */


int ceph_san_des_reconstruct(const char *fmt, const void *buffer, size_t nr_args,
                           size_t size, char *out, size_t out_size) {
    const char *buf_start = (const char *)buffer;
    const char *buf_ptr = buf_start;
    const char *buf_end = buf_start + size;
    const char *fmt_ptr = fmt;
    char *out_ptr = out;
    size_t remaining = out_size - 1; // Reserve space for null terminator
    size_t arg_count = 0;
    int ret;

    if (!fmt || !buffer || !out || !out_size) {
        pr_err("ceph_san_des_reconstruct: invalid parameters\n");
        return -EINVAL;
    }

    *out_ptr = '\0';

    // Process the format string
    while (*fmt_ptr && remaining > 0) {
        if (*fmt_ptr != '%') {
            // Copy literal character
            *out_ptr++ = *fmt_ptr++;
            remaining--;
            continue;
        }

        // Skip the '%'
        fmt_ptr++;

        // Handle %%
        if (*fmt_ptr == '%') {
            *out_ptr++ = '%';
            fmt_ptr++;
            remaining--;
            continue;
        }

        // Skip flags (-+#0 space)
        while (*fmt_ptr && (*fmt_ptr == '-' || *fmt_ptr == '+' || *fmt_ptr == '#' || 
                           *fmt_ptr == '0' || *fmt_ptr == ' ')) {
            fmt_ptr++;
        }

        // Skip field width (digits or *)
        while (*fmt_ptr && (*fmt_ptr >= '0' && *fmt_ptr <= '9')) {
            fmt_ptr++;
        }
        if (*fmt_ptr == '*') {
            fmt_ptr++;
        }

        // Skip precision (.digits or .*)
        if (*fmt_ptr == '.') {
            fmt_ptr++;
            while (*fmt_ptr && (*fmt_ptr >= '0' && *fmt_ptr <= '9')) {
                fmt_ptr++;
            }
            if (*fmt_ptr == '*') {
                fmt_ptr++;
            }
        }

        // Check argument count limit
        if (arg_count >= nr_args) {
            pr_err("ceph_san_des_reconstruct (%zu): too many format specifiers, expected %zu args. Format: '%.100s'\n", 
                   arg_count, nr_args, fmt);
            return -EINVAL;
        }

        // Parse and handle format specifier
        switch (*fmt_ptr) {
        case 's': { // String (inline)
            const char *str;
            size_t str_len;
            size_t max_scan_len;

            // Validate we have enough buffer space for at least a null terminator
            if (buf_ptr >= buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun at string argument\n", arg_count);
                return -EFAULT;
            }

            // String is stored inline in buffer
            str = buf_ptr;

            // Calculate maximum safe length to scan for null terminator
            max_scan_len = buf_end - buf_ptr;

            // Find string length with bounds checking
            str_len = strnlen(str, max_scan_len);
            if (str_len == max_scan_len && str[str_len - 1] != '\0') {
                pr_err("ceph_san_des_reconstruct (%zu): unterminated string in buffer\n", arg_count);
                return -EFAULT;
            }

            // Advance buffer pointer with proper alignment
            buf_ptr += round_up(str_len + 1, 4);

            // Check if buffer advance exceeds entry bounds
            if (buf_ptr > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): string extends beyond buffer bounds\n", arg_count);
                return -EFAULT;
            }

            // Copy string to output with bounds checking
            if (str_len > remaining)
                str_len = remaining;
            memcpy(out_ptr, str, str_len);
            out_ptr += str_len;
            remaining -= str_len;
            break;
        }

        case 'd': case 'i': { // Integer
            int val;

            // Check buffer bounds before reading
            if (buf_ptr + sizeof(int) > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading int\n", arg_count);
                return -EFAULT;
            }

            val = *(int *)buf_ptr;
            buf_ptr += sizeof(int);

            ret = snprintf(out_ptr, remaining, "%d", val);
            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'u': { // Unsigned integer
            unsigned int val;

            // Check buffer bounds before reading
            if (buf_ptr + sizeof(unsigned int) > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned int\n", arg_count);
                return -EFAULT;
            }

            val = *(unsigned int *)buf_ptr;
            buf_ptr += sizeof(unsigned int);

            ret = snprintf(out_ptr, remaining, "%u", val);
            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'x': { // Hex integer (lowercase)
            unsigned int val;

            // Check buffer bounds before reading
            if (buf_ptr + sizeof(unsigned int) > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned int\n", arg_count);
                return -EFAULT;
            }

            val = *(unsigned int *)buf_ptr;
            buf_ptr += sizeof(unsigned int);

            ret = snprintf(out_ptr, remaining, "%x", val);
            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'X': { // Hex integer (uppercase)
            unsigned int val;

            // Check buffer bounds before reading
            if (buf_ptr + sizeof(unsigned int) > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned int\n", arg_count);
                return -EFAULT;
            }

            val = *(unsigned int *)buf_ptr;
            buf_ptr += sizeof(unsigned int);

            ret = snprintf(out_ptr, remaining, "%X", val);
            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'o': { // Octal integer
            unsigned int val;

            // Check buffer bounds before reading
            if (buf_ptr + sizeof(unsigned int) > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned int\n", arg_count);
                return -EFAULT;
            }

            val = *(unsigned int *)buf_ptr;
            buf_ptr += sizeof(unsigned int);

            ret = snprintf(out_ptr, remaining, "%o", val);
            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'p': { // Pointer
            void *val;

            // Check buffer bounds before reading
            if (buf_ptr + sizeof(void *) > buf_end) {
                pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading pointer\n", arg_count);
                return -EFAULT;
            }

            val = *(void **)buf_ptr;
            buf_ptr += sizeof(void *);

            ret = snprintf(out_ptr, remaining, "%p", val);
            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'l': { // Long types
            fmt_ptr++; // Skip 'l'
            if (*fmt_ptr == 'l') { // Long long
                fmt_ptr++; // Skip second 'l'
                if (*fmt_ptr == 'd' || *fmt_ptr == 'i') {
                    long long val;
                    if (buf_ptr + sizeof(long long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading long long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(long long *)buf_ptr;
                    buf_ptr += sizeof(long long);
                    ret = snprintf(out_ptr, remaining, "%lld", val);
                } else if (*fmt_ptr == 'u') {
                    unsigned long long val;
                    if (buf_ptr + sizeof(unsigned long long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long long);
                    ret = snprintf(out_ptr, remaining, "%llu", val);
                } else if (*fmt_ptr == 'x') {
                    unsigned long long val;
                    if (buf_ptr + sizeof(unsigned long long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long long);
                    ret = snprintf(out_ptr, remaining, "%llx", val);
                } else if (*fmt_ptr == 'X') {
                    unsigned long long val;
                    if (buf_ptr + sizeof(unsigned long long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long long);
                    ret = snprintf(out_ptr, remaining, "%llX", val);
                } else if (*fmt_ptr == 'o') {
                    unsigned long long val;
                    if (buf_ptr + sizeof(unsigned long long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long long);
                    ret = snprintf(out_ptr, remaining, "%llo", val);
                } else {
                    pr_err("ceph_san_des_reconstruct: invalid long long format specifier '%%ll%c'\n", *fmt_ptr);
                    return -EINVAL;
                }
            } else { // Long
                if (*fmt_ptr == 'd' || *fmt_ptr == 'i') {
                    long val;
                    if (buf_ptr + sizeof(long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(long *)buf_ptr;
                    buf_ptr += sizeof(long);
                    ret = snprintf(out_ptr, remaining, "%ld", val);
                } else if (*fmt_ptr == 'u') {
                    unsigned long val;
                    if (buf_ptr + sizeof(unsigned long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long);
                    ret = snprintf(out_ptr, remaining, "%lu", val);
                } else if (*fmt_ptr == 'x') {
                    unsigned long val;
                    if (buf_ptr + sizeof(unsigned long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long);
                    ret = snprintf(out_ptr, remaining, "%lx", val);
                } else if (*fmt_ptr == 'X') {
                    unsigned long val;
                    if (buf_ptr + sizeof(unsigned long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long);
                    ret = snprintf(out_ptr, remaining, "%lX", val);
                } else if (*fmt_ptr == 'o') {
                    unsigned long val;
                    if (buf_ptr + sizeof(unsigned long) > buf_end) {
                        pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading unsigned long\n", arg_count);
                        return -EFAULT;
                    }
                    val = *(unsigned long *)buf_ptr;
                    buf_ptr += sizeof(unsigned long);
                    ret = snprintf(out_ptr, remaining, "%lo", val);
                } else {
                    pr_err("ceph_san_des_reconstruct: invalid long format specifier '%%l%c'\n", *fmt_ptr);
                    return -EINVAL;
                }
            }

            if (ret > 0) {
                if (ret > remaining)
                    ret = remaining;
                out_ptr += ret;
                remaining -= ret;
            }
            break;
        }

        case 'z': { // size_t
            fmt_ptr++; // Skip 'z'
            if (*fmt_ptr == 'u') {
                size_t val;
                if (buf_ptr + sizeof(size_t) > buf_end) {
                    pr_err("ceph_san_des_reconstruct (%zu): buffer overrun reading size_t\n", arg_count);
                    return -EFAULT;
                }
                val = *(size_t *)buf_ptr;
                buf_ptr += sizeof(size_t);
                ret = snprintf(out_ptr, remaining, "%zu", val);
                if (ret > 0) {
                    if (ret > remaining)
                        ret = remaining;
                    out_ptr += ret;
                    remaining -= ret;
                }
            } else {
                pr_err("ceph_san_des_reconstruct: invalid size_t format specifier '%%z%c'\n", *fmt_ptr);
                return -EINVAL;
            }
            break;
        }

        default:
            // Unknown format specifier
            pr_err("ceph_san_des_reconstruct: unknown format specifier '%%%c'\n", *fmt_ptr);
            return -EINVAL;
        }

        fmt_ptr++;
        arg_count++;
    }

    // Remove trailing newline if present
    if (out_ptr > out && *(out_ptr - 1) == '\n') {
        *(out_ptr - 1) = '\0';
    } else {
        *out_ptr = '\0';
    }

    return out_size - remaining - 1;
}

/**
 * ceph_san_log_reconstruct - Reconstruct a formatted string from a log entry
 * @entry: Log entry containing serialized data
 * @output: Buffer to write the formatted string to
 * @output_size: Size of the output buffer
 *
 * This is a wrapper around ceph_san_des_reconstruct that handles log entry parsing.
 * It extracts the format string from the source info and calls the core reconstruction function.
 *
 * Returns length of formatted string, or negative error code on failure
 */
int ceph_san_log_reconstruct(const struct ceph_san_log_entry *entry, char *output, size_t output_size)
{
    const struct ceph_san_source_info *info;
    const char *fmt;

    if (!entry || !output || output_size == 0) {
        pr_err("ceph_san_log_reconstruct: invalid parameters\n");
        return -EINVAL;
    }

    /* Verify entry is a valid kernel address */
    if (!is_valid_kernel_addr(entry)) {
        pr_err("ceph_san_log_reconstruct: invalid entry pointer %p\n", entry);
        return -EFAULT;
    }

    /* Verify entry buffer is a valid kernel address */
    if (!is_valid_kernel_addr(entry->buffer)) {
        pr_err("ceph_san_log_reconstruct: invalid buffer pointer %p for entry %p\n",
               entry->buffer, entry);
        return -EFAULT;
    }

#if CEPH_SAN_DEBUG_POISON
    if (entry->debug_poison != CEPH_SAN_LOG_ENTRY_POISON) {
        pr_err("ceph_san_log_reconstruct: corrupted log entry detected\n");
        return -EFAULT;
    }
#endif

    // Get format string from source info
    info = ceph_san_get_source_info(entry->source_id);
    if (!info) {
        pr_err("ceph_san_log_reconstruct: source info not found for ID %u\n", entry->source_id);
        return -EINVAL;
    }

    fmt = info->fmt;
    if (!fmt) {
        pr_err("ceph_san_log_reconstruct: format string not found in source info for ID %u\n", entry->source_id);
        return -EINVAL;
    }

    // Count arguments in format string to pass to des_reconstruct
    // This must match the parsing logic in ceph_san_des_reconstruct exactly
    size_t nr_args = 0;
    const char *p = fmt;
    while (*p) {
        if (*p == '%') {
            p++; // Skip '%'
            
            // Handle %%
            if (*p == '%') {
                p++;
                continue;
            }
            
            // Skip flags (-+#0 space)
            while (*p && (*p == '-' || *p == '+' || *p == '#' || 
                         *p == '0' || *p == ' ')) {
                p++;
            }

            // Skip field width (digits or *)
            while (*p && (*p >= '0' && *p <= '9')) {
                p++;
            }
            if (*p == '*') {
                p++;
            }

            // Skip precision (.digits or .*)
            if (*p == '.') {
                p++;
                while (*p && (*p >= '0' && *p <= '9')) {
                    p++;
                }
                if (*p == '*') {
                    p++;
                }
            }
            
            // Check if we have a valid conversion specifier
            if (*p == 's' || *p == 'd' || *p == 'i' || *p == 'u' || *p == 'p' ||
                *p == 'x' || *p == 'X' || *p == 'o' || *p == 'z') {
                nr_args++;
            } else if (*p == 'l') {
                // Handle long types
                p++; // Skip 'l'
                if (*p == 'l') {
                    p++; // Skip second 'l' for long long
                }
                // Now check the conversion specifier
                if (*p == 'd' || *p == 'i' || *p == 'u' || *p == 'x' || 
                    *p == 'X' || *p == 'o') {
                    nr_args++;
                }
            }
        }
        if (*p) p++;
    }

    // Call the core reconstruction function
    return ceph_san_des_reconstruct(fmt, entry->buffer, nr_args, entry->len, output, output_size);
}
EXPORT_SYMBOL(ceph_san_log_reconstruct);
