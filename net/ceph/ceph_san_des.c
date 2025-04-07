#include <linux/ceph/ceph_san_des.h>
#include <linux/string.h>   /* For strchr, strlen */
#include <linux/ctype.h>    /* For isdigit */
#include <linux/types.h>    /* For size_t */
#include <linux/kernel.h>   /* For snprintf */

static int parse_format_specifier(const char **fmt, char *spec) {
    const char *p = *fmt;
    char *s = spec;

    /* Skip the '%' */
    if (*p != '%') return -1;
    *s++ = *p++;

    /* Skip flags */
    while (*p && (*p == '-' || *p == '+' || *p == ' ' || *p == '#' || *p == '0')) {
        *s++ = *p++;
    }

    /* Skip field width */
    while (*p && isdigit(*p)) {
        *s++ = *p++;
    }

    /* Skip precision */
    if (*p == '.') {
        *s++ = *p++;
        while (*p && isdigit(*p)) {
            *s++ = *p++;
        }
    }

    /* Get length modifier */
    if (*p == 'h' || *p == 'l' || *p == 'L' || *p == 'j' || *p == 'z' || *p == 't') {
        *s++ = *p++;
        if ((*p == 'h' || *p == 'l') && *(p-1) == *p) {
            *s++ = *p++;
        }
    }

    /* Get conversion specifier */
    if (*p && strchr("diouxXeEfFgGaAcspn%", *p)) {
        *s++ = *p++;
    } else {
        return -1;
    }

    *s = '\0';
    *fmt = p;
    return 0;
}

int ceph_san_des_reconstruct(const char *fmt, const void *buffer, size_t nr_args,
                           size_t size, char *out, size_t out_size) {
    const unsigned char *buf = buffer;
    const char *p = fmt;
    char spec[32];
    size_t offset = 0;
    size_t out_offset = 0;
    size_t arg_count = 0;

    if (!fmt || !buffer || !out || !out_size) {
        return -1;
    }
    //printf("Starting reconstruction with buffer at %p, size %zu, nr_args %zu, out_size %zu\n",
    //       buffer, size, nr_args, out_size);
    while (*p && out_offset < out_size - 1) {
        if (*p != '%') {
            out[out_offset++] = *p++;
            continue;
        }

        if (parse_format_specifier(&p, spec) < 0) {
            return -1;
        }

        if (arg_count >= nr_args) {
            return -1;
        }

        /* Check buffer overflow */
        if (offset >= size) {
            return -1;
        }

        //printf("Processing specifier '%s' at offset %zu\n", spec, offset);

        /* Handle different format specifiers */
        switch (spec[strlen(spec)-1]) {
            case 'd':
            case 'i':
            case 'o':
            case 'u':
            case 'x':
            case 'X': {
                long long val;
                const void *ptr = buf + offset;
                if (strchr(spec, 'l')) {
                    val = *(const long long*)ptr;
                    offset += sizeof(long long);
                } else {
                    val = *(const int*)ptr;
                    offset += sizeof(int);
                }
                //printf("Read integer value: %lld at address %p (offset %zu)\n", val, ptr, offset);
                out_offset += snprintf(out + out_offset, out_size - out_offset, spec, val);
                break;
            }

            case 'f':
            case 'e':
            case 'E':
            case 'g':
            case 'G':
            case 'a':
            case 'A': {
                double val = *(const double*)(buf + offset);
                offset += sizeof(double);
                //printf("Read double value: %f at offset %zu\n", val, offset - sizeof(double));
                out_offset += snprintf(out + out_offset, out_size - out_offset, spec, val);
                break;
            }

            case 'c': {
                char val = *(const char*)(buf + offset);
                offset += sizeof(char);
                //printf("Read char value: %c at offset %zu\n", val, offset - sizeof(char));
                out_offset += snprintf(out + out_offset, out_size - out_offset, spec, val);
                break;
            }

            case 's': {
                const char *val = *(const char**)(buf + offset);
                offset += sizeof(const char*);
                //printf("Read string pointer: %p at offset %zu\n", val, offset - sizeof(const char*));
                out_offset += snprintf(out + out_offset, out_size - out_offset, spec, val);
                break;
            }

            case 'p': {
                const void *val = *(const void**)(buf + offset);
                offset += sizeof(const void*);
                //printf("Read pointer value: %p at offset %zu\n", val, offset - sizeof(const void*));
                out_offset += snprintf(out + out_offset, out_size - out_offset, spec, val);
                break;
            }

            case '%': {
                out[out_offset++] = '%';
                break;
            }

            default:
                return -1;
        }

        arg_count++;
    }

    out[out_offset] = '\0';
    return out_offset;
}
