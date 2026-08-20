/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BLOG argument packing.
 */
#ifndef _FS_CEPH_BLOG_SER_H
#define _FS_CEPH_BLOG_SER_H

#include <linux/limits.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unaligned.h>

#define IS_STR_PTR(t) \
	(__builtin_types_compatible_p(typeof(t), const char *) || \
	 __builtin_types_compatible_p(typeof(t), char *) || \
	 __builtin_types_compatible_p(typeof(t), const unsigned char *) || \
	 __builtin_types_compatible_p(typeof(t), unsigned char *))

#define IS_STR_ARRAY(t) \
	(__builtin_types_compatible_p(typeof(t), const char []) || \
	 __builtin_types_compatible_p(typeof(t), char []) || \
	 __builtin_types_compatible_p(typeof(t), const unsigned char []) || \
	 __builtin_types_compatible_p(typeof(t), unsigned char []))

#define IS_STR(t) (IS_STR_PTR(t) || IS_STR_ARRAY(t))

struct blog_bounded_string {
	const char *str;
	size_t len;
};

#define BLOG_STR(__str, __len) \
	(&(const struct blog_bounded_string){ \
		.str = (const char *)(__str), \
		.len = (__len), \
	})

#define IS_BOUNDED_STR(t) \
	(__builtin_types_compatible_p(typeof(t), \
				      const struct blog_bounded_string *) || \
	 __builtin_types_compatible_p(typeof(t), struct blog_bounded_string *))

#define __suppress_cast_warning(type, value) \
({ \
	_Pragma("GCC diagnostic push") \
	_Pragma("GCC diagnostic ignored \"-Wint-to-pointer-cast\"") \
	_Pragma("GCC diagnostic ignored \"-Wpointer-to-int-cast\"") \
	type __scw_result; \
	__scw_result = ((type)(value)); \
	_Pragma("GCC diagnostic pop") \
	__scw_result; \
})

#define ___blog_concat(__a, __b) __a ## __b
#define ___blog_apply(__fn, __n) ___blog_concat(__fn, __n)

#define ___blog_nth(_, __1, __2, __3, __4, __5, __6, __7, __8, __9, \
	__10, __11, __12, __13, __14, __15, __16, __17, __18, __19, __20, \
	__21, __22, __23, __24, __25, __26, __27, __28, __29, __30, __31, \
	__32, __N, ...) __N
#define ___blog_narg(...) ___blog_nth(_, ##__VA_ARGS__, \
	32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, \
	16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define blog_narg(...) ___blog_narg(__VA_ARGS__)

#define STR_MAX_SIZE 255
#define BLOG_MAX_ARGS 32

/**
 * struct blog_arg - an evaluated argument and its serialization reservation
 * @value: cached scalar value
 * @str: cached string pointer
 * @string_len: measured number of source bytes, excluding the terminator
 * @reserved: bytes reserved for this argument, including string padding
 * @is_string: @str and @string_len are valid instead of @value
 *
 * Logging macros build these records before reserving pagefrag space.  String
 * expressions are therefore evaluated once, and serialization cannot copy
 * beyond the length used to calculate that string's reservation.
 */
struct blog_arg {
	union {
		u64 value;
		const char *str;
	};
	u16 string_len;
	u16 reserved;
	bool is_string;
};

static inline void blog_arg_set_string(struct blog_arg *arg, const char *str,
				       size_t limit)
{
	size_t len = 0;

	arg->is_string = true;
	arg->str = str;
	if (!str) {
		arg->string_len = 0;
		arg->reserved = sizeof("(NULL) ");
		return;
	}

	/*
	 * @limit is the caller's scan bound.  Unbounded %s passes
	 * STR_MAX_SIZE; BLOG_STR() passes the caller length (paths,
	 * NAME_MAX dentries) and must not be silently shrunk to 254.
	 * Cap only so reserved (= round_up(len + 1, 4)) fits in u16.
	 */
	limit = min_t(size_t, limit, (size_t)U16_MAX - 4);
	while (len < limit && str[len])
		len++;
	arg->string_len = len;
	arg->reserved = round_up(len + 1, 4);
}

#define const_char_ptr(str) __suppress_cast_warning(const char *, (str))
/* Integer-width round-trip so both if-branches type-check for any arg. */
#define bounded_string_ptr(str) \
	((const struct blog_bounded_string *)(unsigned long)(str))

#define BLOG_ARG(__dst, __arg) \
do { \
	struct blog_arg *__blog_arg = (__dst); \
	__auto_type __blog_value = (__arg); \
	*__blog_arg = (struct blog_arg){}; \
	if (IS_BOUNDED_STR(__blog_value)) { \
		const struct blog_bounded_string *__blog_str = \
			bounded_string_ptr(__blog_value); \
		blog_arg_set_string(__blog_arg, __blog_str->str, \
				    __blog_str->len); \
	} else if (IS_STR(__blog_value)) { \
		blog_arg_set_string(__blog_arg, const_char_ptr(__blog_value), \
				    STR_MAX_SIZE); \
	} else { \
		/* Same-width integer first so 32-bit sparse does not see \
		 * pointer-to-u64. Wider scalars still go through u64. \
		 */ \
		if (sizeof(__blog_value) == sizeof(void *)) \
			__blog_arg->value = (u64)__suppress_cast_warning( \
				unsigned long, __blog_value); \
		else \
			__blog_arg->value = __suppress_cast_warning( \
				u64, __blog_value); \
		__blog_arg->reserved = sizeof(__blog_value) < 4 ? \
			4 : sizeof(__blog_value); \
	} \
} while (0)

/*
 * Fill the per-task scratch in argument order, evaluating each expression once.
 * Each recursive step captures its destination before writing the next slot.
 * Fill each slot directly: by-value struct temporaries can grow VFS stack frames.
 */
#define ___blog_fill0(__dst, ...) ((void)(__dst))
#define ___blog_fill1(__dst, __arg) BLOG_ARG(__dst, __arg)
#define ___blog_fill2(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst2 = (__dst); \
		___blog_fill1(__blog_dst2, __arg); \
		___blog_fill1(__blog_dst2 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill3(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst3 = (__dst); \
		___blog_fill1(__blog_dst3, __arg); \
		___blog_fill2(__blog_dst3 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill4(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst4 = (__dst); \
		___blog_fill1(__blog_dst4, __arg); \
		___blog_fill3(__blog_dst4 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill5(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst5 = (__dst); \
		___blog_fill1(__blog_dst5, __arg); \
		___blog_fill4(__blog_dst5 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill6(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst6 = (__dst); \
		___blog_fill1(__blog_dst6, __arg); \
		___blog_fill5(__blog_dst6 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill7(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst7 = (__dst); \
		___blog_fill1(__blog_dst7, __arg); \
		___blog_fill6(__blog_dst7 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill8(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst8 = (__dst); \
		___blog_fill1(__blog_dst8, __arg); \
		___blog_fill7(__blog_dst8 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill9(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst9 = (__dst); \
		___blog_fill1(__blog_dst9, __arg); \
		___blog_fill8(__blog_dst9 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill10(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst10 = (__dst); \
		___blog_fill1(__blog_dst10, __arg); \
		___blog_fill9(__blog_dst10 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill11(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst11 = (__dst); \
		___blog_fill1(__blog_dst11, __arg); \
		___blog_fill10(__blog_dst11 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill12(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst12 = (__dst); \
		___blog_fill1(__blog_dst12, __arg); \
		___blog_fill11(__blog_dst12 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill13(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst13 = (__dst); \
		___blog_fill1(__blog_dst13, __arg); \
		___blog_fill12(__blog_dst13 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill14(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst14 = (__dst); \
		___blog_fill1(__blog_dst14, __arg); \
		___blog_fill13(__blog_dst14 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill15(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst15 = (__dst); \
		___blog_fill1(__blog_dst15, __arg); \
		___blog_fill14(__blog_dst15 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill16(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst16 = (__dst); \
		___blog_fill1(__blog_dst16, __arg); \
		___blog_fill15(__blog_dst16 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill17(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst17 = (__dst); \
		___blog_fill1(__blog_dst17, __arg); \
		___blog_fill16(__blog_dst17 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill18(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst18 = (__dst); \
		___blog_fill1(__blog_dst18, __arg); \
		___blog_fill17(__blog_dst18 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill19(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst19 = (__dst); \
		___blog_fill1(__blog_dst19, __arg); \
		___blog_fill18(__blog_dst19 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill20(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst20 = (__dst); \
		___blog_fill1(__blog_dst20, __arg); \
		___blog_fill19(__blog_dst20 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill21(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst21 = (__dst); \
		___blog_fill1(__blog_dst21, __arg); \
		___blog_fill20(__blog_dst21 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill22(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst22 = (__dst); \
		___blog_fill1(__blog_dst22, __arg); \
		___blog_fill21(__blog_dst22 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill23(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst23 = (__dst); \
		___blog_fill1(__blog_dst23, __arg); \
		___blog_fill22(__blog_dst23 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill24(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst24 = (__dst); \
		___blog_fill1(__blog_dst24, __arg); \
		___blog_fill23(__blog_dst24 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill25(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst25 = (__dst); \
		___blog_fill1(__blog_dst25, __arg); \
		___blog_fill24(__blog_dst25 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill26(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst26 = (__dst); \
		___blog_fill1(__blog_dst26, __arg); \
		___blog_fill25(__blog_dst26 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill27(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst27 = (__dst); \
		___blog_fill1(__blog_dst27, __arg); \
		___blog_fill26(__blog_dst27 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill28(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst28 = (__dst); \
		___blog_fill1(__blog_dst28, __arg); \
		___blog_fill27(__blog_dst28 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill29(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst29 = (__dst); \
		___blog_fill1(__blog_dst29, __arg); \
		___blog_fill28(__blog_dst29 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill30(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst30 = (__dst); \
		___blog_fill1(__blog_dst30, __arg); \
		___blog_fill29(__blog_dst30 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill31(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst31 = (__dst); \
		___blog_fill1(__blog_dst31, __arg); \
		___blog_fill30(__blog_dst31 + 1, __VA_ARGS__); \
	} while (0)
#define ___blog_fill32(__dst, __arg, ...) \
	do { \
		struct blog_arg *__blog_dst32 = (__dst); \
		___blog_fill1(__blog_dst32, __arg); \
		___blog_fill31(__blog_dst32 + 1, __VA_ARGS__); \
	} while (0)
#define BLOG_FILL_ARGS(__dst, ...) \
	___blog_apply(___blog_fill, blog_narg(__VA_ARGS__))(__dst, __VA_ARGS__)

static inline size_t blog_args_size(const struct blog_arg *args,
				    size_t nr_args)
{
	size_t size = 0;
	size_t i;

	for (i = 0; i < nr_args; i++)
		size += args[i].reserved;
	return size;
}

static inline size_t blog_serialize_string(char *dst,
					   const struct blog_arg *arg)
{
	static const char null_str[] = "(NULL) ";
	size_t limit;
	size_t count;

	if (!arg->str) {
		memcpy(dst, null_str, min(sizeof(null_str), arg->reserved));
		return arg->reserved;
	}

	limit = min(arg->string_len, arg->reserved - 1);
	for (count = 0; count < limit; count++) {
		dst[count] = arg->str[count];
		if (!dst[count])
			return round_up(count + 1, 4);
	}
	dst[count] = '\0';
	return round_up(count + 1, 4);
}

static inline void *blog_serialize_args(void *buffer,
					const struct blog_arg *args,
					size_t nr_args)
{
	char *dst = buffer;
	size_t i;

	for (i = 0; i < nr_args; i++) {
		const struct blog_arg *arg = &args[i];

		if (arg->is_string) {
			dst += blog_serialize_string(dst, arg);
		} else if (arg->reserved == 8) {
			put_unaligned(arg->value, (u64 *)dst);
			dst += 8;
		} else {
			put_unaligned((u32)arg->value, (u32 *)dst);
			dst += 4;
		}
	}
	return dst;
}

#endif /* _FS_CEPH_BLOG_SER_H */
