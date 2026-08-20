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
#define bounded_string_ptr(str) \
	((const struct blog_bounded_string *)(unsigned long)(str))

#define BLOG_ARG(__arg) \
({ \
	__auto_type __blog_value = (__arg); \
	struct blog_arg __blog_arg = {}; \
	if (IS_BOUNDED_STR(__blog_value)) { \
		const struct blog_bounded_string *__blog_str = \
			bounded_string_ptr(__blog_value); \
		blog_arg_set_string(&__blog_arg, __blog_str->str, \
				    __blog_str->len); \
	} else if (IS_STR(__blog_value)) { \
		blog_arg_set_string(&__blog_arg, const_char_ptr(__blog_value), \
				    STR_MAX_SIZE); \
	} else { \
		__blog_arg.value = __suppress_cast_warning(u64, __blog_value); \
		__blog_arg.reserved = sizeof(__blog_value) < 4 ? \
			4 : sizeof(__blog_value); \
	} \
	__blog_arg; \
})

#define ___blog_args0()
#define ___blog_args1(__t) BLOG_ARG(__t)
#define ___blog_args2(__t, __args...) BLOG_ARG(__t), ___blog_args1(__args)
#define ___blog_args3(__t, __args...) BLOG_ARG(__t), ___blog_args2(__args)
#define ___blog_args4(__t, __args...) BLOG_ARG(__t), ___blog_args3(__args)
#define ___blog_args5(__t, __args...) BLOG_ARG(__t), ___blog_args4(__args)
#define ___blog_args6(__t, __args...) BLOG_ARG(__t), ___blog_args5(__args)
#define ___blog_args7(__t, __args...) BLOG_ARG(__t), ___blog_args6(__args)
#define ___blog_args8(__t, __args...) BLOG_ARG(__t), ___blog_args7(__args)
#define ___blog_args9(__t, __args...) BLOG_ARG(__t), ___blog_args8(__args)
#define ___blog_args10(__t, __args...) BLOG_ARG(__t), ___blog_args9(__args)
#define ___blog_args11(__t, __args...) BLOG_ARG(__t), ___blog_args10(__args)
#define ___blog_args12(__t, __args...) BLOG_ARG(__t), ___blog_args11(__args)
#define ___blog_args13(__t, __args...) BLOG_ARG(__t), ___blog_args12(__args)
#define ___blog_args14(__t, __args...) BLOG_ARG(__t), ___blog_args13(__args)
#define ___blog_args15(__t, __args...) BLOG_ARG(__t), ___blog_args14(__args)
#define ___blog_args16(__t, __args...) BLOG_ARG(__t), ___blog_args15(__args)
#define ___blog_args17(__t, __args...) BLOG_ARG(__t), ___blog_args16(__args)
#define ___blog_args18(__t, __args...) BLOG_ARG(__t), ___blog_args17(__args)
#define ___blog_args19(__t, __args...) BLOG_ARG(__t), ___blog_args18(__args)
#define ___blog_args20(__t, __args...) BLOG_ARG(__t), ___blog_args19(__args)
#define ___blog_args21(__t, __args...) BLOG_ARG(__t), ___blog_args20(__args)
#define ___blog_args22(__t, __args...) BLOG_ARG(__t), ___blog_args21(__args)
#define ___blog_args23(__t, __args...) BLOG_ARG(__t), ___blog_args22(__args)
#define ___blog_args24(__t, __args...) BLOG_ARG(__t), ___blog_args23(__args)
#define ___blog_args25(__t, __args...) BLOG_ARG(__t), ___blog_args24(__args)
#define ___blog_args26(__t, __args...) BLOG_ARG(__t), ___blog_args25(__args)
#define ___blog_args27(__t, __args...) BLOG_ARG(__t), ___blog_args26(__args)
#define ___blog_args28(__t, __args...) BLOG_ARG(__t), ___blog_args27(__args)
#define ___blog_args29(__t, __args...) BLOG_ARG(__t), ___blog_args28(__args)
#define ___blog_args30(__t, __args...) BLOG_ARG(__t), ___blog_args29(__args)
#define ___blog_args31(__t, __args...) BLOG_ARG(__t), ___blog_args30(__args)
#define ___blog_args32(__t, __args...) BLOG_ARG(__t), ___blog_args31(__args)
#define BLOG_ARGS(...) \
	___blog_apply(___blog_args, blog_narg(__VA_ARGS__))(__VA_ARGS__)

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
