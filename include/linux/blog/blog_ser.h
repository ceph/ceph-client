/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Binary Logging Serialization
 */
#ifndef _LINUX_BLOG_SER_H
#define _LINUX_BLOG_SER_H

#include <linux/string.h>
#include <linux/kernel.h>

#define IS_CONST_STR_PTR(t) \
	__builtin_types_compatible_p(typeof(t), const char *)

#define IS_STR_PTR(t) \
	__builtin_types_compatible_p(typeof(t), char *)

#define IS_STR(t) \
	(__builtin_types_compatible_p(typeof(t), const char *) || \
	__builtin_types_compatible_p(typeof(t), char *))

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

#define ___blog_nth(_, __1, __2, __3, __4, __5, __6, __7, __8, __9, __10, __11, __12, __13, __14, __15, \
	__16, __17, __18, __19, __20, __21, __22, __23, __24, __25, __26, __27, __28, __29, __30, __31, __32, __N, ...) __N
#define ___blog_narg(...) ___blog_nth(_, ##__VA_ARGS__, \
	32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, \
	16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define blog_narg(...) ___blog_narg(__VA_ARGS__)

#define STR_MAX_SIZE 255
#define __sizeof(x) \
	(IS_STR(x) ? STR_MAX_SIZE : \
	 (sizeof(x) < 4) ? 4 : sizeof(x))

/* Size calculation macros */
#define ___blog_cnt0()		(0)
#define ___blog_cnt1(__t)		(__sizeof(__t))
#define ___blog_cnt2(__t, __args...)	(___blog_cnt1(__args) + __sizeof(__t))
#define ___blog_cnt3(__t, __args...)	(___blog_cnt2(__args) + __sizeof(__t))
#define ___blog_cnt4(__t, __args...)	(___blog_cnt3(__args) + __sizeof(__t))
#define ___blog_cnt5(__t, __args...)	(___blog_cnt4(__args) + __sizeof(__t))
#define ___blog_cnt6(__t, __args...)	(___blog_cnt5(__args) + __sizeof(__t))
#define ___blog_cnt7(__t, __args...)	(___blog_cnt6(__args) + __sizeof(__t))
#define ___blog_cnt8(__t, __args...)	(___blog_cnt7(__args) + __sizeof(__t))
#define ___blog_cnt9(__t, __args...)	(___blog_cnt8(__args) + __sizeof(__t))
#define ___blog_cnt10(__t, __args...)	(___blog_cnt9(__args) + __sizeof(__t))
#define ___blog_cnt11(__t, __args...)	(___blog_cnt10(__args) + __sizeof(__t))
#define ___blog_cnt12(__t, __args...)	(___blog_cnt11(__args) + __sizeof(__t))
#define ___blog_cnt13(__t, __args...)	(___blog_cnt12(__args) + __sizeof(__t))
#define ___blog_cnt14(__t, __args...)	(___blog_cnt13(__args) + __sizeof(__t))
#define ___blog_cnt15(__t, __args...)	(___blog_cnt14(__args) + __sizeof(__t))
#define ___blog_cnt16(__t, __args...)	(___blog_cnt15(__args) + __sizeof(__t))
#define ___blog_cnt17(__t, __args...)	(___blog_cnt16(__args) + __sizeof(__t))
#define ___blog_cnt18(__t, __args...)	(___blog_cnt17(__args) + __sizeof(__t))
#define ___blog_cnt19(__t, __args...)	(___blog_cnt18(__args) + __sizeof(__t))
#define ___blog_cnt20(__t, __args...)	(___blog_cnt19(__args) + __sizeof(__t))
#define ___blog_cnt21(__t, __args...)	(___blog_cnt20(__args) + __sizeof(__t))
#define ___blog_cnt22(__t, __args...)	(___blog_cnt21(__args) + __sizeof(__t))
#define ___blog_cnt23(__t, __args...)	(___blog_cnt22(__args) + __sizeof(__t))
#define ___blog_cnt24(__t, __args...)	(___blog_cnt23(__args) + __sizeof(__t))
#define ___blog_cnt25(__t, __args...)	(___blog_cnt24(__args) + __sizeof(__t))
#define ___blog_cnt26(__t, __args...)	(___blog_cnt25(__args) + __sizeof(__t))
#define ___blog_cnt27(__t, __args...)	(___blog_cnt26(__args) + __sizeof(__t))
#define ___blog_cnt28(__t, __args...)	(___blog_cnt27(__args) + __sizeof(__t))
#define ___blog_cnt29(__t, __args...)	(___blog_cnt28(__args) + __sizeof(__t))
#define ___blog_cnt30(__t, __args...)	(___blog_cnt29(__args) + __sizeof(__t))
#define ___blog_cnt31(__t, __args...)	(___blog_cnt30(__args) + __sizeof(__t))
#define ___blog_cnt32(__t, __args...)	(___blog_cnt31(__args) + __sizeof(__t))
#define blog_cnt(...)	 ___blog_apply(___blog_cnt, blog_narg(__VA_ARGS__))(__VA_ARGS__)

#define IS_STR_ARRAY(t) \
	__builtin_types_compatible_p(typeof(t), char [])

#define IS_DYNAMIC_CHAR_PTR(t) \
	(__builtin_classify_type((t)) == 14 && \
	 __builtin_types_compatible_p(typeof(t), char *) && \
	 !__builtin_constant_p((t)))

#define IS_STATIC_CHAR_ARRAY(t) \
	(__builtin_classify_type((t)) == 5 && \
	 __builtin_types_compatible_p(typeof(t), char[]) && \
	 __builtin_constant_p((t)))

#define IS_DYNAMIC_CHAR_ARRAY(t) \
	(__builtin_classify_type((t)) == 5 && \
	 __builtin_types_compatible_p(typeof(t), char[]) && \
	 !__builtin_constant_p((t)))

#define char_ptr(str) __suppress_cast_warning(char *, (str))

#ifndef _CEPH_BLOG_SER_HELPERS_DEFINED
#define _CEPH_BLOG_SER_HELPERS_DEFINED

union null_str_u {
	char str[8];
	unsigned long force_align;
};

static const union null_str_u null_str = {
	.str = "(NULL) \0"
};

static inline size_t write_null_str(char *dst)
{
	*(union null_str_u *)dst = null_str;
	static_assert(sizeof(null_str.str) == sizeof(unsigned long),
	             "null_str.str size must match unsigned long for proper alignment");
	return __builtin_strlen(null_str.str);
}

static inline size_t strscpy_n(char *dst, const char *src)
{
	size_t count = 0;

	while (count < STR_MAX_SIZE - 1) {
		dst[count] = src[count];
		if (src[count] == '\0')
			goto out;
		count++;
	}

	dst[count] = '\0';
	pr_warn("blog_ser: string truncated, exceeded max size %d\n", STR_MAX_SIZE);
out:
	return count + 1;
}

static inline ssize_t __strscpy(char *dst, const char *src)
{
	if (src != NULL)
		return strscpy_n(dst, src);
	return write_null_str(dst);
}

static inline void* strscpy_n_update(char *dst, const char *src, const char *file, int line)
{
	ssize_t ret = __strscpy(dst, src);
	if (unlikely(ret <= 0 || ret >= STR_MAX_SIZE)) {
		pr_err("blog_ser: string handling error ret=%zd at %s:%d :: dst='%s' src='%s'\n",
		       ret, file, line, dst, src ? src : "(null)");
		/* Return safely instead of panicking - truncate and continue */
		if (ret >= STR_MAX_SIZE) {
			dst[STR_MAX_SIZE - 1] = '\0';
			ret = STR_MAX_SIZE;
		} else {
			/* Handle null or empty string case */
			dst[0] = '\0';
			ret = 1;
		}
	}
	return dst + round_up(ret, 4);
}

#endif /* _CEPH_BLOG_SER_HELPERS_DEFINED */

/* Serialization type macro */
#define __blog_ser_type(__buffer, __t)                          \
	(__builtin_choose_expr((IS_DYNAMIC_CHAR_PTR((__t)) || IS_STATIC_CHAR_ARRAY((__t))),               \
		/* For static arrays (like __func__), just save pointer */   \
		(*(void **)(__buffer) = __suppress_cast_warning(void *, (__t)), \
		 (__buffer) = (void *)((char *)(__buffer) + sizeof(void *))), \
	__builtin_choose_expr(IS_STR((__t)),               \
		((__buffer) = (void *)strscpy_n_update((__buffer), char_ptr(__t), kbasename(__FILE__), __LINE__)), \
	__builtin_choose_expr(IS_STR_ARRAY((__t)),               \
		/* For dynamic arrays, save NULL and string bytes */         \
		 ((__buffer) = (void *)strscpy_n_update((__buffer), char_ptr(__t), kbasename(__FILE__), __LINE__)), \
	__builtin_choose_expr(sizeof((__t)) == 1,                         \
		(*(uint32_t *)(__buffer) = __suppress_cast_warning(uint32_t, (__t)), \
		 (__buffer) = (void *)((char *)(__buffer) + 4)),            \
	__builtin_choose_expr(sizeof((__t)) == 2, /* we have no way to differentiate u16 and u32 in deserialization */                        \
		(*(uint32_t *)(__buffer) = __suppress_cast_warning(uint32_t, (__t)), \
		 (__buffer) = (void *)((char *)(__buffer) + 4)),            \
	__builtin_choose_expr(sizeof((__t)) == 4,                         \
		(*(uint32_t *)(__buffer) = __suppress_cast_warning(uint32_t, (__t)), \
		 (__buffer) = (void *)((char *)(__buffer) + 4)),            \
	__builtin_choose_expr(sizeof((__t)) == 8,                         \
		(*(uint64_t *)(__buffer) = __suppress_cast_warning(uint64_t, (__t)), \
		 (__buffer) = (void *)((char *)(__buffer) + 8)),            \
		(pr_err("UNSUPPORTED_TYPE: %s:%d: unsupported type size %zu\n", kbasename(__FILE__), __LINE__, sizeof(__t))) \
	))))))))

/* Serialization macros */
#define ___blog_ser0(__buffer)
#define ___blog_ser1(__buffer, __t)		(__blog_ser_type(__buffer, __t))
#define ___blog_ser2(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser1(__buffer, __args))
#define ___blog_ser3(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser2(__buffer, __args))
#define ___blog_ser4(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser3(__buffer, __args))
#define ___blog_ser5(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser4(__buffer, __args))
#define ___blog_ser6(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser5(__buffer, __args))
#define ___blog_ser7(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser6(__buffer, __args))
#define ___blog_ser8(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser7(__buffer, __args))
#define ___blog_ser9(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser8(__buffer, __args))
#define ___blog_ser10(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser9(__buffer, __args))
#define ___blog_ser11(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser10(__buffer, __args))
#define ___blog_ser12(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser11(__buffer, __args))
#define ___blog_ser13(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser12(__buffer, __args))
#define ___blog_ser14(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser13(__buffer, __args))
#define ___blog_ser15(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser14(__buffer, __args))
#define ___blog_ser16(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser15(__buffer, __args))
#define ___blog_ser17(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser16(__buffer, __args))
#define ___blog_ser18(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser17(__buffer, __args))
#define ___blog_ser19(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser18(__buffer, __args))
#define ___blog_ser20(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser19(__buffer, __args))
#define ___blog_ser21(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser20(__buffer, __args))
#define ___blog_ser22(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser21(__buffer, __args))
#define ___blog_ser23(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser22(__buffer, __args))
#define ___blog_ser24(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser23(__buffer, __args))
#define ___blog_ser25(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser24(__buffer, __args))
#define ___blog_ser26(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser25(__buffer, __args))
#define ___blog_ser27(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser26(__buffer, __args))
#define ___blog_ser28(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser27(__buffer, __args))
#define ___blog_ser29(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser28(__buffer, __args))
#define ___blog_ser30(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser29(__buffer, __args))
#define ___blog_ser31(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser30(__buffer, __args))
#define ___blog_ser32(__buffer, __t, __args...)	(__blog_ser_type(__buffer, __t), ___blog_ser31(__buffer, __args))
#define ___blog_ser(__buffer, ...)	 ___blog_apply(___blog_ser, blog_narg(__VA_ARGS__))(__buffer, ##__VA_ARGS__)
#define blog_ser(...)	 ___blog_ser(__VA_ARGS__)

#endif /* _LINUX_BLOG_SER_H */
