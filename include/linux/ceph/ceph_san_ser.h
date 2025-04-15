#ifndef CEPH_SAN_SER_H
#define CEPH_SAN_SER_H

#define __suppress_cast_warning(type, value) \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wint-to-pointer-cast\"") \
    _Pragma("GCC diagnostic ignored \"-Wpointer-to-int-cast\"") \
    ((type)(value)) \
    _Pragma("GCC diagnostic pop")

#define ___ceph_san_concat(__a, __b) __a ## __b
#define ___ceph_san_apply(__fn, __n) ___ceph_san_concat(__fn, __n)

#define ___ceph_san_nth(_, __1, __2, __3, __4, __5, __6, __7, __8, __9, __10, __11, __12, __13, __14, __15, \
    __16, __17, __18, __19, __20, __21, __22, __23, __24, __25, __26, __27, __28, __29, __30, __31, __32, __N, ...) __N
#define ___ceph_san_narg(...) ___ceph_san_nth(_, ##__VA_ARGS__, \
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, \
    16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define ceph_san_narg(...) ___ceph_san_narg(__VA_ARGS__)

#define ___ceph_san_cnt0()		(0)
#define ___ceph_san_cnt1(__t)		(sizeof(__t))
#define ___ceph_san_cnt2(__t, __args...)	(___ceph_san_cnt1(__args) + sizeof(__t))
#define ___ceph_san_cnt3(__t, __args...)	(___ceph_san_cnt2(__args) + sizeof(__t))
#define ___ceph_san_cnt4(__t, __args...)	(___ceph_san_cnt3(__args) + sizeof(__t))
#define ___ceph_san_cnt5(__t, __args...)	(___ceph_san_cnt4(__args) + sizeof(__t))
#define ___ceph_san_cnt6(__t, __args...)	(___ceph_san_cnt5(__args) + sizeof(__t))
#define ___ceph_san_cnt7(__t, __args...)	(___ceph_san_cnt6(__args) + sizeof(__t))
#define ___ceph_san_cnt8(__t, __args...)	(___ceph_san_cnt7(__args) + sizeof(__t))
#define ___ceph_san_cnt9(__t, __args...)	(___ceph_san_cnt8(__args) + sizeof(__t))
#define ___ceph_san_cnt10(__t, __args...)	(___ceph_san_cnt9(__args) + sizeof(__t))
#define ___ceph_san_cnt11(__t, __args...)	(___ceph_san_cnt10(__args) + sizeof(__t))
#define ___ceph_san_cnt12(__t, __args...)	(___ceph_san_cnt11(__args) + sizeof(__t))
#define ___ceph_san_cnt13(__t, __args...)	(___ceph_san_cnt12(__args) + sizeof(__t))
#define ___ceph_san_cnt14(__t, __args...)	(___ceph_san_cnt13(__args) + sizeof(__t))
#define ___ceph_san_cnt15(__t, __args...)	(___ceph_san_cnt14(__args) + sizeof(__t))
#define ___ceph_san_cnt16(__t, __args...)	(___ceph_san_cnt15(__args) + sizeof(__t))
#define ___ceph_san_cnt17(__t, __args...)	(___ceph_san_cnt16(__args) + sizeof(__t))
#define ___ceph_san_cnt18(__t, __args...)	(___ceph_san_cnt17(__args) + sizeof(__t))
#define ___ceph_san_cnt19(__t, __args...)	(___ceph_san_cnt18(__args) + sizeof(__t))
#define ___ceph_san_cnt20(__t, __args...)	(___ceph_san_cnt19(__args) + sizeof(__t))
#define ___ceph_san_cnt21(__t, __args...)	(___ceph_san_cnt20(__args) + sizeof(__t))
#define ___ceph_san_cnt22(__t, __args...)	(___ceph_san_cnt21(__args) + sizeof(__t))
#define ___ceph_san_cnt23(__t, __args...)	(___ceph_san_cnt22(__args) + sizeof(__t))
#define ___ceph_san_cnt24(__t, __args...)	(___ceph_san_cnt23(__args) + sizeof(__t))
#define ___ceph_san_cnt25(__t, __args...)	(___ceph_san_cnt24(__args) + sizeof(__t))
#define ___ceph_san_cnt26(__t, __args...)	(___ceph_san_cnt25(__args) + sizeof(__t))
#define ___ceph_san_cnt27(__t, __args...)	(___ceph_san_cnt26(__args) + sizeof(__t))
#define ___ceph_san_cnt28(__t, __args...)	(___ceph_san_cnt27(__args) + sizeof(__t))
#define ___ceph_san_cnt29(__t, __args...)	(___ceph_san_cnt28(__args) + sizeof(__t))
#define ___ceph_san_cnt30(__t, __args...)	(___ceph_san_cnt29(__args) + sizeof(__t))
#define ___ceph_san_cnt31(__t, __args...)	(___ceph_san_cnt30(__args) + sizeof(__t))
#define ___ceph_san_cnt32(__t, __args...)	(___ceph_san_cnt31(__args) + sizeof(__t))
#define ceph_san_cnt(...)	 ___ceph_san_apply(___ceph_san_cnt, ceph_san_narg(__VA_ARGS__))(__VA_ARGS__)

#define IS_STATIC_CHAR_ARRAY(t) \
    (__builtin_classify_type(t) == 5 && \
     __builtin_types_compatible_p(typeof(t), char[]) && \
     __builtin_constant_p(t))

#define IS_DYNAMIC_CHAR_ARRAY(t) \
    (__builtin_classify_type(t) == 5 && \
     __builtin_types_compatible_p(typeof(t), char[]) && \
     !__builtin_constant_p(t))

#define __ceph_san_ser_type(__buffer, __t)                          \
    (__builtin_choose_expr(IS_STATIC_CHAR_ARRAY(__t),               \
        /* For static arrays (like __func__), just save pointer */   \
        (*(void **)(__buffer) = __suppress_cast_warning(void *, __t), \
         (__buffer) = (void *)((char *)(__buffer) + sizeof(void *))), \
    __builtin_choose_expr(IS_DYNAMIC_CHAR_ARRAY(__t),               \
        /* For dynamic arrays, save NULL and string bytes */         \
        (*(void **)(__buffer) = NULL,                               \
         (__buffer) = (void *)((char *)(__buffer) + sizeof(void *)), \
         memcpy((__buffer), __suppress_cast_warning(char *, __t), __builtin_strlen(__suppress_cast_warning(char *, __t)) + 1), \
         (__buffer) = (void *)((char *)(__buffer) + __builtin_strlen(__suppress_cast_warning(char *, __t)) + 1)), \
    __builtin_choose_expr(sizeof(__t) == 1,                         \
        (*(uint8_t *)(__buffer) = __suppress_cast_warning(uint8_t, __t), \
         (__buffer) = (void *)((char *)(__buffer) + 1)),            \
    __builtin_choose_expr(sizeof(__t) == 2,                         \
        (*(uint16_t *)(__buffer) = __suppress_cast_warning(uint16_t, __t), \
         (__buffer) = (void *)((char *)(__buffer) + 2)),            \
    __builtin_choose_expr(sizeof(__t) == 4,                         \
        (*(uint32_t *)(__buffer) = __suppress_cast_warning(uint32_t, __t), \
         (__buffer) = (void *)((char *)(__buffer) + 4)),            \
    __builtin_choose_expr(sizeof(__t) == 8,                         \
        (*(uint64_t *)(__buffer) = __suppress_cast_warning(uint64_t, __t), \
         (__buffer) = (void *)((char *)(__buffer) + 8)),            \
        ((void)0)                                                   \
    )))))))

#define ___ceph_san_ser0(__buffer)
#define ___ceph_san_ser1(__buffer, __t)		(__ceph_san_ser_type(__buffer, __t))
#define ___ceph_san_ser2(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser1(__buffer, __args))
#define ___ceph_san_ser3(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser2(__buffer, __args))
#define ___ceph_san_ser4(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser3(__buffer, __args))
#define ___ceph_san_ser5(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser4(__buffer, __args))
#define ___ceph_san_ser6(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser5(__buffer, __args))
#define ___ceph_san_ser7(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser6(__buffer, __args))
#define ___ceph_san_ser8(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser7(__buffer, __args))
#define ___ceph_san_ser9(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser8(__buffer, __args))
#define ___ceph_san_ser10(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser9(__buffer, __args))
#define ___ceph_san_ser11(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser10(__buffer, __args))
#define ___ceph_san_ser12(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser11(__buffer, __args))
#define ___ceph_san_ser13(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser12(__buffer, __args))
#define ___ceph_san_ser14(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser13(__buffer, __args))
#define ___ceph_san_ser15(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser14(__buffer, __args))
#define ___ceph_san_ser16(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser15(__buffer, __args))
#define ___ceph_san_ser17(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser16(__buffer, __args))
#define ___ceph_san_ser18(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser17(__buffer, __args))
#define ___ceph_san_ser19(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser18(__buffer, __args))
#define ___ceph_san_ser20(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser19(__buffer, __args))
#define ___ceph_san_ser21(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser20(__buffer, __args))
#define ___ceph_san_ser22(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser21(__buffer, __args))
#define ___ceph_san_ser23(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser22(__buffer, __args))
#define ___ceph_san_ser24(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser23(__buffer, __args))
#define ___ceph_san_ser25(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser24(__buffer, __args))
#define ___ceph_san_ser26(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser25(__buffer, __args))
#define ___ceph_san_ser27(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser26(__buffer, __args))
#define ___ceph_san_ser28(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser27(__buffer, __args))
#define ___ceph_san_ser29(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser28(__buffer, __args))
#define ___ceph_san_ser30(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser29(__buffer, __args))
#define ___ceph_san_ser31(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser30(__buffer, __args))
#define ___ceph_san_ser32(__buffer, __t, __args...)	(__ceph_san_ser_type(__buffer, __t), ___ceph_san_ser31(__buffer, __args))
#define ___ceph_san_ser(__buffer, ...)	 ___ceph_san_apply(___ceph_san_ser, ceph_san_narg(__VA_ARGS__))(__buffer, ##__VA_ARGS__)
#define ceph_san_ser(...)	 ___ceph_san_ser(__VA_ARGS__)

#endif /* CEPH_SAN_SER_H */

