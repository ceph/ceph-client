/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CEPH_SAN_PACKER_H
#define _CEPH_SAN_PACKER_H

#include <linux/types.h>
#include <linux/kernel.h>

/*
 * Elegant recursive packing macros
 *
 * These macros provide type-safe serialization and size calculation
 * for arbitrary data with minimal recursion complexity.
 */

/* Special terminator value for recursion */
#define _END _END_MARKER_

/* SERIALIZATION MACROS - True recursion with direct pointer manipulation */

#define SERIALIZE(buff, ...) _SERIALIZE(buff, ##__VA_ARGS__, _END)

#define _SERIALIZE(buff, val, ...) \
    do { \
        typeof(val) *__ptr = (buff); \
        *__ptr = (val); \
        _SERIALIZE_CHECK((typeof(val) *)__ptr + 1, ##__VA_ARGS__); \
    } while(0)

#define _SERIALIZE_CHECK(buff, first, ...) \
    _SERIALIZE_IF_NEMPTY(first)(buff, first, ##__VA_ARGS__)

#define _SERIALIZE_IF_NEMPTY(first) \
    _SERIALIZE_TEST(first, _END, _SERIALIZE_EMPTY, _SERIALIZE_RECURSE)

#define _SERIALIZE_TEST(a, b, empty, recurse) \
    _SERIALIZE_TEST_(a, b) (empty, recurse)

#define _SERIALIZE_TEST_(a, b) \
    _SERIALIZE_IS_ ## b

#define _SERIALIZE_IS__END(empty, recurse) empty
#define _SERIALIZE_IS__END_MARKER_(empty, recurse) empty
#define _SERIALIZE_IS_default(empty, recurse) recurse

#define _SERIALIZE_EMPTY(...)
#define _SERIALIZE_RECURSE(buff, val, ...) \
    _SERIALIZE(buff, val, ##__VA_ARGS__)

/* SIZE CALCULATION MACROS - Elegant recursive calculation */

#define CALC_SIZE(...) _CALC_SIZE(##__VA_ARGS__, _END)

#define _CALC_SIZE(val, ...) \
    _CALC_SIZE_CHECK(sizeof(typeof(val)), ##__VA_ARGS__)

#define _CALC_SIZE_CHECK(current_size, first, ...) \
    _CALC_SIZE_IF_NEMPTY(first)(current_size, first, ##__VA_ARGS__)

#define _CALC_SIZE_IF_NEMPTY(first) \
    _CALC_SIZE_TEST(first, _END, _CALC_SIZE_FINAL, _CALC_SIZE_CONTINUE)

#define _CALC_SIZE_TEST(a, b, final, cont) \
    _CALC_SIZE_TEST_(a, b) (final, cont)

#define _CALC_SIZE_TEST_(a, b) \
    _CALC_SIZE_IS_ ## b

#define _CALC_SIZE_IS__END(final, cont) final
#define _CALC_SIZE_IS__END_MARKER_(final, cont) final
#define _CALC_SIZE_IS_default(final, cont) cont

#define _CALC_SIZE_FINAL(size) (size)
#define _CALC_SIZE_CONTINUE(size, val, ...) \
    _CALC_SIZE_CHECK((size) + sizeof(typeof(val)), ##__VA_ARGS__)

/* USAGE EXAMPLE:
 *
 * // Serialization
 * int buffer[3];
 * SERIALIZE(buffer, 1, 2, 3);
 *
 * // Size calculation
 * size_t size = CALC_SIZE(int_val, u64_val, char_val);
 *
 */

#endif /* _CEPH_SAN_PACKER_H */