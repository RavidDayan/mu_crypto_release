/** @file
  UEFI-compatible stdatomic.h stub for OpenSSL compatibility
  
  Provides minimal atomic operations interface for UEFI environment.
  Since UEFI firmware typically runs in single-threaded context, atomic 
  operations are simplified to regular operations with memory barriers.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __STDATOMIC_H__
#define __STDATOMIC_H__

// Include UEFI base types and synchronization primitives
#include <Base.h>

//
// C11 memory ordering enumeration
//
typedef enum {
  memory_order_relaxed,
  memory_order_consume,
  memory_order_acquire,
  memory_order_release,
  memory_order_acq_rel,
  memory_order_seq_cst
} memory_order;

//
// Atomic type definitions - map to regular volatile types in UEFI context
// UEFI firmware is typically single-threaded, so volatile is sufficient
//
typedef volatile INT8    atomic_char;
typedef volatile UINT8   atomic_uchar;
typedef volatile INT16   atomic_short;
typedef volatile UINT16  atomic_ushort;
typedef volatile INT32   atomic_int;
typedef volatile UINT32  atomic_uint;
typedef volatile INT64   atomic_llong;
typedef volatile UINT64  atomic_ullong;
typedef volatile UINTN   atomic_size_t;
typedef volatile INTN    atomic_ptrdiff_t;
typedef volatile VOID*   atomic_ptr;

//
// Lock-free capability constants
// Set to 2 to indicate lock-free operations are available (simplified for UEFI)
//
#define ATOMIC_CHAR_LOCK_FREE       2
#define ATOMIC_SHORT_LOCK_FREE      2
#define ATOMIC_INT_LOCK_FREE        2
#define ATOMIC_LONG_LOCK_FREE       2
#define ATOMIC_LLONG_LOCK_FREE      2
#define ATOMIC_POINTER_LOCK_FREE    2

//
// Basic atomic operations
// In UEFI single-threaded environment, these simplify to regular operations
// with memory barriers for ordering
//

//
// Atomic load operations
//
#define atomic_load(ptr) (*(ptr))

#define atomic_load_explicit(ptr, order) \
  ({  \
    typeof(*(ptr)) _val;  \
    if ((order) == memory_order_acquire || (order) == memory_order_seq_cst) {  \
      MemoryFence();  \
    }  \
    _val = *(ptr);  \
    if ((order) == memory_order_seq_cst) {  \
      MemoryFence();  \
    }  \
    _val;  \
  })

//
// Atomic store operations  
//
#define atomic_store(ptr, val) ((*(ptr)) = (val))

#define atomic_store_explicit(ptr, val, order) \
  do {  \
    if ((order) == memory_order_release || (order) == memory_order_seq_cst) {  \
      MemoryFence();  \
    }  \
    *(ptr) = (val);  \
    if ((order) == memory_order_seq_cst) {  \
      MemoryFence();  \
    }  \
  } while (0)

//
// Atomic arithmetic operations
//
#define atomic_fetch_add(ptr, val) \
  ({  \
    typeof(*(ptr)) _old = *(ptr);  \
    *(ptr) += (val);  \
    _old;  \
  })

#define atomic_fetch_add_explicit(ptr, val, order) \
  ({  \
    typeof(*(ptr)) _old;  \
    if ((order) == memory_order_acquire || (order) == memory_order_acq_rel || (order) == memory_order_seq_cst) {  \
      MemoryFence();  \
    }  \
    _old = *(ptr);  \
    *(ptr) += (val);  \
    if ((order) == memory_order_release || (order) == memory_order_acq_rel || (order) == memory_order_seq_cst) {  \
      MemoryFence();  \
    }  \
    _old;  \
  })

#define atomic_fetch_sub(ptr, val) atomic_fetch_add(ptr, -(val))
#define atomic_fetch_sub_explicit(ptr, val, order) atomic_fetch_add_explicit(ptr, -(val), order)

//
// Atomic flag type and operations
//
typedef volatile BOOLEAN atomic_flag;
#define ATOMIC_FLAG_INIT FALSE

#define atomic_flag_test_and_set(ptr) \
  ({  \
    BOOLEAN _old = *(ptr);  \
    *(ptr) = TRUE;  \
    _old;  \
  })

#define atomic_flag_test_and_set_explicit(ptr, order) atomic_flag_test_and_set(ptr)

#define atomic_flag_clear(ptr) (*(ptr) = FALSE)
#define atomic_flag_clear_explicit(ptr, order) atomic_flag_clear(ptr)

//
// Memory fence operations
//
#define atomic_thread_fence(order) MemoryFence()
#define atomic_signal_fence(order) /* No-op in UEFI */

//
// Compare and exchange operations (simplified for UEFI)
//
#define atomic_compare_exchange_weak(ptr, expected, desired) \
  ({  \
    BOOLEAN _success = FALSE;  \
    if (*(ptr) == *(expected)) {  \
      *(ptr) = (desired);  \
      _success = TRUE;  \
    } else {  \
      *(expected) = *(ptr);  \
    }  \
    _success;  \
  })

#define atomic_compare_exchange_strong(ptr, expected, desired) \
  atomic_compare_exchange_weak(ptr, expected, desired)

#define atomic_compare_exchange_weak_explicit(ptr, expected, desired, success_order, failure_order) \
  atomic_compare_exchange_weak(ptr, expected, desired)

#define atomic_compare_exchange_strong_explicit(ptr, expected, desired, success_order, failure_order) \
  atomic_compare_exchange_strong(ptr, expected, desired)

//
// Generic atomic operation macros
//
#define _Atomic(T) volatile T

#endif /* __STDATOMIC_H__ */
