/** @file
  Stub stdint.h file to prevent conflicts with system stdint.h
  
  This file prevents the inclusion of system stdint.h which conflicts
  with UEFI type definitions. All required types are already defined
  in CrtLibSupport.h and Base.h.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __STDINT_H__
#define __STDINT_H__

// Prevent multiple inclusions - comprehensive guard coverage
#ifndef _STDINT_H
#define _STDINT_H
#endif

#ifndef _STDINT_H_
#define _STDINT_H_
#endif

#ifndef __STDINT_H
#define __STDINT_H
#endif

#ifndef _STDINT_H_INCLUDED
#define _STDINT_H_INCLUDED
#endif

#ifndef __GLIBC_USE_STDINT_H
#define __GLIBC_USE_STDINT_H
#endif

// Include UEFI types which provide all the definitions we need
#include <Base.h>

// Explicitly define types to override any system definitions
typedef INT64   int64_t;
typedef UINT64  uint64_t;
typedef UINTN   intptr_t;
typedef UINTN   uintptr_t;
typedef INT32   int32_t;
typedef UINT32  uint32_t;
typedef INT16   int16_t;
typedef UINT16  uint16_t;
typedef INT8    int8_t;
typedef UINT8   uint8_t;

// Additional compatibility definitions for OpenSSL
// SIZE_MAX is defined in CrtLibSupport.h to avoid conflicts

#endif /* __STDINT_H__ */
