/* 
 *  This file is part of qcombbdbg.
 *  Copyright (C) 2012 Guillaume Delugré <guillaume@security-labs.org>
 *  All rights reserved.
 *
 *  qcombbdbg is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  qcombbdbg is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with qcombbdbg. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "rex.h"

/* Trampoline to exported functions
void __attribute((naked)) __far_call(void)
{
    asm(
      "blx r7\n"
      "pop {r4-r7, pc}"
    );
}

#define _CALL(address, target_t) \
    asm volatile( \
      "push {r4-r7, lr}\n" \
      "ldr r7, .target_" #address "\n" \
      "b __far_call\n" \
      ".align 2\n" \
      ".target_" #address ":\n" \
      ".word (" #address " | " #target_t ")\n" \
      ::: "r0" \
    ); \

#define IMPORT_SYM0(target_t, address, return_t, sym) \
  return_t __attribute__((naked, noinline)) sym(void) { \
    _CALL(address, target_t); \
  }

#define IMPORT_SYM1(target_t, address, return_t, sym, arg1_t) \
  return_t __attribute__((naked, noinline)) sym(arg1_t) { \
    _CALL(address, target_t); \
  }

#define IMPORT_SYM2(target_t, address, return_t, sym, arg1_t, arg2_t) \
  return_t __attribute__((naked, noinline)) sym(arg1_t, arg2_t) { \
    _CALL(address, target_t); \
  }

#define IMPORT_SYM3(target_t, address, return_t, sym, arg1_t, arg2_t, arg3_t) \
  return_t __attribute__((naked, noinline)) sym(arg1_t, arg2_t, arg3_t) { \
    _CALL(address, target_t); \
  }

#define IMPORT_SYM4(target_t, address, return_t, sym, arg1_t, arg2_t, arg3_t, arg4_t) \
  return_t __attribute__((naked, noinline)) sym(arg1_t, arg2_t, arg3_t, arg4_t) { \
    _CALL(address, target_t); \
  }
*/

/*
 *  Hardcoded addresses used by the debugger.
 */

/* Generic functions, can be rewritten */
//IMPORT_SYM3(ARM_CODE, 0x13910c, void, __memcpy, void * dst, void * src, int size);
//IMPORT_SYM3(ARM_CODE, 0x139234, void, __memmove, void * dst, void * src, int size);
//IMPORT_SYM3(ARM_CODE, 0x1392d8, void, __memset, void * dst, char c, int size);

#ifdef DEBUG
//IMPORT_SYM2(THUMB_CODE, 0x1396b0, char *, strcpy, char * dst, char * src);
#endif

/* Math functions */
//IMPORT_SYM2(ARM_CODE, 0x1392f0, unsigned long long int, __idivsi3, int x, int y);
//IMPORT_SYM2(ARM_CODE, 0x1393c8, unsigned long long int, __udivsi3, unsigned int x, unsigned int y);

/* Low-level functions, can be rewritten */
//IMPORT_SYM0(THUMB_CODE, 0xbede4, void, cpu_interrupts_disable);
//IMPORT_SYM0(THUMB_CODE, 0xbedfc, void, cpu_interrupts_enable);

/* REX core functions, necessary */
//IMPORT_SYM0(THUMB_CODE, 0x1375dc, rex_task *, rex_self);
//IMPORT_SYM1(THUMB_CODE, 0x137048, void, rex_find_best_task, rex_task * tasks);
//IMPORT_SYM0(THUMB_CODE, 0x13fa14, void, rex_context_switch);
//IMPORT_SYM1(THUMB_CODE, 0x137a32, int, rex_wait, int signals);
//IMPORT_SYM2(THUMB_CODE, 0x137570, int, rex_set_task_signals, rex_task * task, int signals);
//IMPORT_SYM2(THUMB_CODE, 0x13752c, int, rex_clear_task_signals, rex_task * task, int signals);
//IMPORT_SYM3(THUMB_CODE, 0x137a06, int, rex_queue_dpc, rex_apc_routine apc, rex_task * task, void * arg);

//IMPORT_SYM4(THUMB_CODE, 0x5f8108, void, heap_create, rex_heap * h, void * base, int size, void (* failover)(rex_heap *));
//IMPORT_SYM2(THUMB_CODE, 0x5f85f4, void *, heap_malloc, rex_heap * h, int size);
//IMPORT_SYM2(THUMB_CODE, 0x5f8852, void, heap_free, rex_heap * h, void * chunk);

/* Diagnostic task functions, necessary */
//IMPORT_SYM2(THUMB_CODE, 0x5730b6, char *, diag_alloc_packet, char cmd, int size);
//IMPORT_SYM1(THUMB_CODE, 0x5732cc, void, diag_queue_response_packet, void * data);

//void rex_sched(void)
//{
//  rex_find_best_task(rex_tasks_head);
//  rex_context_switch();
//}

/* 
 * eabi soft arithmetic divisions
 * needed by gcc
 */
int __divsi3(int a, int b)
{
  unsigned long long int result;
  
  result = __aeabi_idivmod(a, b);
  return result & 0xffffffff;
}

int __aeabi_idiv(int a, int b)
{
  return __divsi3(a, b);
}

int __modsi3(int a, int b)
{
  unsigned long long int result;
  
  result = __aeabi_idivmod(a, b);
  return result >> 32;
}

int __udivsi3(unsigned int a, unsigned int b)
{
  unsigned long long int result;
  
  result = __aeabi_uidivmod(a, b);
  return result & 0xffffffff;
}

int __aeabi_uidiv(unsigned int a, unsigned int b)
{
  return __udivsi3(a, b);
}

int __umodsi3(unsigned int a, unsigned int b)
{
  unsigned long long int result;
  
  result = __aeabi_uidivmod(a, b);
  return result >> 32;
}

