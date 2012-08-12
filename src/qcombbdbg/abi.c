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

#include "abi.h"

#ifdef __GNUC__

/* 
 * eabi soft arithmetic divisions
 * needed by gcc
 */

#ifdef REUSE_EXTERNAL_SOFTFLOAT_FUNCS
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
#endif

/* GCC switch helpers */
void __attribute__((naked)) __gnu_thumb1_case_sqi(int i)
{
  __asm__ __volatile__(
    "push {r1}\n"
    "mov r1, lr\n"
    "lsr r1, r1, #1\n"
    "lsl r1, r1, #1\n"
    "ldrsb r1, [r1, r0]\n"
    "lsl r1, r1, #1\n"
    "add lr, lr, r1\n"
    "pop {r1}\n"
    "bx lr\n"
  );
}

void __attribute__((naked)) __gnu_thumb1_case_uqi(int i)
{
  __asm__ __volatile__(
    "push {r1}\n"
    "mov r1, lr\n"
    "lsr r1, r1, #1\n"
    "lsl r1, r1, #1\n"
    "ldrb r1, [r1, r0]\n"
    "lsl r1, r1, #1\n"
    "add lr, lr, r1\n"
    "pop {r1}\n"
    "bx lr\n"
  );
}

void __attribute__((naked)) __gnu_thumb1_case_shi(int i)
{
  __asm__ __volatile__(
    "push {r0, r1}\n"
    "mov r1, lr\n"
    "lsr r1, r1, #1\n"
    "lsl r0, r0, #1\n"
    "lsl r1, r1, #1\n"
    "ldrsh r1, [r1, r0]\n"
    "lsl r1, r1, #1\n"
    "add lr, lr, r1\n"
    "pop {r0, r1}\n"
    "bx lr\n"
  ); 
}

void __attribute__((naked)) __gnu_thumb1_case_uhi(int i)
{
  __asm__ __volatile__(
    "push {r0, r1}\n"
    "mov r1, lr\n"
    "lsr r1, r1, #1\n"
    "lsl r0, r0, #1\n"
    "lsl r1, r1, #1\n"
    "ldrh r1, [r1, r0]\n"
    "lsl r1, r1, #1\n"
    "add lr, lr, r1\n"
    "pop {r0, r1}\n"
    "bx lr\n"
  ); 
}

#endif

