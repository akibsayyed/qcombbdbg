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

#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#define ARM_MODE_USER 0x10
#define ARM_MODE_FIQ 0x11
#define ARM_MODE_IRQ 0x12
#define ARM_MODE_SVC 0x13
#define ARM_MODE_ABORT 0x17
#define ARM_MODE_UNDEF 0x1b
#define ARM_MODE_SYS 0x1f

#define ARM_SPR_MASK_MODE 0x1f
#define ARM_SPR_THUMB (1 << 5)
#define ARM_SPR_MASK_FIQ (1 << 6)
#define ARM_SPR_MASK_IRQ (1 << 7)
#define ARM_SPR_MASK_INTS (ARM_SPR_MASK_FIQ | ARM_SPR_MASK_IRQ)
#define ARM_SPR_COND_FLAGS (0x1f << 27)

typedef struct
{
  int reset_vector;
  int undefined_instruction_vector;
  int software_vector;
  int prefetch_abort_vector;
  int data_abort_vector;
  int address_exception_vector;
  int irq_vector;
  int fiq_vector;
} interrupt_vector_table;

#define INSTALL_VECTOR_HANDLER(vector, handler) \
  original_ivt.vector = ivt->vector; \
  ivt->vector = 0xea000000 | (((int)handler - __builtin_offsetof(interrupt_vector_table, vector) - 8) >> 2);

#define RESTORE_VECTOR_HANDLER(vector) \
  ivt->vector = original_ivt.vector;

#define WITHOUT_INTERRUPTS(code) \
  int int_mask = cpu_interrupts_disable(); \
  code; \
  cpu_restore_interrupts(int_mask); \

#define WITH_INTERRUPTS(code) \
  int int_mask = cpu_interrupts_enable(); \
  code; \
  cpu_restore_interrupts(int_mask); \

int cpu_interrupts_disable(void);
int cpu_interrupts_enable(void);
void cpu_restore_interrupts(int);
int cpu_is_in_irq_mode(void);
int cpu_are_interrupts_enabled(void);
void install_interrupt_handlers(void);
void restore_interrupt_handlers(void);

#endif

