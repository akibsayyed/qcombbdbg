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

/*
 *  interrupts.c: The interrupt handlers.
 */

#include "core.h"
#include "mmu.h"
#include "interrupts.h"

interrupt_vector_table * ivt = 0;
interrupt_vector_table original_ivt;

#define ARM_ASSEMBLY(arm, ...) \
  __asm__ __volatile__( \
    ".align 2\n" \
    "bx pc\n" \
    "nop\n" \
    ".arm\n" \
    ".code 32\n" \
    arm \
    "add r12, pc, #1\n" \
    "bx r12\n" \
    ".thumb\n" \
    ".code 16" \
    __VA_ARGS__ \
  ) \


/*
 *  Returns the current program register.
 */
int get_cpsr(void)
{
  int cpsr;

  ARM_ASSEMBLY(
    "mrs %0, cpsr\n",
    : "=r" (cpsr)
  );

  return cpsr;
}

/*
 *  Disables IRQ and FIQ interrupts.
 *  Returns previous interrupt flags.
 */
int cpu_interrupts_disable(void)
{
  int tmp_reg, ret;

  ARM_ASSEMBLY(
    "mrs %0, cpsr\n"
    "orr %1, %0, %[mask_int]\n"
    "msr cpsr_c, %1\n"
    "and %0, %0, %[mask_int]\n",
    : "=r" (ret), "=r" (tmp_reg)
    : [mask_int] "i" (ARM_SPR_MASK_INTS)
  );

  return ret;
}

/*
 *  Enables IRQ and FIQ interrupts.
 *  Returns previous interrupt flags.
 */
int cpu_interrupts_enable(void)
{
  int tmp_reg, ret;

  ARM_ASSEMBLY(
    "mrs %0, cpsr\n"
    "bic %1, %0, %[mask_int]\n"
    "msr cpsr_c, %1\n"
    "and %0, %0, %[mask_int]\n",
    : "=r" (ret), "=r" (tmp_reg)
    : [mask_int] "i" (ARM_SPR_MASK_INTS)
  );

  return ret;
}

/*
 *  Checks whether interrupts are currently enabled.
 */
int cpu_are_interrupts_enabled(void)
{
  int cpsr;

  ARM_ASSEMBLY(
    "mrs %0, cpsr\n",
    : "=r" (cpsr)
  );

  return (cpsr & ARM_SPR_MASK_INTS) != ARM_SPR_MASK_INTS;
}

/*
 *  Restores interrupts state.
 */
void cpu_restore_interrupts(int flags)
{
  int tmp_reg;

  ARM_ASSEMBLY(
    "mrs %0, cpsr\n"
    "bic %0, %0, %[mask_int]\n"
    "and %1, %1, %[mask_int]\n"
    "orr %0, %0, %1\n"
    "msr cpsr_c, %0\n",
    : "=&r" (tmp_reg)
    : "r" (flags), [mask_int] "i" (ARM_SPR_MASK_INTS)
    : "memory"
  );
}

/*
 *  Check if we are currently processing an IRQ.
 *  REX sets the processor mode to either IRQ or SYSTEM when doing this.
 */
int cpu_is_in_irq_mode(void)
{
  int cpsr;

  ARM_ASSEMBLY(
    "mrs %0, cpsr\n",
    : "=r" (cpsr)
  );

  cpsr &= ARM_SPR_MASK_MODE;
  return (cpsr == ARM_MODE_IRQ) || (cpsr == ARM_MODE_SYS);
}

/*
 *  Restores context from stack and resumes execution.
 */
void __attribute__((naked)) restore_context(void)
{
  ARM_ASSEMBLY(
    "ldmfd sp!, {r12}\n"
    "tst r12, %[thumb_flag]\n"        /* return to thumb state ? */
    "ldrne lr, [sp, #56]\n"
    "orrne lr, lr, #1\n"              /* set return address as thumb */
    "strne lr, [sp, #56]\n"
    "bic r12, r12, %[thumb_flag]\n"
    "msr cpsr, r12\n"                 /* restore cpsr */ 
    "ldmfd sp!, {r0-r12, lr, pc}\n",  /* return to original context */
    ::
    [thumb_flag] "i" (ARM_SPR_THUMB)
  );
}

void __attribute__((naked)) prefetch_abort_handler(void)
{
  ARM_ASSEMBLY(
    "stmfd sp!, {r0}\n"             /* save r0 on abort stack */
    "sub r0, lr, #4\n"              /* lr_abort = prefetch_abort_address + 4 */
    "mrs lr, spsr\n"
    "bic lr, lr, %[thumb_flag]\n"
    "orr lr, lr, %[mask_ints]\n"
    "msr cpsr_c, lr\n"                      /* move to calling mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store return address */
    "stmfd sp!, {r1-r12, lr}\n"     /* store lr_supervisor, r1-r12 */
    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
    "ldmfd sp!, {r0}\n"             /* restore original r0 */
    "mrs r1, spsr\n"
    "msr cpsr_c, lr\n"                      /* move to calling mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store r0 */
    "stmfd sp!, {r1}\n"             /* store spsr, return frame complete */

    "mov r0, %[event]\n"            /* r0 = EVENT_BREAKPOINT */
    "mov r1, sp\n"                  /* r1 = saved context */

    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
                                    /* 
                                     * CALLING STACK:
                                     *  original r0-r12 registers
                                     *  original_lr
                                     *  pc = fault_address
                                     *  original spsr
                                     */
    "mrs r2, spsr\n" 
    "tst r2, %[thumb_flag]\n"       /* interrupt occured in thumb state ? */
    "addne lr, pc, #9\n"            /* lr = .xfer_to_dbg_handler_thumb */
    "addeq lr, pc, #8\n"            /* lr = .xfer_to_dbg_handler */
    "stmfd sp!, {lr}\n"
    "ldmfd sp!, {pc}^\n"            /* iret, restore spsr, jump to .xfer_to_dbg_handler */

    ".thumb\n"
    ".code 16\n"
    ".prefetch_abort_xfer_to_dbg_handler_thumb:\n"
    "bx pc\n"                       /* arm state fallback */
    "nop\n"
    ".arm\n"
    ".code 32\n"
    ".prefetch_abort_xfer_to_dbg_handler:\n"
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_BREAKPOINT, fault_address) */
    "blx restore_context\n",

    :: 
    [abort_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_ABORT),
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [event] "i" (EVENT_BREAKPOINT),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

void __attribute__((naked)) data_abort_handler(void)
{
  ARM_ASSEMBLY(
    "stmfd sp!, {r0}\n"             /* save r0 on abort stack */
    "sub r0, lr, #8\n"              /* lr_abort = data_abort_address + 8 */
    "mrs lr, spsr\n"
    "bic lr, lr, %[thumb_flag]\n"
    "orr lr, lr, %[mask_ints]\n"
    "msr cpsr_c, lr\n"                      /* move to calling mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store return address */
    "stmfd sp!, {r1-r12, lr}\n"     /* store lr_supervisor, r1-r12 */
    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
    "ldmfd sp!, {r0}\n"             /* restore original r0 */
    "mrs r1, spsr\n"
    "msr cpsr_c, lr\n"                      /* move to calling mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store r0 */
    "stmfd sp!, {r1}\n"             /* store spsr, return frame complete */
    
    "mov r0, %[event]\n"            /* r0 = EVENT_MEMORY_FAULT */
    "mov r1, sp\n"                  /* r1 = saved context */

    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
                                    /* 
                                     * SUPERVISOR STACK:
                                     *  original r0-r12 registers
                                     *  original_lr
                                     *  pc = fault_address
                                     *  original spsr
                                     */
    "mrs r2, spsr\n" 
    "tst r2, %[thumb_flag]\n"       /* interrupt occured in thumb state ? */
    "addne lr, pc, #9\n"            /* lr = .xfer_to_dbg_handler_thumb */
    "addeq lr, pc, #8\n"            /* lr = .xfer_to_dbg_handler */
    "stmfd sp!, {lr}\n"
    "ldmfd sp!, {pc}^\n"            /* iret, restore spsr, jump to .xfer_to_dbg_handler */

    ".thumb\n"
    ".code 16\n"
    ".data_abort_xfer_to_dbg_handler_thumb:\n"
    "bx pc\n"                       /* arm state fallback */
    "nop\n"
    ".arm\n"
    ".code 32\n"
    ".data_abort_xfer_to_dbg_handler:\n"
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_MEMORY_FAULT, fault_address) */
    "blx restore_context\n",

    :: 
    [abort_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_ABORT),
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [event] "i" (EVENT_MEMORY_FAULT),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

void __attribute__((naked)) undefined_instruction_handler(void)
{
  ARM_ASSEMBLY(
    "stmfd sp!, {r0}\n"             /* save r0 on abort stack */
    "mrs r0, spsr\n" 
    "tst r0, %[thumb_flag]\n"       /* interrupt occured in thumb state ? */
    "sub r0, lr, #2\n"              /* lr_undef = undefined_address + 2 (thumb) */
    "subeq r0, r0, #2\n"            /* lr_undef = undefined_address + 4 (arm state) */

    "mrs lr, spsr\n"
    "bic lr, lr, %[thumb_flag]\n"
    "orr lr, lr, %[mask_ints]\n"
    "msr cpsr_c, lr\n"                      /* move to calling mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store return address */
    "stmfd sp!, {r1-r12, lr}\n"     /* store lr_supervisor, r1-r12 */
    "msr cpsr_c, %[undef_mode]\n"           /* 11010111b : move to undefined mode, disabled interrupts */
    "ldmfd sp!, {r0}\n"             /* restore original r0 */
    "mrs r1, spsr\n"
    "msr cpsr_c, lr\n"                      /* move to calling mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store r0 */
    "stmfd sp!, {r1}\n"             /* store spsr, return frame complete */

    "mov r0, %[event]\n"            /* r0 = EVENT_ILLEGAL_INSTRUCTION */
    "mov r1, sp\n"                  /* r1 = saved context */

    "msr cpsr_c, %[undef_mode]\n"           /* 11010111b : move to undefined mode, disabled interrupts */
                                    /* 
                                     * SUPERVISOR STACK:
                                     *  original r0-r12 registers
                                     *  original_lr
                                     *  pc = fault_address
                                     *  original spsr
                                     */

    "mrs r2, spsr\n" 
    "tst r2, %[thumb_flag]\n"       /* interrupt occured in thumb state ? */
    "addne lr, pc, #9\n"            /* lr = .xfer_to_dbg_handler_thumb */
    "addeq lr, pc, #8\n"            /* lr = .xfer_to_dbg_handler */
    "stmfd sp!, {lr}\n"
    "ldmfd sp!, {pc}^\n"            /* iret, restore spsr, jump to .xfer_to_dbg_handler */

    ".thumb\n"
    ".code 16\n"
    ".undefined_insn_xfer_to_dbg_handler_thumb:\n"
    "bx pc\n"                       /* arm state fallback */
    "nop\n"
    ".arm\n"
    ".code 32\n"
    ".undefined_insn_xfer_to_dbg_handler:\n"
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_ILLEGAL_INSTRUCTION, fault_address) */
    "blx restore_context\n",

    :: 
    [undef_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_UNDEF),
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [event] "i" (EVENT_ILLEGAL_INSTRUCTION),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

/*
 *  This is not recoverable. We are supposedly dead at this point, but try to contact the debugger anyway.
 */
void __attribute__((naked)) reset_handler(void)
{
  ARM_ASSEMBLY(
    "stmfd sp!, {lr}\n"             /* store return address (UNPREDICTABLE) */
    "stmfd sp!, {r0-r12, lr}\n"     /* store lr_supervisor (UNPREDICTABLE), r1-r12 */
    "mrs r1, spsr\n"
    "stmfd sp!, {r1}\n"             /* store spsr (UNPREDICTABLE), return frame complete */

    "mov r0, %[event]\n"            /* r0 = EVENT_RESET */
    "mov r1, sp\n"                  /* r1 = saved context */

    "mrs r12, cpsr\n"
    "bic r12, r12, %[mask_ints]\n"
    "msr cpsr, r12\n"               /* enable interrupts */
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_RESET, fault_address) */
    "blx restore_context\n",

    :: 
    [event] "i" (EVENT_RESET),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

void install_interrupt_handlers(void)
{
  WITHOUT_INTERRUPTS(
    mmu_disable();

    INSTALL_VECTOR_HANDLER(reset_vector, &reset_handler);
    INSTALL_VECTOR_HANDLER(software_vector, &reset_handler);
    INSTALL_VECTOR_HANDLER(prefetch_abort_vector, &prefetch_abort_handler);
    INSTALL_VECTOR_HANDLER(data_abort_vector, &data_abort_handler);
    INSTALL_VECTOR_HANDLER(undefined_instruction_vector, &undefined_instruction_handler);

    mmu_enable();
  );
}

void restore_interrupt_handlers(void)
{
  WITHOUT_INTERRUPTS(
    mmu_disable();

    RESTORE_VECTOR_HANDLER(reset_vector);
    RESTORE_VECTOR_HANDLER(software_vector);
    RESTORE_VECTOR_HANDLER(prefetch_abort_vector);
    RESTORE_VECTOR_HANDLER(data_abort_vector);
    RESTORE_VECTOR_HANDLER(undefined_instruction_vector);

    mmu_enable();
  );
}

/*
 *  Sets byte to value and returns previous value.
 */
inline char xchg_b(char * p, char value)
{
  int prev_value;

  ARM_ASSEMBLY(
    "swpb %0, %1, [%2]\n", 
    : "=&r" (prev_value)
    : "r" (value), "r" (p)
  );

  return prev_value;
}

