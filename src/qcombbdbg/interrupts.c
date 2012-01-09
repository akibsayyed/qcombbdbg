#include "core.h"
#include "mmu.h"
#include "interrupts.h"

interrupt_vector_table * ivt = 0;
interrupt_vector_table original_ivt;

#define ARM_ASSEMBLY(code) \
  asm( \
    "bx pc\n" \
    "nop\n" \
    ".arm\n" \
    ".code 32\n" \
    code \
  ) \

/*
 *  Disables IRQ and FIQ interrupts.
 */
void __attribute__((naked)) cpu_interrupts_disable(void)
{
  ARM_ASSEMBLY(
    "mrs r0, cpsr\n"
    "orr r0, r0, %[mask_int]\n"
    "msr cpsr_c, r0\n"
    "bx lr\n"
    :: [mask_int] "i" (ARM_SPR_MASK_INTS)
  );
}

/*
 *  Enables IRQ and FIQ interrupts.
 */
void __attribute__((naked)) cpu_interrupts_enable(void)
{
  ARM_ASSEMBLY(
    "mrs r0, cpsr\n"
    "bic r0, r0, %[mask_int]\n"
    "msr cpsr_c, r0\n"
    "bx lr\n"
    :: [mask_int] "i" (ARM_SPR_MASK_INTS)
  );
}

/*
 *  Restores context from stack and resumes execution.
 */
void __attribute__((naked)) restore_context(void)
{
  asm (
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "ldmfd sp!, {r12}\n"
    "tst r12, %[thumb_flag]\n"      /* return to thumb state ? */
    "ldrne lr, [sp, #56]\n"
    "orrne lr, lr, #1\n"            /* set return address as thumb */
    "strne lr, [sp, #56]\n"
    "bic r12, r12, %[thumb_flag]\n"
    "msr cpsr, r12\n"               /* restore cpsr */ 
    "ldmfd sp!, {r0-r12, lr, pc}\n" /* return to original context */
    ::
    [thumb_flag] "i" (ARM_SPR_THUMB)
  );
}

void __attribute__((naked)) prefetch_abort_handler(void)
{
  asm(
    ".arm\n"
    ".code 32\n"
    "stmfd sp!, {r0}\n"             /* save r0 on abort stack */
    "mrs r0, spsr\n" 
    "sub r0, lr, #4\n"              /* lr_abort = prefetch_abort_address + 4 */
    "msr cpsr_c, %[svc_mode]\n"     /* 11010011b : move to supervisor mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store return address */
    "stmfd sp!, {r1-r12, lr}\n"     /* store lr_supervisor, r1-r12 */
    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
    "ldmfd sp!, {r0}\n"             /* restore original r0 */
    "mrs r1, spsr\n"
    "msr cpsr_c, %[svc_mode]\n"     /* 11010011b : move to supervisor mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store r0 */
    "stmfd sp!, {r1}\n"             /* store spsr, return frame complete */
    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
                                    /* 
                                     * SUPERVISOR STACK:
                                     *  original r0-r12 registers
                                     *  original_lr
                                     *  pc = fault_address
                                     *  original spsr
                                     */

    "mov r0, %[event]\n"            /* r0 = EVENT_BREAKPOINT */
    "sub r1, lr, #4\n"              /* r1 = fault_address */
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
    "mrs r12, cpsr\n"
    "bic r12, r12, %[mask_ints]\n"
    "msr cpsr, r12\n"               /* enable interrupts */
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_BREAKPOINT, fault_address) */
    "blx restore_context\n" 

    :: 
    [svc_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_SVC),
    [abort_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_ABORT),
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [event] "i" (EVENT_BREAKPOINT),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

void __attribute__((naked)) data_abort_handler(void)
{
  asm(
    ".arm\n"
    ".code 32\n"
    "stmfd sp!, {r0}\n"             /* save r0 on abort stack */
    "mrs r0, spsr\n" 
    "sub r0, lr, #8\n"              /* lr_abort = data_abort_address + 8 */
    "msr cpsr_c, %[svc_mode]\n"           /* 11010011b : move to supervisor mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store return address */
    "stmfd sp!, {r1-r12, lr}\n"     /* store lr_supervisor, r1-r12 */
    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
    "ldmfd sp!, {r0}\n"             /* restore original r0 */
    "mrs r1, spsr\n"
    "msr cpsr_c, %[svc_mode]\n"           /* 11010011b : move to supervisor mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store r0 */
    "stmfd sp!, {r1}\n"             /* store spsr, return frame complete */
    "msr cpsr_c, %[abort_mode]\n"           /* 11010111b : move to abort mode, disabled interrupts */
                                    /* 
                                     * SUPERVISOR STACK:
                                     *  original r0-r12 registers
                                     *  original_lr
                                     *  pc = fault_address
                                     *  original spsr
                                     */

    "mov r0, %[event]\n"            /* r0 = EVENT_MEMORY_FAULT */
    "sub r1, lr, #8\n"              /* r1 = fault_address */
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
    "mrs r12, cpsr\n"
    "bic r12, r12, %[mask_ints]\n"
    "msr cpsr, r12\n"               /* enable interrupts */
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_MEMORY_FAULT, fault_address) */
    "blx restore_context\n" 

    :: 
    [svc_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_SVC),
    [abort_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_ABORT),
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [event] "i" (EVENT_MEMORY_FAULT),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

void __attribute__((naked)) undefined_instruction_handler(void)
{
  asm(
    ".arm\n"
    ".code 32\n"
    "stmfd sp!, {r0}\n"             /* save r0 on abort stack */
    "mrs r0, spsr\n" 
    "tst r0, %[thumb_flag]\n"       /* interrupt occured in thumb state ? */
    "sub r0, lr, #2\n"              /* lr_undef = undefined_address + 2 (thumb) */
    "subeq r0, r0, #2\n"            /* lr_undef = undefined_address + 4 (arm state) */

    "msr cpsr_c, %[svc_mode]\n"           /* 11010011b : move to supervisor mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store return address */
    "stmfd sp!, {r1-r12, lr}\n"     /* store lr_supervisor, r1-r12 */
    "msr cpsr_c, %[undef_mode]\n"           /* 11010111b : move to undefined mode, disabled interrupts */
    "ldmfd sp!, {r0}\n"             /* restore original r0 */
    "mrs r1, spsr\n"
    "msr cpsr_c, %[svc_mode]\n"           /* 11010011b : move to supervisor mode, disabled interrupts */
    "stmfd sp!, {r0}\n"             /* store r0 */
    "stmfd sp!, {r1}\n"             /* store spsr, return frame complete */
    "msr cpsr_c, %[undef_mode]\n"           /* 11010111b : move to undefined mode, disabled interrupts */
                                    /* 
                                     * SUPERVISOR STACK:
                                     *  original r0-r12 registers
                                     *  original_lr
                                     *  pc = fault_address
                                     *  original spsr
                                     */

    "mov r0, %[event]\n"            /* r0 = EVENT_ILLEGAL_INSTRUCTION */
    "sub r1, lr, #4\n"              /* r1 = fault_address */
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
    "mrs r12, cpsr\n"
    "bic r12, r12, %[mask_ints]\n"
    "msr cpsr, r12\n"               /* enable interrupts */
    "blx dbg_break_handler\n"       /* call dbg_break_handler(EVENT_ILLEGAL_INSTRUCTION, fault_address) */
    "blx restore_context\n" 

    :: 
    [svc_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_SVC),
    [undef_mode] "i" (ARM_SPR_MASK_INTS | ARM_MODE_UNDEF),
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [event] "i" (EVENT_ILLEGAL_INSTRUCTION),
    [mask_ints] "i" (ARM_SPR_MASK_INTS)
  );
}

/*
 *  XXX: We are already in supervisor mode.
 *  SVC instructions are LR destructive.
 *
void __attribute__((naked)) software_interrupt_handler(void)
{
}
*/

void install_interrupt_handlers(void)
{
  NO_INTERRUPTS(
    mmu_disable();

    INSTALL_VECTOR_HANDLER(prefetch_abort_vector, &prefetch_abort_handler);
    INSTALL_VECTOR_HANDLER(data_abort_vector, &data_abort_handler);
    INSTALL_VECTOR_HANDLER(undefined_instruction_vector, &undefined_instruction_handler);

    mmu_enable();
  );
}

void restore_interrupt_handlers(void)
{
  NO_INTERRUPTS(
    mmu_disable();

    RESTORE_VECTOR_HANDLER(prefetch_abort_vector);
    RESTORE_VECTOR_HANDLER(data_abort_vector);
    RESTORE_VECTOR_HANDLER(undefined_instruction_vector);

    mmu_enable();
  );
}

