#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#define ARM_MODE_USER 0x10
#define ARM_MODE_FIQ 0x11
#define ARM_MODE_IRQ 0x12
#define ARM_MODE_SVC 0x13
#define ARM_MODE_ABORT 0x17
#define ARM_MODE_UNDEF 0x1b
#define ARM_MODE_SYS 0x1f

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

void install_interrupt_handlers(void);
void restore_interrupt_handlers(void);

#endif

