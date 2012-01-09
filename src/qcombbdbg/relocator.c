#include "interrupts.h"
#include "relocator.h"

int thumb_insn_get_cond(thumb_insn insn)
{
  return (insn & THUMB_CONDITION_MASK) >> 8;
}

thumb_insn thumb_insn_set_cond(thumb_insn insn, int cond)
{
  return (insn & ~THUMB_CONDITION_MASK) | ((cond << 8) & THUMB_CONDITION_MASK);
}

int thumb_insn_get_imm11(thumb_insn insn)
{
  return (insn & 0x7ff);
}

thumb_insn thumb_insn_set_imm11(thumb_insn insn, int imm)
{
  return (insn & ~0x7ff) | (imm & 0x7ff);
}

int thumb_insn_get_imm8(thumb_insn insn)
{
  return (insn & 0xff);
}

thumb_insn thumb_insn_set_imm8(thumb_insn insn, int imm)
{
  return (insn & ~0xff) | (imm & 0xff);
}

int thumb_insn_get_imm7(thumb_insn insn)
{
  return (insn & 0x7f);
}

thumb_insn thumb_insn_set_imm7(thumb_insn insn, int imm)
{
  return (insn & ~0x7f) | (imm & 0x7f);
}

int thumb_insn_get_rd(thumb_insn insn)
{
  return (insn & THUMB_REGISTER_MASK);
}

thumb_insn thumb_insn_set_rd(thumb_insn insn, int reg)
{
  return (insn & ~THUMB_REGISTER_MASK) | (reg & THUMB_REGISTER_MASK); 
}

int thumb_insn_get_rd_shifted(thumb_insn insn)
{
  return thumb_insn_get_rd(insn >> 8);
}

thumb_insn thumb_insn_set_rd_shifted(thumb_insn insn, int reg)
{
  return ((insn & ~(THUMB_REGISTER_MASK << 8)) | reg << 8); 
}

int thumb_insn_get_rd_hi(thumb_insn insn)
{
  return thumb_insn_get_rd(insn) | ((insn & 0x80) >> 4);
}

thumb_insn thumb_insn_set_rd_hi(thumb_insn insn, int reg)
{
  int h1;

  h1 = (reg & 8) << 4;
  return thumb_insn_set_rd(insn, reg) |  h1;
}

int thumb_insn_get_rm(thumb_insn insn)
{
  return thumb_insn_get_rd(insn >> 3);
}

thumb_insn thumb_insn_set_rm(thumb_insn insn, int reg)
{
  return ((insn & ~(THUMB_REGISTER_MASK << 3)) | ((reg & THUMB_REGISTER_MASK) << 3)); 
}

int thumb_insn_get_rn(thumb_insn insn)
{
  return thumb_insn_get_rd(insn >> 6);
}

thumb_insn thumb_insn_set_rn(thumb_insn insn, int reg)
{
  return ((insn & ~(THUMB_REGISTER_MASK << 6)) | ((reg & THUMB_REGISTER_MASK) << 6)); 
}

int thumb_insn_get_rm_hi(thumb_insn insn)
{
  return thumb_insn_get_rm(insn) | ((insn & 0x40) >> 3);
}

thumb_insn thumb_insn_set_rm_hi(thumb_insn insn, int reg)
{
  int h2;

  h2 = (reg & 8) << 3;
  return thumb_insn_set_rm(insn, reg) | h2;
}

int thumb_insn_get_pc(thumb_insn insn)
{
  return REG_PC;
}

int thumb_insn_get_sp(thumb_insn insn)
{
  return REG_SP;
}

int thumb_insn_get_bitmap(thumb_insn insn)
{
  return (insn & THUMB_REGISTER_BITMAP_MASK);
}

thumb_insn thumb_insn_set_bitmap(thumb_insn insn, int map)
{
  return (insn & ~THUMB_REGISTER_BITMAP_MASK) | (map & THUMB_REGISTER_BITMAP_MASK);
}

thumb_insn_def thumb_insn_table[] =
{
  [T_ADD_HI] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .can_write_sp = 1,
    .opcode = { .mask = 0xff00, .value = 0x4400 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_rd_hi, .set = thumb_insn_set_rd_hi },
      [1] = { .get = thumb_insn_get_rm_hi, .set = thumb_insn_set_rm_hi }
    }
  },

  [T_ADD_PC_IMM8] =
  {
    .can_read_pc = 1,
    .reads_pc = 1,
    .opcode = { .mask = 0xf800, .value = 0xa000 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_rd_shifted, .set = thumb_insn_set_rd_shifted },
      [1] = { .get = thumb_insn_get_pc, .set = 0 /* TODO */ }
    }
  },

  [T_ADD_SP_IMM7] = 
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode = { .mask = 0xff80, .value = 0xb000 },
    {
      [0] = { .get = thumb_insn_get_sp, .set = 0 /* TODO */ },
      [1] = { .get = thumb_insn_get_imm7, .set = thumb_insn_set_imm7 }
    }
  },

  [T_B_COND] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .reads_pc = 1,
    .branch = 1,
    .opcode = { .mask = 0xf000, .value = 0xd000 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_imm8, .set = thumb_insn_set_imm8 }
    }
  },

  [T_B] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .reads_pc = 1,
    .branch = 1,
    .opcode = { .mask = 0xf800, .value = 0xe000 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_imm11, .set = thumb_insn_set_imm11 }
    }
  },

  [T_BL] =
  {
    .can_write_pc = 1,
    .branch = 1,
    .link = 1,
    .opcode = { .mask = 0xf800, .value = 0xf800 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_imm11, .set = thumb_insn_set_imm11 }
    }
  },

  [T_BLX] =
  {
    .can_write_pc = 1,
    .branch = 1,
    .link = 1,
    .opcode = { .mask = 0xf800, .value = 0xe800 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_imm11, .set = thumb_insn_set_imm11 }
    }
  },

  [T_BLX_REG] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .branch = 1,
    .link = 1,
    .opcode = { .mask = 0xff80, .value = 0x4780 },
    .operands = 
    {
      [0] = { .get = thumb_insn_get_rm_hi, .set = thumb_insn_set_rm_hi }
    }
  },

  [T_BX] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .branch = 1,
    .opcode = { .mask = 0xff80, .value = 0x4700 },
    .operands = 
    {
      [0] = { .get = thumb_insn_get_rm_hi, .set = thumb_insn_set_rm_hi }
    }
  },

 /*
  [T_CMP_HI] =
  {
    .can_read_pc = 1,
    .opcode = { .mask = 0xff00, .value = 0x4500 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_rd_hi, .set = thumb_insn_set_rd_hi },
      [1] = { .get = thumb_insn_get_rm_hi, .set = thumb_insn_set_rm_hi }
    }
  },
  */

  [T_LDR_PC_IMM8] =
  {
    .can_read_pc = 1,
    .reads_pc = 1,
    .opcode = { .mask = 0xf800, .value = 0x4800 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_rd_shifted, .set = thumb_insn_set_rd_shifted },
      [1] = { .get = thumb_insn_get_pc, .set = 0 /* TODO */ }
    }
  },
  
  [T_MOV_HI] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .can_write_sp = 1,
    .opcode = { .mask = 0xff00, .value = 0x4600 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_rd_hi, .set = thumb_insn_set_rd_hi },
      [1] = { .get = thumb_insn_get_rm_hi, .set = thumb_insn_set_rm_hi }
    }
  },

  [T_POP_WITH_PC] =
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .branch = 1,
    .opcode = { .mask = 0xff00, .value = 0xbd00 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_bitmap, .set = thumb_insn_set_bitmap }
    }
  },

  [T_POP_WITHOUT_PC] =
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode = { .mask = 0xff00, .value = 0xbc00 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_bitmap, .set = thumb_insn_set_bitmap }
    }
  },

  [T_PUSH] =
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode  = { .mask = 0xfe00, .value = 0xb400 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_bitmap, .set = thumb_insn_set_bitmap }
    }
  },

  [T_SUB_SP_IMM7] = 
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode = { .mask = 0xff80, .value = 0xb080 },
    .operands =
    {
      [0] = { .get = thumb_insn_get_sp, .set = 0 /* TODO */ },
      [1] = { .get = thumb_insn_get_imm7, .set = thumb_insn_set_imm7 }
    }
  }
};

/* 
 * Move 8-bit constant into register 
 */
int thumb_rel_move_imm_to_reg(thumb_insn ** pdest, int reg, int imm)
{
  thumb_insn insn;

  insn = T_MOV_IMM8_OPCODE;
  insn = thumb_insn_set_rd_shifted(insn, reg);
  insn = thumb_insn_set_imm8(insn, imm);

  **pdest = insn;
  (*pdest)++;

  return sizeof(thumb_insn);
}

int thumb_rel_do_op_reg_reg(thumb_insn ** pdest, int opcode, int reg_dst, int reg_src)
{
  thumb_insn insn;

  insn = opcode;
  insn = thumb_insn_set_rd(insn, reg_dst);
  insn = thumb_insn_set_rm(insn, reg_src);
  **pdest = insn;
  (*pdest)++;

  return sizeof(thumb_insn);
}

int thumb_rel_do_op_reg_reg_hi(thumb_insn ** pdest, int opcode, int reg_dst, int reg_src)
{
  thumb_insn insn;

  insn = opcode;
  insn = thumb_insn_set_rd_hi(insn, reg_dst);
  insn = thumb_insn_set_rm_hi(insn, reg_src);
  **pdest = insn;
  (*pdest)++;

  return sizeof(thumb_insn);
}

/*
 *  Move register to register.
 *  At least one register must be a high register (r8-r15).
 */
int thumb_rel_move_reg_to_reg_hi(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg_hi(pdest, thumb_insn_table[T_MOV_HI].opcode.value, reg_dst, reg_src);
}

/*
 *  Move register to register.
 *  Both registers must be low registers (r0-r7).
 */
int thumb_rel_move_reg_to_reg_lo(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg(pdest, T_MOV_LO_OPCODE, reg_dst, reg_src);
}

/*
 *  Move register to register.
 */
int thumb_rel_move_reg_to_reg(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  if ( IS_HI_REG(reg_dst) || IS_HI_REG(reg_src) )
    return thumb_rel_move_reg_to_reg_hi(pdest, reg_dst, reg_src);
  else
    return thumb_rel_move_reg_to_reg_lo(pdest, reg_dst, reg_src);
}

/* 
 * Add two low registers.
 */
int thumb_rel_add_reg_to_reg_lo(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg(pdest, T_ADC_OPCODE, reg_dst, reg_src);
}

/*
 *  Add register to register.
 *  At least one register must be a high register.
 */
int thumb_rel_add_reg_to_reg_hi(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg_hi(pdest, thumb_insn_table[T_ADD_HI].opcode.value, reg_dst, reg_src);
}

int thumb_rel_add_reg_to_reg(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  if ( IS_HI_REG(reg_dst) || IS_HI_REG(reg_src) )
    return thumb_rel_add_reg_to_reg_hi(pdest, reg_dst, reg_src);
  else
    return thumb_rel_add_reg_to_reg_lo(pdest, reg_dst, reg_src);
}

/*
 *  OR between registers.
 */
int thumb_rel_or_reg_to_reg(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg(pdest, T_ORR_OPCODE, reg_dst, reg_src);
}

/*
 *  Register bit-clear.
 */
int thumb_rel_bic_reg_to_reg(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg(pdest, T_BIC_OPCODE, reg_dst, reg_src);
}

/*
 *  Logical shift left register.
 */
int thumb_rel_lsl_reg_to_reg(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg(pdest, T_LSL_OPCODE, reg_dst, reg_src);
}

/*
 *  Arithmetic shift right register.
 */
int thumb_rel_asr_reg_to_reg(thumb_insn ** pdest, int reg_dst, int reg_src)
{
  return thumb_rel_do_op_reg_reg(pdest, T_ASR_OPCODE, reg_dst, reg_src);
}

/*
 *  Emits a PUSH {regs} instruction.
 */
int thumb_rel_push_reg(thumb_insn ** pdest, int regs)
{
  thumb_insn insn;

  insn = thumb_insn_table[T_PUSH].opcode.value;
  insn = thumb_insn_table[T_PUSH].operands[0].set(insn, regs);
  **pdest = insn;
  (*pdest)++;

  return sizeof(thumb_insn);
}

/* 
 * Emits a POP {regs} instruction.
 */
int thumb_rel_pop_reg(thumb_insn ** pdest, int regs)
{
  thumb_insn insn;

  insn = thumb_insn_table[T_POP_WITHOUT_PC].opcode.value;
  insn = thumb_insn_table[T_POP_WITHOUT_PC].operands[0].set(insn, regs);
  **pdest = insn;
  (*pdest)++;

  return sizeof(thumb_insn);
}

/*
 *  Load or store data from the saved control structure.
 *  Generates:
 *    sub/add sp, STACK_SHIFT - stack_delta
 *    ldr/str reg, [sp, #field]
 *    add/sub sp, STACK_SHIFT - stack_delta
 */
int thumb_rel_load_store_field(thumb_insn ** pdest, int reg, int load, int field, int stack_delta)
{
  thumb_insn insn;
  thumb_insn * dest;
  int written, delta;
  int op;

  dest = *pdest;
  delta = STACK_SHIFT - stack_delta;

  if ( delta > 0 )
    op = T_SUB_SP_IMM7;
  else
    op = T_ADD_SP_IMM7;

  insn = thumb_insn_table[op].opcode.value;
  insn = thumb_insn_table[op].operands[1].set(insn, delta >> 2);
  *dest++ = insn; /* add/sub sp, [shift to saved pc] */

  if ( load )
    insn = T_LDR_SP_IMM8_OPCODE; 
  else
    insn = T_STR_SP_IMM8_OPCODE; 

  insn = thumb_insn_set_rd_shifted(insn, reg);
  insn = thumb_insn_set_imm8(insn, field >> 2);
  *dest++ = insn; /* ldr/str reg, [sp, #field] */

  if ( delta > 0 )
    op = T_ADD_SP_IMM7;
  else
    op = T_SUB_SP_IMM7;

  insn = thumb_insn_table[op].opcode.value;
  insn = thumb_insn_table[op].operands[1].set(insn, delta >> 2);
  *dest++ = insn; /* add/sub sp, [shift to saved pc] */

  written = dest - *pdest;
  *pdest = dest;

  return written;
}

int thumb_rel_load_pc(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest, 
    reg, 
    1, 
    __builtin_offsetof(rel_ctrl, pc),
    stack_delta
  );
}

int thumb_rel_store_pc(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest, 
    reg,
    0, 
    __builtin_offsetof(rel_ctrl, pc),
    stack_delta
  );
}

int thumb_rel_load_cpsr(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest,
    reg,
    1,
    __builtin_offsetof(rel_ctrl, cpsr),
    stack_delta
  );
}

int thumb_rel_load_thumb_bit(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest,
    reg,
    1,
    __builtin_offsetof(rel_ctrl, thumb_bit),
    stack_delta
  );
}

int thumb_rel_store_thumb_bit(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest,
    reg,
    0,
    __builtin_offsetof(rel_ctrl, thumb_bit),
    stack_delta
  );
}

/*
 *  Adjusts LR in case of relocating a BL/BLX instruction.
 */
int thumb_rel_adjust_lr(thumb_insn ** pdest, int stack_delta)
{
  thumb_insn * dest;
  int written;

  dest = *pdest;
 
  /* push {r0-r1} */
  thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1));
  stack_delta += 8;

  /* Load return address into r0 */
  thumb_rel_load_pc(&dest, REG_R0, stack_delta);

  /* mov r1, 1 */
  thumb_rel_move_imm_to_reg(&dest, REG_R1, 1);

  /* orr r0, r1 */
  thumb_rel_or_reg_to_reg(&dest, REG_R0, REG_R1);

  /* mov lr, r0 */
  thumb_rel_move_reg_to_reg(&dest, REG_LR, REG_R0);

  /* pop {r0-r1} */
  thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1));

  written = dest - *pdest;
  *pdest = dest;

  return written;
}

/*
 *  Some of our code may have tainted the cpsr flags.
 *  We need to restore them before return.
 *  Generates:
 *    push {r0-r1}
 *    ldr r1, [cpsr]
 *    bx pc
 *    nop
 *    mrs r0, cpsr
 *    lsl r0, r0, 5
 *    lsr r0, r0, 5
 *    orr r0, r1, r0
 *    msr cpsr, r0
 *    add r0, pc, 1
 *    bx r0
 *    pop {r0-r1}
 */
int thumb_rel_restore_flags(thumb_insn ** pdest, int stack_delta)
{
  int written;
  thumb_insn t_insn;
  thumb_insn * dest;
  arm_insn a_insn;

  dest = *pdest;

  /* push {r0-r1} */
  thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1));
  stack_delta += 8;

  /* load saved flags into r1 */
  thumb_rel_load_cpsr(&dest, REG_R1, stack_delta);
 
  if ( (int)dest % 4 == 2 )
    *dest++ = THUMB_NOP; /* align 4 */

  t_insn = thumb_insn_table[T_BX].opcode.value;
  t_insn = thumb_insn_table[T_BX].operands[0].set(t_insn, REG_PC);
  *dest++ = t_insn; /* bx pc */
  *dest++ = THUMB_NOP; /* nop */

  /* Now we are in ARM state */

  a_insn = 0xe10f0000; /* mrs r0, cpsr */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe1a00280; /* mov r0, r0 lsl 5 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe1a002a0; /* mov r0, r0 lsr 5 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe1810000; /* orr r0, r1, r0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe1a002a0; /* msr cpsr, r0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  /* Get back to thumb state */
  
  a_insn = 0xe28f0001; /* add r0, pc, 1 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe1200010; /* bx r0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  /* pop {r0-r1} */
  thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1));

  written = dest - *pdest;
  *pdest = dest;

  return written;
}

/*
 *  Writes epilogue for relocated instruction.
 *  Resuming execution to the next original instruction.
 *  r12 is used to preserve the conditional flags in cpsr.
 *
 *    sub sp, 4
 *    push {r0-r2}
 *    mov r0, r12
 *    ldr r1, [saved_pc]
 *    ldr r2, [thumb_bit]
 *    mov r12, r2
 *    add r1, r12
 *    str r1, [sp, #12]
 *    mov r12, r0
 *    pop {r0-r2, pc}
 *
 */
int thumb_rel_epilogue(thumb_insn ** pdest, int stack_delta)
{
  thumb_insn insn;
  thumb_insn * dest;
  int written;

  dest = *pdest;
  written = 0;

  insn = thumb_insn_table[T_SUB_SP_IMM7].opcode.value; 
  insn = thumb_insn_table[T_SUB_SP_IMM7].operands[1].set(insn, 4 >> 2); 
  *dest++ = insn; /* sub sp, 4 */

  stack_delta += 4;

  /* TODO: handle the case if stack_delta + 4 == STACK_SHIFT */

  /* push {r0-r2} */
  thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2));

  /* mov r0, r12 */
  thumb_rel_move_reg_to_reg_hi(&dest, REG_R0, REG_R12);

  /* ldr r1, [saved_pc] */
  thumb_rel_load_pc(&dest, REG_R1, stack_delta);

  /* ldr r2, [thumb_bit] */
  thumb_rel_load_thumb_bit(&dest, REG_R2, stack_delta);
  
  /* mov r12, r2 */
  thumb_rel_move_reg_to_reg_hi(&dest, REG_R12, REG_R2);

  /* add r1, r12 */
  thumb_rel_add_reg_to_reg_hi(&dest, REG_R1, REG_R12);

  insn = T_STR_SP_IMM8_OPCODE; 
  insn = thumb_insn_set_rd_shifted(insn, REG_R1);  
  insn = thumb_insn_set_imm8(insn, 12 >> 2);
  *dest++ = insn; /* str r1, [sp, #12] */


  /* pop {r0-r2, pc} */
  insn = thumb_insn_table[T_POP_WITH_PC].opcode.value;
  insn = thumb_insn_table[T_POP_WITH_PC].operands[0].set(
    insn, 
    T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_PC)
  ); 
  *dest++ = insn; 

  written = dest - *pdest;
  *pdest = dest;

  return written;
}

int thumb_rel_get_insn_def(thumb_insn insn)
{
  int i;
  for ( i = 0; i < sizeof(thumb_insn_table) / sizeof(thumb_insn_def); ++i )
    if ( (insn & thumb_insn_table[i].opcode.mask) == thumb_insn_table[i].opcode.value )
      return i;

  return -1;
}

/*
 *  Count numbers of registers in a push/pop operand map (hamming).
 */
int thumb_rel_count_regs_in_map(int map)
{
  int c;

  for ( c = 0; map != 0; ++c )
    map &= map - 1;

  return c;
}

/*
 * Relocates a single thumb instruction to a scratch buffer.
 */
int relocate_thumb_insn(thumb_insn * pc, thumb_insn * dest, int * output_size)
{
  thumb_insn_def * idef;
  thumb_insn insn, tmp_insn;
  thumb_insn * base, * tmp_dest;
  int stack_delta;
  int tainted_flags;
  int new_reg, new_reg2, num_regs, i, cond;

  stack_delta = 0;
  tainted_flags = 0;

  base = dest;
  insn = *pc;
  i = thumb_rel_get_insn_def(insn);

  /* We have an instruction that needs relocation */
  if ( i > 0 )
  {
    idef = &thumb_insn_table[i];

    /*
     * The instruction modifies PC value.
     * Possible instructions:
     *  b.cond pc+(imm8<<1)
     *  b pc+(imm11<<1)
     *  bl/blx lr+(imm11<<1)
     *  blx reg
     *  bx reg
     *  add pc, reg
     *  mov pc, reg
     *  pop {regs, pc}
     */
    if ( idef->branch || (idef->can_write_pc && idef->operands[0].get(insn) == REG_PC) )
    {
      switch ( i )
      {
        case T_POP_WITH_PC:
          num_regs = thumb_rel_count_regs_in_map(idef->operands[0].get(insn));   
          
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0)); /* push {r0} */
          stack_delta += 4;

          tmp_insn = thumb_insn_set_imm8(T_LDR_SP_IMM8_OPCODE, num_regs);
          tmp_insn = thumb_insn_set_rd(tmp_insn, REG_R0); 
          *dest++ = tmp_insn; /* ldr r0, [sp, num_regs * 4] */
          
          /* Save pc value */
          /* TODO: check thumb bit */
          thumb_rel_store_pc(&dest, REG_R0, stack_delta);
          thumb_rel_pop_reg(&dest, T_RBIT(REG_R0)); /* pop {r0} */
          stack_delta -= 4;

          /* pop registers except pc */
          if ( num_regs > 1 )
            thumb_rel_pop_reg(&dest, idef->operands[0].get(insn) & ~T_RBIT(REG_PC));

          tmp_insn = thumb_insn_table[T_ADD_SP_IMM7].opcode.value;
          tmp_insn = thumb_insn_table[T_ADD_SP_IMM7].operands[1].set(tmp_insn, 4 >> 2);
          *dest++ = tmp_insn; /* add sp, 4 */

          stack_delta -= num_regs * 4; 

          break;

        case T_B_COND:
          
          tmp_dest = dest;
          dest++;

          /* push {r0-r2} */
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2));
          stack_delta += 12;

          /* load return address into r0 */
          thumb_rel_load_pc(&dest, REG_R0, stack_delta);

          /* move r1, imm8 */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, idef->operands[0].get(insn));

          /* move r2, 24 */
          thumb_rel_move_imm_to_reg(&dest, REG_R2, 24);

          /* lsl r1, r2 */
          thumb_rel_lsl_reg_to_reg(&dest, REG_R1, REG_R2);

          /* move r2, 23 */
          thumb_rel_move_imm_to_reg(&dest, REG_R2, 24);

          /* asr r1, r2 (sign extend) */
          thumb_rel_asr_reg_to_reg(&dest, REG_R1, REG_R2);

          /* add r0, r1 */
          thumb_rel_add_reg_to_reg(&dest, REG_R0, REG_R1);

          /* store return address */
          thumb_rel_store_pc(&dest, REG_R0, stack_delta);

          /* pop {r0-r2} */
          thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2));
          stack_delta -= 12;

          cond = thumb_insn_get_cond(insn);  
          if ( cond != COND_AL )
          {
            insn = thumb_insn_set_cond(insn, REVERSE_COND(cond));
            insn = thumb_insn_set_imm8(insn, (dest - tmp_dest - 2));

            *tmp_dest = insn;
          }
          else
            *tmp_dest = THUMB_NOP; /* Unconditional branch */

          tainted_flags = 1;
          break;

        case T_B:

          /* push {r0-r3} */
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta += 16;

          /* Load return address into pc */
          thumb_rel_load_pc(&dest, REG_R0, stack_delta);

          /* mov r1, (imm11 << 1) & 0xff */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) << 1) & 0xff);

          /* mov r2, (imm11 >> 7) & 0xff */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) >> 7) & 0xff);

          /* mov r3, 8 */
          thumb_rel_move_imm_to_reg(&dest, REG_R3, 8);

          /* lsl r2, r3 */
          thumb_rel_lsl_reg_to_reg(&dest, REG_R2, REG_R3);

          /* orr r1, r2 */
          thumb_rel_or_reg_to_reg(&dest, REG_R1, REG_R2);

          /* mov r3, 20 */
          thumb_rel_move_imm_to_reg(&dest, REG_R3, 20);

          /* lsl r1, r3 */
          thumb_rel_lsl_reg_to_reg(&dest, REG_R1, REG_R3);

          /* asr r1, r3 (sign extend) */
          thumb_rel_asr_reg_to_reg(&dest, REG_R1, REG_R3);

          /* add r0, r1 */
          thumb_rel_add_reg_to_reg(&dest, REG_R0, REG_R1);

          /* store return address */
          thumb_rel_store_pc(&dest, REG_R0, stack_delta);

          /* pop {r0-r3} */
          thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta -= 16;
  
          tainted_flags = 1;
          break;

        case T_BL:
        case T_BLX:
          
          /* push {r0-r3} */
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta += 16;

          /* mov r0, lr */
          thumb_rel_move_reg_to_reg(&dest, REG_R0, REG_LR);

          /* load return address into lr */
          thumb_rel_adjust_lr(&dest, stack_delta);

          /* mov r1, (imm11 << 1) & 0xff */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) << 1) & 0xff);

          /* mov r2, (imm11 >> 7) & 0xff */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) >> 7) & 0xff);

          /* mov r3, 8 */
          thumb_rel_move_imm_to_reg(&dest, REG_R3, 8);

          /* lsl r2, r3 */
          thumb_rel_lsl_reg_to_reg(&dest, REG_R2, REG_R3);

          /* orr r1, r2 */
          thumb_rel_or_reg_to_reg(&dest, REG_R1, REG_R2);

          /* add r0, r1 */
          thumb_rel_add_reg_to_reg(&dest, REG_R0, REG_R1);

          if ( i == T_BL )
          {
            thumb_rel_move_imm_to_reg(&dest, REG_R1, 1);
            thumb_rel_or_reg_to_reg(&dest, REG_R0, REG_R1); /* Thumb */
          }
          else
          {
            thumb_rel_move_imm_to_reg(&dest, REG_R1, 3);
            thumb_rel_bic_reg_to_reg(&dest, REG_R0, REG_R1); /* Align 4 */
          }

          thumb_rel_store_pc(&dest, REG_R0, stack_delta);

          /* pop {r0-r3} */
          thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta -= 16;

          tainted_flags = 1;
          break;

        case T_BX:
        case T_BLX_REG:
          if ( idef->link )
          {
            thumb_rel_adjust_lr(&dest, stack_delta);

            /* LR adjustment is flag destuctive */
            tainted_flags = 1;
          }

          new_reg = NEXT_THUMB_REG(idef->operands[0].get(insn));
          thumb_rel_push_reg(&dest, new_reg);
          stack_delta += 4;

          thumb_rel_move_reg_to_reg(&dest, new_reg, idef->operands[0].get(insn));
          thumb_rel_store_pc(&dest, new_reg, stack_delta);

          thumb_rel_pop_reg(&dest, new_reg);
          stack_delta -= 4;
          
          /* Move operation on low registers is flag destructive */
          if ( !IS_HI_REG(idef->operands[0].get(insn)) )
            tainted_flags = 1;

          break;

        case T_ADD_HI:
        case T_MOV_HI:
          new_reg = NEXT_THUMB_REG(idef->operands[1].get(insn));
          thumb_rel_push_reg(&dest, new_reg);
          stack_delta += 4;

          thumb_rel_move_reg_to_reg(&dest, new_reg, idef->operands[1].get(insn));
          thumb_rel_store_pc(&dest, new_reg, stack_delta);

          thumb_rel_pop_reg(&dest, new_reg);
          stack_delta -= 4;
          
          /* Move operation on low registers is flag destructive */
          if ( !IS_HI_REG(idef->operands[1].get(insn)) )
            tainted_flags = 1;
          
          break;
      }

    }

    /* 
     * The instruction depends on PC value.
     * Possible instructions:
     *  add reg, pc
     *  add reg, pc, imm8
     *  ldr reg, [pc, #imm8]
     *  mov reg, pc
     */
    else if ( idef->reads_pc || (idef->can_read_pc && idef->operands[1].get(insn) == REG_PC ) )
    {
      /* Allocates an unused register */
      new_reg = NEXT_THUMB_REG(idef->operands[0].get(insn)); 

      /* push {new_reg} */
      thumb_rel_push_reg(&dest, T_RBIT(new_reg));
      stack_delta += 4;

      /* ldr new_reg, return_address */
      thumb_rel_load_pc(&dest, new_reg, stack_delta);

      if ( i == T_LDR_PC_IMM8 )
      {
        /* 
         * Before:
         *  ldr reg, [pc, imm8] 
         * After:
         *  push {new_reg2}
         *  mov new_reg2, imm8*4
         *  ldr reg, [new_reg, new_reg2]
         *  pop {new_reg2}
         */
        new_reg2 = NEXT_THUMB_REG(new_reg);
        thumb_rel_push_reg(&dest, T_RBIT(new_reg2));
        stack_delta += 4;

        thumb_rel_move_imm_to_reg(&dest, new_reg2, thumb_insn_get_imm8(insn) * 4);
        tmp_insn = T_LDR_REG_REG_OPCODE;
        tmp_insn = thumb_insn_set_rd(tmp_insn, idef->operands[0].get(insn));
        tmp_insn = thumb_insn_set_rm(tmp_insn, new_reg);
        tmp_insn = thumb_insn_set_rn(tmp_insn, new_reg2);
        *dest++ = tmp_insn;
        
        thumb_rel_pop_reg(&dest, T_RBIT(new_reg2));
        stack_delta -= 4;
        tainted_flags = 1;
      }
      else if ( i == T_ADD_PC_IMM8 )
      {
        /* 
         * Before:
         *  add reg, pc, imm8
         * After:
         *  push {new_reg2}
         *  mov new_reg2, imm8*4
         *  add reg, new_reg, new_reg2
         *  pop {new_reg2}
         */

        new_reg2 = NEXT_THUMB_REG(new_reg);
        thumb_rel_push_reg(&dest, T_RBIT(new_reg2));
        stack_delta += 4;

        thumb_rel_move_imm_to_reg(&dest, new_reg2, thumb_insn_get_imm8(insn) * 4);
        tmp_insn = T_ADD_REG_REG_OPCODE;
        tmp_insn = thumb_insn_set_rd(tmp_insn, idef->operands[0].get(insn));
        tmp_insn = thumb_insn_set_rm(tmp_insn, new_reg);
        tmp_insn = thumb_insn_set_rn(tmp_insn, new_reg2);
        *dest++ = tmp_insn;
        
        thumb_rel_pop_reg(&dest, T_RBIT(new_reg2));
        stack_delta -= 4;
        tainted_flags = 1;
      }
      else
      {
        /* replace pc by new_reg in instruction */
        *dest++ = idef->operands[1].set(insn, new_reg);
      }

      /* pop {new_reg} */
      thumb_rel_pop_reg(&dest, T_RBIT(new_reg));
      stack_delta -= 4;
    }

    /* 
     * The instruction modifies SP value.
     * Possible instructions:
     *  add sp, reg
     *  add sp, imm7
     *  mov sp, reg
     *  push {regs}
     *  pop {regs_without_pc}
     *  sub sp, imm7
     */
    else if ( idef->writes_sp || (idef->can_write_sp && idef->operands[0].get(insn) == REG_SP ) )
    {
      switch ( i )
      {
        case T_PUSH:
          num_regs = thumb_rel_count_regs_in_map(idef->operands[0].get(insn));
          stack_delta += num_regs * 4;
          break;

        case T_POP_WITHOUT_PC:
          num_regs = thumb_rel_count_regs_in_map(idef->operands[0].get(insn));
          stack_delta -= num_regs * 4;
          break;

        case T_SUB_SP_IMM7:
          stack_delta += idef->operands[1].get(insn) << 2;
          break;
        
        case T_ADD_SP_IMM7:
          stack_delta -= idef->operands[1].get(insn) << 2;
          break;

        case T_ADD_HI:
        case T_MOV_HI:
          return -2;
        /* TODO: stack modified by register value?? */
      }

      *dest++ = insn;
    }
  }
  else
    *dest++ = insn; /* PC/SP independent instruction */

  /* We might have corrupted the flags, restore them if necessary */
  if ( tainted_flags )
    thumb_rel_restore_flags(&dest, stack_delta);

  thumb_rel_epilogue(&dest, stack_delta);
  *output_size = (dest - base) * sizeof(thumb_insn);

  return 0;
}

void __attribute__((naked)) return_at_relocated_insn(void (* reloc_addr)(void))
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "ldr lr, [sp, #60]\n"           /* Load return address */
    "str r0, [sp, #60]\n"           /* Set new return at reloc_addr */ 
    "ldr r11, [sp]\n"               /* Load cpsr */
    "str lr, [sp]\n"                /* rel_ctrl.pc */
    "add sp, #4\n"
    "mov r12, #0\n"
    "tst r11, %[thumb_flag]\n"      /* thumb instruction ? */
    "orrne r12, r12, #1\n" 
    "mov r10, %[cond_flags]\n"
    "orr r10, %[int_flags]\n"
    "and r11, r11, r10\n"
    "ldmfd sp!, {r0-r1}\n"          /* Load r0-r1 */
    "stmfd sp!, {r11-r12}\n"        /* rel_ctrl.cpsr, rel_ctrl.thumb_bit */
    "add sp, #8\n"
    "bic r11, r11, %[thumb_flag]\n"
    "msr cpsr, r11\n"               /* restore cpsr */ 
    "ldmfd sp!, {r2-r12, lr, pc}"   /* restore context, jump at relocated instruction */
    ::
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [cond_flags] "i" (ARM_SPR_COND_FLAGS),
    [int_flags] "i" (ARM_SPR_MASK_INTS)
  );
}

