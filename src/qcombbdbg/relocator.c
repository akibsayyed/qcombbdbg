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
 *  relocator.c: Engine for relocating thumb instructions.
 *  Needed for displaced stepping and tracepoints.
 */

#include "core.h"
#include "interrupts.h"
#include "mmu.h"
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

/*
 *  Table of instructions which need to be manually relocated.
 */
thumb_insn_def thumb_insn_table[] =
{
  [T_ADD_HI] =
  {
    .can_read_pc = 1,
    .can_write_pc = 1,
    .can_write_sp = 1,
    .opcode = { .mask = 0xff00, .value = 0x4400 }, /* b01000100_xxxxxxxx */
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
    .opcode = { .mask = 0xf800, .value = 0xa000 }, /* b10100xxx_xxxxxxxx */
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
    .opcode = { .mask = 0xff80, .value = 0xb000 }, /* b10110000_0xxxxxxx */
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
    .opcode = { .mask = 0xf000, .value = 0xd000 }, /* b1101xxxx_xxxxxxxx */
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
    .opcode = { .mask = 0xf800, .value = 0xe000 }, /* b11100xxx_xxxxxxxx */
    .operands =
    {
      [0] = { .get = thumb_insn_get_imm11, .set = thumb_insn_set_imm11 }
    }
  },

  [T_BL_HI] =
  {
    .can_read_pc = 1,
    .reads_pc = 1,
    .opcode = { .mask = 0xf800, .value = 0xf000 }, /* b11110xxx_xxxxxxxx */
    .operands = 
    {
      [0] = { .get = thumb_insn_get_imm11, .set = thumb_insn_set_imm11 }
    }
  },

  [T_BL_LO] =
  {
    .can_write_pc = 1,
    .branch = 1,
    .link = 1,
    .opcode = { .mask = 0xf800, .value = 0xf800 }, /* b11111xxx_xxxxxxxx */
    .operands =
    {
      [0] = { .get = thumb_insn_get_imm11, .set = thumb_insn_set_imm11 }
    }
  },

  [T_BLX_LO] =
  {
    .can_write_pc = 1,
    .branch = 1,
    .link = 1,
    .opcode = { .mask = 0xf800, .value = 0xe800 }, /* b11101xxx_xxxxxxxx */
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
    .opcode = { .mask = 0xff80, .value = 0x4780 }, /* b01000111_1xxxxxxx */
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
    .opcode = { .mask = 0xff80, .value = 0x4700 }, /* b01000111_0xxxxxxx */
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
    .opcode = { .mask = 0xf800, .value = 0x4800 }, /* b01001xxx_xxxxxxxx */
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
    .opcode = { .mask = 0xff00, .value = 0x4600 }, /* b01000110_xxxxxxxx */
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
    .opcode = { .mask = 0xff00, .value = 0xbd00 }, /* b10111101_xxxxxxxx */
    .operands =
    {
      [0] = { .get = thumb_insn_get_bitmap, .set = thumb_insn_set_bitmap }
    }
  },

  [T_POP_WITHOUT_PC] =
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode = { .mask = 0xff00, .value = 0xbc00 }, /* b10111100_xxxxxxxx */
    .operands =
    {
      [0] = { .get = thumb_insn_get_bitmap, .set = thumb_insn_set_bitmap }
    }
  },

  [T_PUSH] =
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode = { .mask = 0xfe00, .value = 0xb400 }, /* b1011010x_xxxxxxxx */
    .operands =
    {
      [0] = { .get = thumb_insn_get_bitmap, .set = thumb_insn_set_bitmap }
    }
  },

  [T_SUB_SP_IMM7] = 
  {
    .can_write_sp = 1,
    .writes_sp = 1,
    .opcode = { .mask = 0xff80, .value = 0xb080 }, /* b10110000_1xxxxxxx */
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
 *    ldr/str reg, [sp, #reloc_info.field]
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
  {
    op = T_ADD_SP_IMM7;
    delta = -delta;
  }

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
  {
    op = T_SUB_SP_IMM7;
    delta = -delta;
  }

  insn = thumb_insn_table[op].opcode.value;
  insn = thumb_insn_table[op].operands[1].set(insn, delta >> 2);
  *dest++ = insn; /* add/sub sp, [shift to saved pc] */

  written = dest - *pdest;
  *pdest = dest;

  return written;
}

int thumb_rel_load_read_pc(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest, 
    reg, 
    1, 
    __builtin_offsetof(reloc_info, read_pc),
    stack_delta
  );
}

int thumb_rel_load_next_pc(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest, 
    reg, 
    1, 
    __builtin_offsetof(reloc_info, next_pc),
    stack_delta
  );
}

int thumb_rel_store_next_pc(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest, 
    reg,
    0, 
    __builtin_offsetof(reloc_info, next_pc),
    stack_delta
  );
}

int thumb_rel_load_flags(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest,
    reg,
    1,
    __builtin_offsetof(reloc_info, flags),
    stack_delta
  );
}

int thumb_rel_load_interrupts(thumb_insn ** pdest, int reg, int stack_delta)
{
  return thumb_rel_load_store_field(
    pdest,
    reg,
    1,
    __builtin_offsetof(reloc_info, interrupts),
    stack_delta
  );
}

/*
 *  Adjusts LR in case of relocating a BL/BLX instruction.
 *    push {r0}
 *    ldr r0, [reloc_info.next_pc]
 *    mov lr, r0
 *    pop {r0}
 */
int thumb_rel_adjust_lr(thumb_insn ** pdest, int stack_delta)
{
  thumb_insn * dest;
  int written;

  dest = *pdest;
 
  /* push {r0} */
  thumb_rel_push_reg(&dest, T_RBIT(REG_R0));
  stack_delta += 4;

  /* Load next instruction address into r0 */
  thumb_rel_load_next_pc(&dest, REG_R0, stack_delta);

  /* mov lr, r0 */
  thumb_rel_move_reg_to_reg(&dest, REG_LR, REG_R0);

  /* pop {r0} */
  thumb_rel_pop_reg(&dest, T_RBIT(REG_R0));
  stack_delta -= 4;

  written = dest - *pdest;
  *pdest = dest;

  return written;
}

/*
 *  Some of our code may have tainted the cpsr flags.
 *  We need to restore them before return.
 *  Generates:
 *    push {r0-r1}
 *    ldr r1, [reloc_info.flags]
 *    bx pc
 *    nop
 *    mrs r0, cpsr
 *    lsl r0, r0, 5
 *    lsr r0, r0, 5
 *    orr r0, r1, r0
 *    msr cpsr_f, r0
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
  thumb_rel_load_flags(&dest, REG_R1, stack_delta);
 
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

  a_insn = 0xe128f000; /* msr cpsr_f, r0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  /* Get back to thumb state */
  
  a_insn = 0xe28f0001; /* add r0, pc, 1 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe12fff10; /* bx r0 */
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
 *  Restore interrupt state and resume execution to the next original instruction.
 *
 *    sub sp, 4
 *    push {r0-r1}
 *    ldr r0, [reloc_info.next_pc]
 *    str r0, [sp, #8]
 *    ldr r1, [reloc_info.interrupts]
 *    bx pc
 *    nop
 *    mrs r0, cpsr
 *    bic r0, r0, 0xc0
 *    orr r0, r0, r1
 *    msr cpsr_c, r0
 *    add r0, pc, 1
 *    pop {r0-r1, pc}
 *
 */
int thumb_rel_epilogue(thumb_insn ** pdest, int stack_delta)
{
  thumb_insn insn;
  arm_insn a_insn;
  thumb_insn * dest;
  int written;

  dest = *pdest;
  written = 0;

  insn = thumb_insn_table[T_SUB_SP_IMM7].opcode.value; 
  insn = thumb_insn_table[T_SUB_SP_IMM7].operands[1].set(insn, 4 >> 2); 
  *dest++ = insn; /* sub sp, 4 */

  stack_delta += 4;

  /* TODO: handle the case if stack_delta + 4 == STACK_SHIFT */

  /* push {r0-r1} */
  thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1));
  stack_delta += 8;

  /* ldr r0, [saved_pc] */
  thumb_rel_load_next_pc(&dest, REG_R0, stack_delta);

  insn = T_STR_SP_IMM8_OPCODE; 
  insn = thumb_insn_set_rd_shifted(insn, REG_R0);  
  insn = thumb_insn_set_imm8(insn, 8 >> 2);
  *dest++ = insn; /* str r0, [sp, #8] */

  /* ldr r1, [interrupts] */
  thumb_rel_load_interrupts(&dest, REG_R1, stack_delta);

  if ( (int)dest % 4 == 2 )
    *dest++ = THUMB_NOP; /* align 4 */

  insn = thumb_insn_table[T_BX].opcode.value;
  insn = thumb_insn_table[T_BX].operands[0].set(insn, REG_PC);
  *dest++ = insn; /* bx pc */
  *dest++ = THUMB_NOP; /* nop */

  /* Now we are in ARM state */

  a_insn = 0xe10f0000; /* mrs r0, cpsr */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe3c000c0; /* bic r0, r0, #0xc0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe1800001; /* orr r0, r0, r1 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe121f000; /* msr cpsr_c, r0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  /* Get back to thumb state */
  
  a_insn = 0xe28f0001; /* add r0, pc, 1 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  a_insn = 0xe12fff10; /* bx r0 */
  *(arm_insn *)dest = a_insn;
  dest += 2; 

  /* pop {r0-r1, pc} */
  insn = thumb_insn_table[T_POP_WITH_PC].opcode.value;
  insn = thumb_insn_table[T_POP_WITH_PC].operands[0].set(
    insn, 
    T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_PC)
  ); 
  *dest++ = insn; 
  stack_delta -= 8;

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
  int new_reg, new_reg2, new_reg3, new_reg4;
  int num_regs, i, cond;

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
        /* 
         * Unstack registers, set PC as new return address.
         *
         * Can switch to ARM state.
         */
        case T_POP_WITH_PC:
          num_regs = thumb_rel_count_regs_in_map(idef->operands[0].get(insn));   
          
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0)); /* push {r0} */
          stack_delta += 4;

          tmp_insn = thumb_insn_set_imm8(T_LDR_SP_IMM8_OPCODE, num_regs);
          tmp_insn = thumb_insn_set_rd_shifted(tmp_insn, REG_R0); 
          *dest++ = tmp_insn; /* ldr r0, [sp, num_regs * 4] */
          
          /* Save return value */
          thumb_rel_store_next_pc(&dest, REG_R0, stack_delta);
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

        /*
         *  If cond:
         *    PC = PC + (sign_extend(imm8) << 1)
         *
         *  Stay in thumb state.
         */
        case T_B_COND:
          
          tmp_dest = dest;
          dest++; /* Leave space for the conditional branch */

          /* push {r0-r2} */
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2));
          stack_delta += 12;

          /* load pc into r0 */
          thumb_rel_load_read_pc(&dest, REG_R0, stack_delta);

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

          /* mov r1, 1 */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, 1);

          /* orr r0, r1 (keep thumb bit) */
          thumb_rel_or_reg_to_reg(&dest, REG_R0, REG_R1);

          /* store return address */
          thumb_rel_store_next_pc(&dest, REG_R0, stack_delta);

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

        /*
         * PC = PC + (sign_extend(imm11) << 1)
         *
         * Stay in Thumb state.
         */
        case T_B:

          /* push {r0-r3} */
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta += 16;

          /* Load return address into pc */
          thumb_rel_load_read_pc(&dest, REG_R0, stack_delta);

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

          /* mov r1, 1 */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, 1);

          /* orr r0, r1 (keep thumb bit) */
          thumb_rel_or_reg_to_reg(&dest, REG_R0, REG_R1);

          /* store return address */
          thumb_rel_store_next_pc(&dest, REG_R0, stack_delta);

          /* pop {r0-r3} */
          thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta -= 16;
  
          tainted_flags = 1;
          break;

        /*
         *  PC = LR + (imm11 << 1)
         *  LR = address of next instruction | 1
         *
         *  Can switch to ARM state.
         */
        case T_BL_LO:
        case T_BLX_LO:
          
          /* push {r0-r3} */
          thumb_rel_push_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta += 16;

          /* mov r0, lr */
          thumb_rel_move_reg_to_reg(&dest, REG_R0, REG_LR);

          /* load next instruction into into lr */
          thumb_rel_adjust_lr(&dest, stack_delta);

          /* mov r1, (imm11 << 1) & 0xff ; imm11[6:0] << 1 */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) << 1) & 0xff);

          /* mov r2, (imm11 >> 7) & 0xff ; imm11[10:7] */
          thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) >> 7) & 0xff);

          /* mov r3, 8 */
          thumb_rel_move_imm_to_reg(&dest, REG_R3, 8);

          /* lsl r2, r3 ; */
          thumb_rel_lsl_reg_to_reg(&dest, REG_R2, REG_R3);

          /* orr r1, r2  ; r1 = imm11[10:7] << 8 | imm11[6:0] << 1 == imm11 << 1 */
          thumb_rel_or_reg_to_reg(&dest, REG_R1, REG_R2);

          /* add r0, r1 */
          thumb_rel_add_reg_to_reg(&dest, REG_R0, REG_R1);

          if ( i == T_BL_LO )
          {
            thumb_rel_move_imm_to_reg(&dest, REG_R1, 1); /* T bit = 1 */
            thumb_rel_or_reg_to_reg(&dest, REG_R0, REG_R1);
          }
          else /* BLX */
          {
            thumb_rel_move_imm_to_reg(&dest, REG_R1, 3);
            thumb_rel_bic_reg_to_reg(&dest, REG_R0, REG_R1); /* Destination align 4 */
          }

          thumb_rel_store_next_pc(&dest, REG_R0, stack_delta);

          /* pop {r0-r3} */
          thumb_rel_pop_reg(&dest, T_RBIT(REG_R0) | T_RBIT(REG_R1) | T_RBIT(REG_R2) | T_RBIT(REG_R3));
          stack_delta -= 16;

          tainted_flags = 1;
          break;

        /*
         *  PC = reg
         *  LR = next instruction | 1 if BLX
         *
         *  Can switch to ARM state.
         */
        case T_BX:
        case T_BLX_REG:
          if ( idef->link )
            thumb_rel_adjust_lr(&dest, stack_delta);

          /* Set the new return address */
          thumb_rel_store_next_pc(&dest, idef->operands[0].get(insn), stack_delta);
          break;

        /* 
         * PC = reg
         *  or
         * PC = PC + reg
         *
         * Stay in Thumb state.
         */
        case T_ADD_HI:
        case T_MOV_HI:
          /* push {new_reg, new_reg2} */
          new_reg = NEXT_THUMB_REG(idef->operands[1].get(insn));
          new_reg2 = NEXT_THUMB_REG(new_reg);
          thumb_rel_push_reg(&dest, T_RBIT(new_reg) | T_RBIT(new_reg2));
          stack_delta += 8;

          /* mov new_reg, reg */
          thumb_rel_move_reg_to_reg(&dest, new_reg, idef->operands[1].get(insn));

          if ( i == T_ADD_HI )
          {
            /* ldr new_reg2, [reloc_info.read_pc] */
            thumb_rel_load_read_pc(&dest, new_reg2, stack_delta);
            /* add new_reg, new_reg2 */
            thumb_rel_add_reg_to_reg(&dest, new_reg, new_reg2);
          }
          
          /* mov new_reg2, 1 */
          new_reg2 = NEXT_THUMB_REG(new_reg);
          thumb_rel_move_imm_to_reg(&dest, new_reg2, 1);

          /* orr new_reg, new_reg2 (thumb bit) */
          thumb_rel_or_reg_to_reg(&dest, new_reg, new_reg2);

          /* Save return address */
          thumb_rel_store_next_pc(&dest, new_reg, stack_delta);

          thumb_rel_pop_reg(&dest, T_RBIT(new_reg) | T_RBIT(new_reg2));
          stack_delta -= 8;
          
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
     *  bl.hi imm11
     */
    else if ( idef->reads_pc || (idef->can_read_pc && idef->operands[1].get(insn) == REG_PC ) )
    {
      /* Allocates an unused register */
      new_reg = NEXT_THUMB_REG(idef->operands[0].get(insn)); 

      /* push {new_reg} */
      thumb_rel_push_reg(&dest, T_RBIT(new_reg));
      stack_delta += 4;

      /* ldr new_reg, [reloc_info.read_pc] */
      thumb_rel_load_read_pc(&dest, new_reg, stack_delta);

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
      else if ( i == T_BL_HI )
      {
        /*
         *  Instruction does:
         *    LR = PC + (sign_extend(imm11) << 12)
         */
        new_reg2 = NEXT_THUMB_REG(new_reg);
        new_reg3 = NEXT_THUMB_REG(new_reg2);
        new_reg4 = NEXT_THUMB_REG(new_reg3);

        /* push {new_reg2, new_reg3, new_reg4} */
        thumb_rel_push_reg(&dest, T_RBIT(new_reg2) | T_RBIT(new_reg3) | T_RBIT(new_reg4));
        stack_delta += 12;

        /* mov new_reg2, (imm11 & 0xff) ; imm11[7:0] */
        thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) << 1) & 0xff);

        /* mov new_reg3, (imm11 >> 8) & 0xff ; imm11[10:8] */
        thumb_rel_move_imm_to_reg(&dest, REG_R1, (idef->operands[0].get(insn) >> 7) & 0xff);

        /* mov new_reg4, 8 */
        thumb_rel_move_imm_to_reg(&dest, REG_R3, 8);

        /* lsl new_reg3, new_reg4 ; */
        thumb_rel_lsl_reg_to_reg(&dest, REG_R2, REG_R3);

        /* orr new_reg2, new_reg3 */  
        thumb_rel_or_reg_to_reg(&dest, REG_R1, REG_R2);

        /* mov new_reg4, 21 */
        thumb_rel_move_imm_to_reg(&dest, REG_R3, 8);

        /* lsl new_reg2, new_reg4 */
        thumb_rel_lsl_reg_to_reg(&dest, REG_R2, REG_R3);

        /* mov new_reg4, 9 */
        thumb_rel_move_imm_to_reg(&dest, REG_R3, 20);

        /* asr new_reg2, new_reg4 (sign extend) */
        thumb_rel_asr_reg_to_reg(&dest, REG_R1, REG_R2);

        /* add lr, new_reg2 */
        thumb_rel_add_reg_to_reg(&dest, REG_LR, new_reg2);

        /* push {new_reg2, new_reg3, new_reg4} */
        thumb_rel_pop_reg(&dest, T_RBIT(new_reg2) | T_RBIT(new_reg3) | T_RBIT(new_reg4));
        stack_delta -= 12;
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
        /* TODO: stack pointer modified by register value?? */
      }

      *dest++ = insn;
    }
  }
  else
    *dest++ = insn; /* PC/SP independent instruction */

  /* We might have corrupted the CPU flags, restore them if necessary */
  if ( tainted_flags )
    thumb_rel_restore_flags(&dest, stack_delta);

  /* Write the epilogue stub */
  thumb_rel_epilogue(&dest, stack_delta);
  *output_size = (dest - base) * sizeof(thumb_insn);

  /* Invalidates the instruction cache of the relocated buffer */
  mmu_sync_insn_cache_range(base, *output_size);

  return 0;
}

/*
 *  Handler to return to a relocated instruction.
 *  SP points to the saved_context structure.
 *  Fill up the reloc_info structure, restore registers and pass control to the relocated instruction buffer.
 */
void __attribute__((naked)) return_at_relocated_insn(void (* reloc_addr)(void))
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "ldr r8, [sp]\n"                /* r8 = saved_context->cspr */
    "ldr r9, [sp, #60]\n"           /* r9 = saved_context->pc */
    "str r0, [sp, #60]\n"           /* saved_context->pc = reloc_addr */ 
    "mov r7, r8\n"
    "bic r7, r7, %[thumb_flag]\n"
    "orr r7, r7, %[int_flags]\n"
    "msr cpsr_c, r7\n"                /* The following code is NOT reentrant, disable interrupts */

    /* 
     * Create reloc_info structure on stack.
     * r9, r10, r11, r12 = reloc_info 
     */
    "sub sp, %[stack_shift]\n"
    "tst r8, %[thumb_flag]\n"       /* thumb instruction ? */
    "addne r9, #4\n"               /* Reading PC in Thumb mode yields address of instruction + 4 */
    "addeq r9, #8\n"               /* Reading PC in ARM mode yields address of instruction + 8 */
    "subne r10, r9, #1\n"          /* Next instruction at (PC + 2) | 1 in Thumb mode */
    "subeq r10, r9, #4\n"          /* Next instruction at PC + 4 in ARM mode */
    "mov r11, %[cond_flags]\n"
    "and r11, r11, r8\n"            /* Keep condition and interrupt status from cspr */
    "mov r12, %[int_flags]\n"
    "and r12, r12, r8\n"
    "add sp, %[reloc_info_size]\n"
    "stmfd sp!, {r9-r12}\n"        /* Fill { reloc_info.read_pc, reloc_info.next_pc, reloc_info.flags } */
    "add sp, %[stack_shift]\n"

    /* Restore context and jump to relocated instruction */
    "add sp, #4\n"                  /* Skip cspr */
    "msr cpsr_f, r7\n"              /* Restore flags */
    "ldmfd sp!, {r0-r12, lr, pc}"   /* Restore context, jump at relocated instruction */
    ::
    [thumb_flag] "i" (ARM_SPR_THUMB),
    [cond_flags] "i" (ARM_SPR_COND_FLAGS),
    [int_flags] "i" (ARM_SPR_MASK_INTS),
    [stack_shift] "i" (STACK_SHIFT - sizeof(saved_context)),
    [reloc_info_size] "i" (sizeof(reloc_info))
  );
}

