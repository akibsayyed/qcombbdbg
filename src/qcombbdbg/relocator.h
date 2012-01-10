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

#ifndef __RELOCATOR_H
#define __RELOCATOR_H

/*
 *  ARM general purpose registers.
 */
enum arm_registers
{
  REG_R0 = 0,
  REG_R1,
  REG_R2,
  REG_R3,
  REG_R4,
  REG_R5,
  REG_R6,
  REG_R7,
  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_SP,
  REG_LR,
  REG_PC
};

#define T_RBIT(reg) \
  ((reg == REG_PC) ? (1 << 8) : (1 << reg))

#define THUMB_REGISTER_MASK 0x7 /* b111 */
#define ARM_REGISTER_MASK 0xf   /* b1111 */

#define IS_HI_REG(reg) (reg > REG_R7)
#define NEXT_THUMB_REG(reg) ((reg + 1) & THUMB_REGISTER_MASK)

/*
 *  Thumb instructions that need to be relocated.
 */
enum thumb_insns
{
  T_ADD_HI,
  T_ADD_PC_IMM8,
  T_ADD_SP_IMM7,
  T_B_COND,
  T_B,
  T_BL,
  T_BLX,
  T_BLX_REG,
  T_BX,
  /* T_CMP_HI, Do not take into account the case CMP PC, reg */
  T_LDR_PC_IMM8,
  T_MOV_HI,
  T_POP_WITH_PC,
  T_POP_WITHOUT_PC,
  T_PUSH,
  T_SUB_SP_IMM7,
};

#define THUMB_REGISTER_BITMAP_MASK 0x1ff /* b1_11111111 */
#define THUMB_CONDITION_MASK 0xf00

#define THUMB_NOP 0x46c0

#define T_LDR_SP_IMM8_OPCODE 0x9800
#define T_STR_SP_IMM8_OPCODE 0x9000
#define T_MOV_LO_OPCODE 0x1c00
#define T_MOV_IMM8_OPCODE 0x2000
#define T_ORR_OPCODE 0x4300
#define T_ADC_OPCODE 0x4140
#define T_BIC_OPCODE 0x4380
#define T_LSL_OPCODE 0x4080
#define T_ASR_OPCODE 0x4100
#define T_LDR_REG_REG_OPCODE 0x5800
#define T_ADD_REG_REG_OPCODE 0x1800

/*
 *  ARM conditional flags in the SPR.
 */
enum arm_conditions
{
  COND_EQ,
  COND_NE,
  COND_CS,
  COND_CC,
  COND_MI,
  COND_PL,
  COND_VS,
  COND_VC,
  COND_HI,
  COND_LS,
  COND_GE,
  COND_LT,
  COND_GT,
  COND_LE,
  COND_AL,
};

#define REVERSE_COND(cond) ( ((cond >> 1) << 1) + 1 - (cond % 2) )
#define STACK_SHIFT 64

/*
 *  Structure needed by the relocated code.
 *  Positioned at $sp - STACK_SHIFT
 */
typedef struct
{
  unsigned int pc;
  unsigned int cpsr;
  int thumb_bit;
} rel_ctrl;

typedef unsigned short thumb_insn;
typedef unsigned int arm_insn;

typedef int (*insn_op_get)(thumb_insn); 
typedef thumb_insn (*insn_op_set)(thumb_insn, int);

/*
 *  Thumb instruction definition.
 */
typedef struct
{
  int can_read_pc : 1;  /* Can reference pc (e.g. load relative) */
  int can_write_pc : 1; /* Can modify pc (e.g. pop return address) */
  int can_write_sp : 1; /* Can modify sp (e.g stack frame create/destroy) */
  int reads_pc : 1;     /* Inconditionaly reads pc (e.g. relative branches) */
  int writes_sp : 1;    /* Inconditionaly reads sp (e.g. push/pop) */
  int branch : 1;       /* Inconditionaly writes pc (branches) */
  int link : 1;         /* Branch link */

  /* Opcode pattern */
  struct 
  {
    unsigned short mask;
    unsigned short value;
  } opcode;

  /* Operands read/write access */
  struct
  {
    insn_op_get get;
    insn_op_set set;
  } operands[2];
} thumb_insn_def;

int relocate_thumb_insn(thumb_insn *, thumb_insn *, int *);

#endif

