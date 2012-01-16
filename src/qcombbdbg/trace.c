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
 *  trace.c: The tracepoint engine, including the tracepoint VM.
 */

#include "core.h"
#include "mmu.h"
#include "interrupts.h"
#include "trace.h"

trace_engine tengine;

/*
 *  Check whether registers has been collected for a frame.
 *  Since a trace frame is created for a single context, 
 *  we do not need to record registers multiple times in the same frame.
 */
int are_registers_collected(trace_frame * tframe)
{
  trace_entry * tentry;

  tentry = tframe->entries;
  while ( tentry )
  {
    if ( tentry->type == TRACE_ENTRY_REGS )
      return 1;

    tentry = tentry->next;
  }

  return 0;
}

/*
 *  The trace engine has stopped.
 */
void trace_stop(char stop_reason)
{
  tengine.vm.running = 0;
  tengine.status = stop_reason;
}

/*
 *  An error occured during a trace action.
 */
void trace_error(char error)
{
  trace_stop(TRACE_STOP_ERROR);
  tengine.vm.error = error;
}

/*
 *  Finds a defined trace variable.
 */
trace_variable * trace_get_variable(unsigned short id)
{
  trace_variable * tvar;

  tvar = tengine.tvars;
  while ( tvar )
  {
    if ( tvar->id == id)
      return tvar;

    tvar = tvar->next;
  }

  return 0;
}

/*
 *  Sets a trace variable value.
 */
void trace_set_variable(unsigned short id, int value)
{
  trace_variable * tvar;

  tvar = trace_get_variable(id);
  if ( !tvar )
  {
    tvar = malloc(sizeof(trace_variable));
    tvar->id = id;
    tvar->value = value;

    tvar->next = tengine.tvars; tvar->prev = 0;
    tengine.tvars = tvar;
  }
  else
    tvar->value = value;
}

/*
 *  Returns the size of a trace entry.
 */
unsigned int trace_entry_get_size(trace_entry * tentry)
{
  unsigned int size;

  switch ( tentry->type )
  {
    case TRACE_ENTRY_REGS:
      size = sizeof(trace_registers_entry); 
      break;

    case TRACE_ENTRY_MEM:
      size = __builtin_offsetof(trace_memory_entry, data) + tentry->entry.mem.length; 
      break;

    case TRACE_ENTRY_VAR:
      size = sizeof(trace_variable_entry);
      break;
  }

  return size;
}

/*
 *  Add a new entry in the current trace frame.
 */
int trace_buffer_add_entry(trace_entry * tentry)
{
  trace_entry * last_entry;
  trace_frame * tframe;
  unsigned int size;

  size = trace_entry_get_size(tentry);

  if ( size + tengine.tbuffer.used > tengine.tbuffer.size )
  {
    free(tentry);
    return TRACE_STOP_BUFFER_FULL;
  }

  tframe = tengine.tbuffer.current_frame;
  if ( tframe->entry_count )
  {
    last_entry = tframe->entries;
    while ( last_entry->next ) last_entry = last_entry->next;

    last_entry->next = tentry;
  }
  else
    tframe->entries = tentry;
  
  tentry->next = 0;

  tengine.tbuffer.used += size;
  tframe->entry_count++;

  return 0;
}

/*
 *  Records the current thread context in the trace buffer.
 */
int trace_buffer_trace_registers(context * ctx)
{
  trace_entry * tentry;

  if ( are_registers_collected(tengine.tbuffer.current_frame) )
    return 0;
  else
  {
    tentry = malloc(__builtin_offsetof(trace_entry, entry) + sizeof(trace_registers_entry));
    tentry->type = TRACE_ENTRY_REGS;
    __memcpy(&tentry->entry.regs.ctx, ctx, sizeof(context));

    return trace_buffer_add_entry(tentry);
  }
}

/*
 *  Records a piece of memory in the trace buffer.
 */
int trace_buffer_trace_memory(void * address, unsigned short length)
{
  trace_entry * tentry;

  tentry = malloc(__builtin_offsetof(trace_entry, entry.mem.data) + length);
  tentry->type = TRACE_ENTRY_MEM;
  tentry->entry.mem.length = length;

  if ( dbg_read_memory(address, &tentry->entry.mem.data, length) )
  {
    free(tentry);
    trace_error(TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);
    return TRACE_STOP_ERROR;
  }

  return trace_buffer_add_entry(tentry);
}

/*
 *  Records the value of the variable in the trace buffer.
 */
int trace_buffer_trace_variable(unsigned short id)
{
  trace_variable * tvar;
  trace_entry * tentry;

  tentry = malloc(__builtin_offsetof(trace_entry, entry) + sizeof(trace_variable_entry));
  tentry->type = TRACE_ENTRY_VAR;
  tentry->entry.var.id = id;

  tvar = trace_get_variable(id);
  if ( !tvar )
  {
    trace_set_variable(id, 0);
    tentry->entry.var.value = 0;
  }
  else
    tentry->entry.var.value = tvar->value;

  return trace_buffer_add_entry(tentry);
}

/*
 *  If the trace buffer is circular, we might need to remove old frames.
 */
int trace_buffer_remove_oldest_frame(void)
{
  trace_frame * tframe;
  trace_entry * tentry, * curr_entry;

  if ( tengine.tbuffer.frame_count < 2 )
    return -1;

  tframe = tengine.tbuffer.frames;
  tentry = tframe->entries;
  while ( tentry )
  {
    curr_entry = tentry;
    
    tengine.tbuffer.used -= trace_entry_get_size(curr_entry);
    free(curr_entry);

    tentry = tentry->next;
  }

  tengine.tbuffer.frames = tframe->next;
  tengine.tbuffer.frame_count--;
  free(tframe);

  return 0;
}

/*
 *  Creates a new frame in the trace buffer.
 *  A frame is created when a tracepoint is hit.
 *  Every tracepoint actions creates a new entry in the frame.
 */
trace_frame * trace_buffer_create_frame(unsigned short tp_id)
{
  trace_frame * tframe;

  tframe = malloc(sizeof(trace_frame));
  tframe->tracepoint_id = tp_id;
  tframe->entry_count = 0;
  tframe->entries = 0;
  tframe->next = 0;

  if ( tengine.tbuffer.current_frame )
    tengine.tbuffer.current_frame->next = tframe;
  else
    tengine.tbuffer.frames = tframe;

  
  tengine.tbuffer.current_frame = tframe;
  tengine.tbuffer.frame_created++;
  tengine.tbuffer.frame_count++;

  return tframe;
}

/*
 *  Clears the trace buffer.
 */
void trace_buffer_clear(void)
{
  int f, e;
  trace_frame * curr_frame, * tframe;
  trace_entry * curr_entry, * tentry;

  tframe = tengine.tbuffer.frames;
  while ( tframe )
  {
    curr_frame = tframe;
    tentry = tframe->entries;
    while ( tentry )
    {
      curr_entry = tentry;
      tentry = tentry->next;
      free(curr_entry);
    }
    tframe = tframe->next;
    free(curr_frame);
  }

  tengine.tbuffer.size = TRACE_BUFFER_DEFAULT_SIZE;
  tengine.tbuffer.current_frame = 0;
  tengine.tbuffer.frame_created = 0;
  tengine.tbuffer.frame_count = 0;
  tengine.tbuffer.used = 0;
}

void trace_vm_init(void)
{
  tengine.vm.base_address = 0;
  tengine.vm.pc = 0;
  tengine.vm.running = 0;
  tengine.vm.error = 0;
  tengine.vm.arm_ctx = 0;

  tengine.vm.stack.stack = malloc(TRACE_VM_STACK_SIZE * sizeof(trace_vm_stack_val));
  tengine.vm.stack.stack_ptr = 0;
}

void trace_engine_init(void)
{
  tengine.status = TRACE_STOP_NOT_RUN;

  trace_vm_init();
  trace_buffer_clear();
}

#define PUSH(v) tengine.vm.stack.stack[tengine.vm.stack.stack_ptr++] = (trace_vm_stack_val)(v)
#define POP tengine.vm.stack.stack[--tengine.vm.stack.stack_ptr]
#define PEEK(n) tengine.vm.stack.stack[tengine.vm.stack.stack_ptr - n - 1]

void trace_op_not_implemented(void)
{
  trace_error(TRACE_VM_ERROR_NOT_IMPLEMENTED);
}

void trace_op_add(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a + b);
}

void trace_op_sub(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a - b);
}

void trace_op_mul(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a * b);
}

void trace_op_divs(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  if ( !b )
    return trace_error(TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a / b);
}

void trace_op_divu(void)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  if ( !b )
    return trace_error(TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a / b);
}

void trace_op_rems(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  if ( !b )
    return trace_error(TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a % b);
}

void trace_op_remu(void)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  if ( !b )
    return trace_error(TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a % b);
}

void trace_op_lsh(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a << b);
}

void trace_op_rshs(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a >> b);
}

void trace_op_rshu(void)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  PUSH(a >> b);
}

void trace_op_trace_quick(int size)
{
  int stop;
  void * addr;

  addr = (void *)POP.i;
  
  trace_buffer_trace_memory(addr, size);
}

void trace_op_trace(void)
{
  trace_op_trace_quick(POP.i);
}

void trace_op_eqz(void)
{
  PUSH(POP.i == 0);
}

void trace_op_and(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a & b);
}

void trace_op_or(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a | b);
}

void trace_op_xor(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a ^ b);
}

void trace_op_not(void)
{
  PUSH(~POP.i);
}

void trace_op_eq(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a == b);
}

void trace_op_lts(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a < b);
}

void trace_op_ltu(void)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  PUSH(a < b);
}

void trace_op_ext(int n)
{
  int a, s;

  a = POP.i;
  s = sizeof(trace_vm_stack_val) * 8 - n; 

  PUSH((a << s) >> s);
}

void trace_op_ref8(void)
{
  unsigned char * addr;

  addr = (unsigned char *)POP.u;
  if ( !mmu_probe_read(addr, 1) )
    return trace_error(TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);

  PUSH((unsigned int)*addr);
}

void trace_op_ref16(void)
{
  unsigned short * addr;

  addr = (unsigned short *)POP.u;
  if ( !mmu_probe_read(addr, 2) )
    return trace_error(TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);

  PUSH((unsigned int)*addr);
}

void trace_op_ref32(void)
{
  unsigned int * addr;

  addr = (unsigned int *)POP.u;
  if ( !mmu_probe_read(addr, 4) )
    return trace_error(TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);

  PUSH(*addr);
}

void trace_op_goto(int offset)
{
  tengine.vm.pc = tengine.vm.base_address + offset;
}

void trace_op_if_goto(int offset)
{
  if ( POP.i )
    trace_op_goto(offset);
}

void trace_op_const(int c)
{
  PUSH(c);
}

void trace_op_pop(void)
{
  POP.i;
}

void trace_op_reg(int n)
{
  int reg;

  if ( n == 25 )  /* cspr */
    reg = tengine.vm.arm_ctx->saved_ctx.spsr;
  else if ( n < 13 ) /* r0-r12 */
    reg = ((int *)tengine.vm.arm_ctx)[n + 1];
  else if ( n == 13 ) /* sp */
    reg = tengine.vm.arm_ctx->sp;
  else /* lr, pc */
    reg = ((int *)tengine.vm.arm_ctx)[n];

  PUSH(reg);
}

void trace_op_end(void)
{
  tengine.vm.running = 0;
}

void trace_op_dup(void)
{
  PUSH(PEEK(0).i);
}

void trace_op_zext(int n)
{
  unsigned int a, s;

  a = POP.i;
  s = sizeof(trace_vm_stack_val) * 8 - n; 

  PUSH((a << s) >> s);
}

void trace_op_swap(void)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(b);
  PUSH(a);
}

void trace_op_getv(int n)
{
  trace_variable * tvar;

  tvar = trace_get_variable(n);
  if ( tvar )
    PUSH(tvar->value);
  else
  {
    trace_set_variable(n, 0);
    PUSH(0);
  }
}

void trace_op_setv(int n)
{
  trace_set_variable(n, PEEK(0).i);
}

void trace_op_tracev(int n)
{
  trace_buffer_trace_variable(n);
}

void trace_op_tracenz(void)
{
  /* TODO */
}

void trace_op_trace16(int size)
{
  trace_op_trace_quick(size);
}

void trace_op_pick(int n)
{
  PUSH(PEEK(n).i);
}

void trace_op_rot(void)
{
  int a, b, c;

  c = POP.i; b = POP.i; a = POP.i;
  PUSH(c);
  PUSH(b);
  PUSH(a);
}

trace_vm_opcode_handler trace_vm_opcode_table[TRACE_OPCODE_NR + 1] =
{
  [OP_FLOAT] = trace_op_not_implemented,
  [OP_ADD] = trace_op_add,
  [OP_SUB] = trace_op_sub,
  [OP_MUL] = trace_op_mul,
  [OP_DIVS] = trace_op_not_implemented, //trace_op_divs,
  [OP_DIVU] = trace_op_not_implemented, //trace_op_divu,
  [OP_REMS] = trace_op_not_implemented, //trace_op_rems, 
  [OP_REMU] = trace_op_not_implemented, //trace_op_remu, 
  [OP_LSH] = trace_op_lsh,
  [OP_RSHS] = trace_op_rshs,
  [OP_RSHU] = trace_op_rshu,
  [OP_TRACE] = trace_op_trace,
  [OP_TRACE_QUICK].a1 = trace_op_trace_quick,
  [OP_EQZ] = trace_op_eqz,
  [OP_AND] = trace_op_and,
  [OP_OR] = trace_op_or,
  [OP_XOR] = trace_op_xor,
  [OP_NOT] = trace_op_not,
  [OP_EQ] = trace_op_eq,
  [OP_LTS] = trace_op_lts,
  [OP_LTU] = trace_op_ltu,
  [OP_EXT].a1 = trace_op_ext,
  [OP_REF8] = trace_op_ref8,
  [OP_REF16] = trace_op_ref16,
  [OP_REF32] = trace_op_ref32,
  [OP_REF64] = trace_op_not_implemented,
  [OP_REF_FLOAT] = trace_op_not_implemented,
  [OP_REF_DOUBLE] = trace_op_not_implemented,
  [OP_REF_LONG_DOUBLE] = trace_op_not_implemented,
  [OP_L2D] = trace_op_not_implemented,
  [OP_D2L] = trace_op_not_implemented,
  [OP_IF_GOTO].a1 = trace_op_if_goto,
  [OP_GOTO].a1 = trace_op_goto,
  [OP_CONST8].a1 = trace_op_const,
  [OP_CONST16].a1 = trace_op_const,
  [OP_CONST32].a1 = trace_op_const,
  [OP_CONST64] = trace_op_not_implemented,
  [OP_REG].a1 = trace_op_reg,
  [OP_END] = trace_op_end,
  [OP_DUP] = trace_op_dup,
  [OP_POP] = trace_op_pop,
  [OP_ZEXT].a1 = trace_op_zext,
  [OP_SWAP] = trace_op_swap,
  [OP_GETV].a1 = trace_op_getv,
  [OP_SETV].a1 = trace_op_setv,
  [OP_TRACEV].a1 = trace_op_tracev,
  [OP_TRACENZ] = trace_op_tracenz,
  [OP_TRACE16].a1 = trace_op_trace16,
  [OP_UNDEF] = trace_op_not_implemented,
  [OP_PICK].a1 = trace_op_pick,
  [OP_ROT] = trace_op_rot
};

int trace_vm_exec(char * bytecode, unsigned int size, context * arm_ctx)
{
  int arg;
  char opcode;

  tengine.vm.base_address = tengine.vm.pc = bytecode;
  tengine.vm.arm_ctx = arm_ctx;
  tengine.vm.running = 1;

  while ( tengine.vm.running )
  {
    if ( (unsigned int)tengine.vm.pc < (unsigned int)tengine.vm.base_address ||
         (unsigned int)tengine.vm.pc >= (unsigned int)tengine.vm.base_address + size )
    {
      trace_error(TRACE_VM_ERROR_INVALID_PC);
      break;
    }

    opcode = *tengine.vm.pc++;
    if ( opcode < 1 || opcode > TRACE_OPCODE_NR )
    {
      trace_error(TRACE_VM_ERROR_INVALID_OPCODE);
      break;
    }

    switch ( opcode )
    {
      case OP_EXT:
      case OP_ZEXT:
      case OP_CONST8:
      case OP_PICK:
      case OP_TRACE_QUICK:
        arg = *tengine.vm.pc++;
        trace_vm_opcode_table[opcode].a1(arg);      
        break;

      case OP_CONST16:
      case OP_IF_GOTO:
      case OP_GOTO:
      case OP_REG:
      case OP_GETV:
      case OP_SETV:
      case OP_TRACE16:
      case OP_TRACEV:
        arg = *(short *)tengine.vm.pc;
        tengine.vm.pc += sizeof(short);
        trace_vm_opcode_table[opcode].a1(arg);      
        break;
       
      case OP_CONST32:
        arg = *(int *)tengine.vm.pc;
        tengine.vm.pc += sizeof(int);
        trace_vm_opcode_table[opcode].a1(arg);      
        break;

      default:
        trace_vm_opcode_table[opcode].a0();      
        break;
    }
  }

  return PEEK(0).i;
}

