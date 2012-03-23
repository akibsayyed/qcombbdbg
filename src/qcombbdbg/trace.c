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

DEFINE_GDB_SCRIPT("scripts/tools/gdb-python/trace.py");

trace_engine tengine;

/*
 *  Check whether registers has been collected for a frame.
 *  Since a trace frame is created for a single context, 
 *  we do not need to record registers multiple times in the same frame.
 */
int are_registers_collected(trace_frame * tframe)
{
  trace_entry * tentry;

  foreach_trace_entry(tframe, tentry)
    if ( tentry->type == TRACE_ENTRY_REGS )
      return 1;

  return 0;
}

void trace_start(void)
{
  tengine.status = 0;
  dbg_enable_all_tracepoints();
}

/*
 *  The trace engine has stopped.
 */
void trace_stop(char stop_reason)
{
  dbg_disable_all_tracepoints();
  tengine.status = stop_reason;
}

/*
 *  An error occured during a trace action.
 */
void trace_vm_error(trace_vm_state * state, char error)
{
  trace_stop(TRACE_STOP_ERROR);
  state->running = 0;
  state->error = error;
}

/*
 *  Finds a defined trace variable.
 */
trace_variable * trace_get_variable(unsigned short id)
{
  trace_variable * tvar;

  foreach_trace_var(tvar)
    if ( tvar->id == id)
      return tvar;

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
      size = sizeof(trace_registers_entry) + 1; 
      break;

    case TRACE_ENTRY_MEM:
      size = __builtin_offsetof(trace_memory_entry, data) + tentry->entry.mem.length + 1; 
      break;

    case TRACE_ENTRY_VAR:
      size = sizeof(trace_variable_entry) + 1;
      break;

    default:
      size = 0;
  }

  return size;
}

/*
 *  Returns the size occupied by a trace frame.
 */
unsigned int trace_frame_get_size(trace_frame * tframe)
{
  unsigned int size;
  trace_entry * tentry;

  size = 0;
  if ( tframe->entry_count > 0 )
    foreach_trace_entry(tframe, tentry)
      size += trace_entry_get_size(tentry);

  return size;
}

/*
 *  Add a new entry in the current trace frame.
 */
int trace_frame_add_entry(trace_frame * tframe, trace_entry * tentry)
{
  trace_entry * last_entry;
  unsigned int size;

  size = trace_entry_get_size(tentry);

  /* TODO: circular buffering */
  if ( size + tengine.tbuffer.used > tengine.tbuffer.size )
  {
    free(tentry);
    trace_stop(TRACE_STOP_BUFFER_FULL);
    return TRACE_STOP_BUFFER_FULL;
  }

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
int trace_buffer_trace_registers(trace_frame * tframe, saved_context * ctx)
{
  trace_entry * tentry;

  if ( are_registers_collected(tframe) )
    return 0;
  else
  {
    tentry = malloc(__builtin_offsetof(trace_entry, entry) + sizeof(trace_registers_entry));
    tentry->type = TRACE_ENTRY_REGS;
    __memcpy(&tentry->entry.regs.ctx, ctx, sizeof(saved_context));
    tentry->entry.regs.ctx.sp = (int)(ctx + 1);

    return trace_frame_add_entry(tframe, tentry);
  }
}

/*
 *  Records a piece of memory in the trace buffer.
 */
int trace_buffer_trace_memory(trace_frame * tframe, void * address, unsigned short length)
{
  trace_entry * tentry;

  tentry = malloc(__builtin_offsetof(trace_entry, entry.mem.data) + length);
  tentry->type = TRACE_ENTRY_MEM;
  tentry->entry.mem.address = address;
  tentry->entry.mem.length = length;

  if ( dbg_read_memory(address, &tentry->entry.mem.data, length) )
  {
    free(tentry);
    trace_stop(TRACE_STOP_ERROR);
    return TRACE_STOP_ERROR;
  }

  return trace_frame_add_entry(tframe, tentry);
}

/*
 *  Records the value of the variable in the trace buffer.
 */
int trace_buffer_trace_variable(trace_frame * tframe, unsigned short id)
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

  return trace_frame_add_entry(tframe, tentry);
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
trace_frame * trace_buffer_create_frame(breakpoint * tp)
{
  trace_frame * tframe;

  tframe = malloc(sizeof(trace_frame));
  tframe->tp = tp;
  tframe->entry_count = 0;
  tframe->entries = 0;
  tframe->next = 0;

  if ( tengine.tbuffer.last_frame )
    tengine.tbuffer.last_frame->next = tframe;
  else
    tengine.tbuffer.frames = tframe;
  
  tengine.tbuffer.last_frame = tframe;
  tengine.tbuffer.frame_created++;
  tengine.tbuffer.frame_count++;

  return tframe;
}

/*
 *  Clears the trace buffer.
 */
void trace_buffer_clear(void)
{
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
  tengine.tbuffer.last_frame = 0;
  tengine.tbuffer.frames = 0;
  tengine.tbuffer.frame_created = 0;
  tengine.tbuffer.frame_count = 0;
  tengine.tbuffer.used = 0;
}

/*
 *  Creates a new VM context.
 */
trace_vm_state * trace_vm_state_create(saved_context * saved_ctx, trace_frame * tframe)
{
  trace_vm_state * state;

  state = malloc(sizeof(trace_vm_state));
  if ( !state )
    return 0;

  state->arm_ctx = malloc(sizeof(context));
  if ( !state->arm_ctx )
  {
    free(state);
    return 0;
  }

  state->stack.stack = malloc(TRACE_VM_STACK_SIZE * sizeof(trace_vm_stack_val));
  if ( !state->stack.stack )
  {
    free(state->arm_ctx);
    free(state);
    return 0;
  }

  __memcpy(state->arm_ctx, saved_ctx, sizeof(saved_context));
  state->arm_ctx->sp = (int)(saved_ctx + 1);
  state->base_address = 0;
  state->pc = 0;
  state->running = 0;
  state->error = 0;
  state->stack.stack_ptr = 0;
  state->frame = tframe;

  return state;
}

/*
 *  Destroys a VM context.
 */
void trace_vm_state_destroy(trace_vm_state * state)
{
  free(state->arm_ctx);
  free(state->stack.stack);
  free(state);
}

/*
 *  Initializes the trace engine.
 */
void trace_engine_init(void)
{
  tengine.status = TRACE_STOP_NOT_RUN;
  //rex_initialize_critical_section(&tengine.critical_section);
  trace_buffer_clear();
}

#define PUSH(v) state->stack.stack[state->stack.stack_ptr++] = (trace_vm_stack_val)(v)
#define POP state->stack.stack[--state->stack.stack_ptr]
#define PEEK(n) state->stack.stack[state->stack.stack_ptr - n - 1]

DEFINE_OPCODE_HANDLER(not_implemented)
{
  trace_vm_error(state, TRACE_VM_ERROR_NOT_IMPLEMENTED);
}

DEFINE_OPCODE_HANDLER(add)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a + b);
}

DEFINE_OPCODE_HANDLER(sub)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a - b);
}

DEFINE_OPCODE_HANDLER(mul)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a * b);
}

DEFINE_OPCODE_HANDLER(divs)
{
  int a, b;

  b = POP.i; a = POP.i;
  if ( !b )
    return trace_vm_error(state, TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a / b);
}

DEFINE_OPCODE_HANDLER(divu)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  if ( !b )
    return trace_vm_error(state, TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a / b);
}

DEFINE_OPCODE_HANDLER(rems)
{
  int a, b;

  b = POP.i; a = POP.i;
  if ( !b )
    return trace_vm_error(state, TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a % b);
}

DEFINE_OPCODE_HANDLER(remu)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  if ( !b )
    return trace_vm_error(state, TRACE_VM_ERROR_DIV_BY_0);

  PUSH(a % b);
}

DEFINE_OPCODE_HANDLER(lsh)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a << b);
}

DEFINE_OPCODE_HANDLER(rshs)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a >> b);
}

DEFINE_OPCODE_HANDLER(rshu)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  PUSH(a >> b);
}

DEFINE_OPCODE_HANDLER(trace_quick, int size)
{
  void * addr;
  addr = (void *)POP.i;
  
  if ( trace_buffer_trace_memory(state->frame, addr, size) )
  {
    state->running = 0;
    state->error = TRACE_VM_ERROR_UNKNOWN;
  }
}

DEFINE_OPCODE_HANDLER(trace)
{
  trace_op_trace_quick(state, POP.i);
}

DEFINE_OPCODE_HANDLER(eqz)
{
  PUSH(POP.i == 0);
}

DEFINE_OPCODE_HANDLER(and)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a & b);
}

DEFINE_OPCODE_HANDLER(or)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a | b);
}

DEFINE_OPCODE_HANDLER(xor)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a ^ b);
}

DEFINE_OPCODE_HANDLER(not)
{
  PUSH(~POP.i);
}

DEFINE_OPCODE_HANDLER(eq)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a == b);
}

DEFINE_OPCODE_HANDLER(lts)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(a < b);
}

DEFINE_OPCODE_HANDLER(ltu)
{
  unsigned int a, b;

  b = POP.u; a = POP.u;
  PUSH(a < b);
}

DEFINE_OPCODE_HANDLER(ext, int n)
{
  int a, s;

  a = POP.i;
  s = sizeof(trace_vm_stack_val) * 8 - n; 

  PUSH((a << s) >> s);
}

DEFINE_OPCODE_HANDLER(ref8)
{
  unsigned char * addr;

  addr = (unsigned char *)POP.u;
  if ( !mmu_probe_read(addr, 1) )
    return trace_vm_error(state, TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);

  PUSH((unsigned int)*addr);
}

DEFINE_OPCODE_HANDLER(ref16)
{
  unsigned short * addr;

  addr = (unsigned short *)POP.u;
  if ( !mmu_probe_read(addr, 2) )
    return trace_vm_error(state, TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);

  PUSH((unsigned int)*addr);
}

DEFINE_OPCODE_HANDLER(ref32)
{
  unsigned int * addr;

  addr = (unsigned int *)POP.u;
  if ( !mmu_probe_read(addr, 4) )
    return trace_vm_error(state, TRACE_VM_ERROR_INVALID_MEMORY_ACCESS);

  PUSH(*addr);
}

DEFINE_OPCODE_HANDLER(goto, int offset)
{
  state->pc = state->base_address + offset;
}

DEFINE_OPCODE_HANDLER(if_goto, int offset)
{
  if ( POP.i )
    trace_op_goto(state, offset);
}

DEFINE_OPCODE_HANDLER(const, int c)
{
  PUSH(c);
}

DEFINE_OPCODE_HANDLER(pop)
{
  (void)POP.i;
}

DEFINE_OPCODE_HANDLER(reg, int n)
{
  int reg;

  if ( n == 25 )  /* cspr */
    reg = state->arm_ctx->saved_ctx.spsr;
  else if ( n < 13 ) /* r0-r12 */
    reg = ((int *)state->arm_ctx)[n + 1];
  else if ( n == 13 ) /* sp */
    reg = state->arm_ctx->sp;
  else /* lr, pc */
    reg = ((int *)state->arm_ctx)[n];

  PUSH(reg);
}

DEFINE_OPCODE_HANDLER(end)
{
  state->running = 0;
}

DEFINE_OPCODE_HANDLER(dup)
{
  PUSH(PEEK(0).i);
}

DEFINE_OPCODE_HANDLER(zext, int n)
{
  unsigned int a, s;

  a = POP.i;
  s = sizeof(trace_vm_stack_val) * 8 - n; 

  PUSH((a << s) >> s);
}

DEFINE_OPCODE_HANDLER(swap)
{
  int a, b;

  b = POP.i; a = POP.i;
  PUSH(b);
  PUSH(a);
}

DEFINE_OPCODE_HANDLER(getv, int n)
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

DEFINE_OPCODE_HANDLER(setv, int n)
{
  trace_set_variable(n, PEEK(0).i);
}

DEFINE_OPCODE_HANDLER(tracev, int n)
{
  if ( trace_buffer_trace_variable(state->frame, n) )
  {
    state->running = 0;
    state->error = TRACE_VM_ERROR_UNKNOWN;
  }
}

DEFINE_OPCODE_HANDLER(tracenz)
{
  /* TODO */
  trace_vm_error(state, TRACE_VM_ERROR_NOT_IMPLEMENTED);
}

DEFINE_OPCODE_HANDLER(trace16, int size)
{
  trace_op_trace_quick(state, size);
}

DEFINE_OPCODE_HANDLER(pick, int n)
{
  PUSH(PEEK(n).i);
}

DEFINE_OPCODE_HANDLER(rot)
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
  [OP_DIVS] = trace_op_divs,
  [OP_DIVU] = trace_op_divu,
  [OP_REMS] = trace_op_rems, 
  [OP_REMU] = trace_op_remu, 
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

/*
 *  Executes GDB bytecode into the given VM context.
 */
int trace_vm_exec(trace_vm_state * state, char * bytecode, unsigned int size)
{
  unsigned int arg;
  unsigned char opcode;

  state->base_address = state->pc = bytecode;
  state->running = 1;

  while ( state->running )
  {
    if ( (unsigned int)state->pc < (unsigned int)state->base_address ||
         (unsigned int)state->pc >= (unsigned int)state->base_address + size )
    {
      trace_vm_error(state, TRACE_VM_ERROR_INVALID_PC);
      break;
    }

    opcode = *(state->pc++);
    if ( opcode < 1 || opcode > TRACE_OPCODE_NR )
    {
      trace_vm_error(state, TRACE_VM_ERROR_INVALID_OPCODE);
      break;
    }

    switch ( opcode )
    {
      case OP_EXT:
      case OP_ZEXT:
      case OP_CONST8:
      case OP_PICK:
      case OP_TRACE_QUICK:
        arg = *(state->pc++);
        trace_vm_opcode_table[opcode].a1(state, arg);
        break;

      case OP_CONST16:
      case OP_IF_GOTO:
      case OP_GOTO:
      case OP_REG:
      case OP_GETV:
      case OP_SETV:
      case OP_TRACE16:
      case OP_TRACEV:
        arg = 0;
        arg |= *(state->pc++) << 8;
        arg |= *(state->pc++);
        trace_vm_opcode_table[opcode].a1(state, arg);
        break;
       
      case OP_CONST32:
        arg = 0;
        arg |= *(state->pc++) << 24;
        arg |= *(state->pc++) << 16;
        arg |= *(state->pc++) << 8;
        arg |= *(state->pc++);
        trace_vm_opcode_table[opcode].a1(state, arg);
        break;

      default:
        trace_vm_opcode_table[opcode].a0(state);
        break;
    }
  }

  return state->error;
}

/*
 *  Executes GDB bytecode into the given VM context.
 *  Returns top of stack in result.
 */
int trace_vm_eval(trace_vm_state * state, char * bytecode, unsigned int size, int * result)
{
  if ( trace_vm_exec(state, bytecode, size) );
    return state->error;

  *result = PEEK(0).i;
  return 0;
}

