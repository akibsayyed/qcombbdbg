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

#ifndef __TRACE_H
#define __TRACE_H

#define DEFINE_GDB_SCRIPT(script_name) \
  asm("\
    .pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\n\
    .byte 1\n\
    .asciz \"" script_name "\"\n\
    .popsection \n\
    ");

#define foreach_trace_frame(tf) for ( tf = tengine.tbuffer.frames; tf != 0; tf = tf->next )
#define foreach_trace_entry(tf, te) for ( te = tf->entries; te != 0; te = te->next )
#define foreach_trace_var(tv) for ( tv = tengine.tvars; tv != 0; tv = tv->next )

/* Registers entry */
typedef struct __attribute__((packed))
{
  context ctx;
} trace_registers_entry;

/* Memory entry */
typedef struct __attribute__((packed))
{
  void * address;
  unsigned short length;
  char data[1];
} trace_memory_entry;

/* Trace variable entry */
typedef struct __attribute__((packed))
{
  unsigned short id;
  int value;
} trace_variable_entry;

/*
 *  A trace entry can contain:
 *    - A trace of the registers.
 *    - A piece of memory
 *    - A saved trace variable value.
 */
#define TRACE_ENTRY_REGS 'R'
#define TRACE_ENTRY_MEM 'M'
#define TRACE_ENTRY_VAR 'V'

/*
 *  An entry in a trace frame.
 *  A trace frame can contain multiple entries.
 */
typedef struct __attribute__((packed)) _trace_entry
{
  struct _trace_entry * next;

  char type;
  union 
  {
    trace_registers_entry regs;
    trace_memory_entry mem;
    trace_variable_entry var;
  } entry;
} trace_entry;

/*
 *  A frame in the trace buffer.
 *  A new frame is created each time a tracepoint is hit.
 */
typedef struct _trace_frame
{
  struct _trace_frame * next;

  breakpoint *tp;
  unsigned int entry_count;
  trace_entry * entries;

} trace_frame;

#define TRACE_BUFFER_DEFAULT_SIZE 0x10000

/*
 *  The global trace buffer.
 */
typedef struct
{
  char circular;
  unsigned int size;
  unsigned int used;

  unsigned int frame_created;
  unsigned int frame_count;
  trace_frame * frames;
  trace_frame * last_frame;
} trace_buffer;

/*
 *  Definition of a trace variable.
 */
typedef struct _trace_variable
{
  unsigned short id;
  int value;
  struct _trace_variable * next;
  struct _trace_variable * prev;
} trace_variable;

/*
 *  Reasons for which the trace engine could be stopped.
 */
enum trace_stop_reasons
{
  /* The trace has not been started */
  TRACE_STOP_NOT_RUN = 1,

  /* The trace has been stopped by user command */
  TRACE_STOP_USER,

  /* The trace buffer cannot hold any more information */
  TRACE_STOP_BUFFER_FULL,

  /* The client has detached */
  TRACE_STOP_DISCONNECTED,

  /* No more pass for tracepoints */
  TRACE_STOP_NO_MORE_PASS,

  /* An error occurred in the tracepoint action */
  TRACE_STOP_ERROR,

  /* Unknown reason */
  TRACE_STOP_UNKNOWN
};

#define TRACE_OPCODE_NR 0x33
enum trace_vm_opcodes
{
  OP_FLOAT = 1,        /* not implemented */
  OP_ADD,              
  OP_SUB,              
  OP_MUL,              
  OP_DIVS,             
  OP_DIVU,
  OP_REMS,
  OP_REMU,
  OP_LSH,
  OP_RSHS,
  OP_RSHU,
  OP_TRACE,
  OP_TRACE_QUICK,
  OP_EQZ,               /* equals zero */
  OP_AND,
  OP_OR,
  OP_XOR,
  OP_NOT,
  OP_EQ,               /* equals */
  OP_LTS,              /* less than signed */
  OP_LTU,              /* less than unsigned */
  OP_EXT,              /* sign ext */
  OP_REF8,
  OP_REF16,
  OP_REF32,
  OP_REF64,
  OP_REF_FLOAT,        /* not implemented */
  OP_REF_DOUBLE,       /* not implemented */
  OP_REF_LONG_DOUBLE,  /* not implemented */
  OP_L2D,              /* not implemented */
  OP_D2L,              /* not implemented */
  OP_IF_GOTO,
  OP_GOTO,
  OP_CONST8,
  OP_CONST16,
  OP_CONST32,
  OP_CONST64,
  OP_REG,
  OP_END,
  OP_DUP,
  OP_POP,
  OP_ZEXT,             /* zero ext */
  OP_SWAP,
  OP_GETV,
  OP_SETV,
  OP_TRACEV,
  OP_TRACENZ,
  OP_TRACE16,
  OP_UNDEF,
  OP_PICK,
  OP_ROT
};

typedef union
{
  int i;
  unsigned int u;
  float d;
} trace_vm_stack_val;

#define TRACE_VM_STACK_SIZE 512
typedef struct
{
  int stack_ptr;
  trace_vm_stack_val * stack;
} trace_vm_stack;

/*
 *  The trace action VM control structure.
 */
typedef struct
{
  /* The VM stack */
  trace_vm_stack stack;

  /* The VM bytecode address */
  char * base_address;

  /* The current instruction address */
  char * pc;

  /* The real CPU context */
  context * arm_ctx;

  /* VM running state */
  char running;

  /* Last error */
  char error;

  /* Associated trace frame in the trace buffer */
  trace_frame * frame;
} trace_vm_state;

/*
 *  Errors which could have been fired during the execution of a trace action.
 */
enum trace_vm_error
{
  TRACE_VM_ERROR_DIV_BY_0 = 1,
  TRACE_VM_ERROR_INVALID_OPCODE,
  TRACE_VM_ERROR_NOT_IMPLEMENTED,
  TRACE_VM_ERROR_INVALID_PC,
  TRACE_VM_ERROR_INVALID_MEMORY_ACCESS,
  TRACE_VM_ERROR_UNKNOWN
};

#define DEFINE_OPCODE_HANDLER(opcode, ...) void trace_op_##opcode(trace_vm_state * state, ##__VA_ARGS__)

typedef void (* trace_vm_opcode_handler_0)(trace_vm_state *);
typedef void (* trace_vm_opcode_handler_1)(trace_vm_state *, int);

typedef union
{
  trace_vm_opcode_handler_0 a0;
  trace_vm_opcode_handler_1 a1;
} trace_vm_opcode_handler;

/*
 *  The main trace engine control structure.
 */
typedef struct
{
  char status;
  trace_variable * tvars; 
  trace_buffer tbuffer;
  //rex_critical_section critical_section;
} trace_engine;

void trace_engine_init(void);
void trace_buffer_clear(void);
void trace_start(void);
void trace_stop(char);

trace_vm_state * trace_vm_state_create(saved_context *, trace_frame *);
void trace_vm_state_destroy(trace_vm_state *);
int trace_vm_exec(trace_vm_state *, char *, unsigned int);
int trace_vm_eval(trace_vm_state *, char *, unsigned int, int *);

unsigned int trace_frame_get_size(trace_frame *);
unsigned int trace_entry_get_size(trace_entry *);
trace_frame * trace_buffer_create_frame(breakpoint*);
int trace_buffer_trace_registers(trace_frame *, saved_context *);
int trace_buffer_trace_memory(trace_frame *, void *, unsigned short);

trace_variable * trace_get_variable(unsigned short);
void trace_set_variable(unsigned short, int);

#endif

