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

#ifndef __CMD_H
#define __CMD_H

#include "rex.h"

register char * stack asm("sp");

/* Hooked command from the diagnostic task */
#define DBG_CMD 0x7b
#define DBG_MAX_PACKET_SIZE 4096

typedef int task_id;
#define TASK_IDLE 1

/* REX signal used to break/resume tasks */
#define SIGNAL_DEBUG (1 << 31)

/* Error control codes */
#define ERROR_CMD_NOT_FOUND -1
#define ERROR_TASK_NOT_FOUND -2
#define ERROR_INVALID_TASK_STATE -3
#define ERROR_BREAKPOINT_ALREADY_EXISTS -4
#define ERROR_NO_BREAKPOINT -5
#define ERROR_BAD_ADDRESS_ALIGNMENT -6
#define ERROR_INVALID_CPU_MODE -7
#define ERROR_INVALID_MEMORY_ACCESS -8
#define ERROR_NO_TRACEPOINT -9
#define ERROR_NO_TRACE_VARIABLE -10
#define ERROR_NO_MEMORY_AVAILABLE -11

/* Memory breakpoint opcodes */
#define ARM_BKPT 0xe1200070
#define THUMB_BKPT 0xbe00 
#define THUMB_UNDEF 0xde00

enum cmd_type 
{
  /* Attach / detach commands */
  CMD_ATTACH,
  CMD_DETACH,

  /* Thread info commands */
  CMD_GET_NUM_TASKS,
  CMD_GET_TASK_INFO,
  CMD_GET_TASK_STATE,

  /* Thread control commands */
  CMD_STOP_TASK,
  CMD_RESUME_TASK,

  /* Basic debugger commands */
  CMD_READ_MEM,
  CMD_WRITE_MEM,
  CMD_GET_REGS,
  CMD_SET_REGS,
  CMD_INSERT_BREAKPOINT,
  CMD_REMOVE_BREAKPOINT,

  /* Tracepoints related commands */
  CMD_INSERT_TRACEPOINT,
  CMD_REMOVE_TRACEPOINT,
  CMD_TRACE_CLEAR,
  CMD_TRACE_START,
  CMD_TRACE_STOP,
  CMD_TRACE_STATUS,
  CMD_GET_TVAR,
  CMD_SET_TVAR,

#ifdef DEBUG
  CMD_DEBUG_ECHO = 0x80,  /* Simple echo */
  CMD_DEBUG_CALL,         /* Call function and return r0-r1 */
  CMD_DEBUG_TRIGGER_EXCEPTION,
  CMD_DEBUG_TRIGGER_STACK_OVERFLOW,
  CMD_DEBUG_SEND_SIGNAL,  /* Send a signal to a task */
  CMD_DEBUG_RELOC_INSN,   /* Relocate an instruction */
#endif
};

/*
 *  Responses are synchronous packets resulting from a debugger command.
 *  Events are asynchronous packets emitted during a debug event.
 */
enum packet_type 
{
  PACKET_RESPONSE,
  PACKET_EVENT
};

enum event_type 
{
  EVENT_STOP,
  EVENT_BREAKPOINT,
  EVENT_MEMORY_FAULT,
  EVENT_ILLEGAL_INSTRUCTION
};

enum task_state 
{
  TASK_STATE_ALIVE,
  TASK_STATE_HALTED,
  TASK_STATE_DEAD,
  TASK_STATE_UNKNOWN
};

enum breakpoint_type 
{
  BREAKPOINT_NORMAL,
  BREAKPOINT_TRACE
};

enum exception_type
{
  EXCEPTION_UNDEF_INSN,
  EXCEPTION_SOFTWARE,
  EXCEPTION_PREFETCH_ABORT,
  EXCEPTION_DATA_ABORT
};

/* Debug structures */
typedef struct __attribute__((packed)) _saved_context
{
  int spsr;
  int r0;
  int r1;
  int r2;
  int r3;
  int r4;
  int r5;
  int r6;
  int r7;
  int r8;
  int r9;
  int r10;
  int r11;
  int r12;
  int lr;
  int pc;
} saved_context;

typedef struct __attribute__((packed))
{
  saved_context saved_ctx;
  int sp;
} context;

typedef struct __attribute__((packed)) _breakpoint
{
  struct _breakpoint * next;
  struct _breakpoint * prev;

  char type;
  char kind; /* arm/thumb */
  void * address; 
  void * relocated_address;
  int original_insn;

  union {
    struct {
      char enabled;
      int hits;
      int pass;

      struct {
        unsigned int size;
        char * bytecode;
      } condition;
    } trace;

    struct {
      char access;
      unsigned int start;
      unsigned int end;
    } watch;
  };
} breakpoint;

typedef struct __attribute__((packed, aligned(4)))
{
  rex_task * task;
  int state;
  saved_context * ctx;
  int saved_sp;
} task_entry;

typedef struct __attribute__((packed, aligned(4)))
{
  int num_tasks;
  task_entry * tasks;
} task_list;

/* Command structures */
typedef struct __attribute__((packed, aligned(4)))
{
  char hooked_cmd; // DBG_CMD
  char cmd_type;
  union 
  {
    task_id tid;

    struct {
      void * base;
      unsigned int size;
    } read;
    
    struct {
      void * dest;
      char data[1];
    } write;

    struct {
      task_id tid;
      context ctx;
    } set_regs;

    struct {
      void * address;
      char kind;
    } breakpoint;

    struct {
      long long int (* f)(int, int, int, int);
      int arg1;
      int arg2;
      int arg3;
      int arg4;
    } call;

    struct {
      task_id tid;
      int exception;
    } exception;

    struct {
      task_id tid;
      char data[1];
    } overflow;

    struct {
      task_id tid;
      int sigs;
    } signal;

    struct {
      void * src;
      void * dst;
    } reloc;

    struct __attribute__((packed)) {
      unsigned short id;
      int value;
    } tvar;
  };
} request_packet;

typedef struct __attribute__((packed, aligned(4)))
{
  char type;
  char error_code;

  union 
  {
    int num_tasks;
    int task_state;
    int size;
    int tvar_value;
    char data[1];

    context ctx;

    struct {
      int wait_signals;
      int active_signals;
      char name[1];
    } task_info;

    struct {
      long long int result;
    } call;

    struct __attribute__((packed)) {
      char status;
      char circular;
      unsigned int tframes;
      unsigned int tcreated;
      unsigned int tsize;
      unsigned int tfree;
    } tstatus;
    
  };
} response_packet;

typedef struct __attribute__((packed, aligned(4)))
{
  char type;
  task_id tid;
  int event;
  context ctx;
} event_packet;

void * malloc(int);
void free(void *);
response_packet * alloc_response_packet(int);
int dbg_read_memory(void *, void *, unsigned int);

#ifdef DEBUG
response_packet * __cmd_echo(request_packet *, int);
response_packet * __cmd_call_routine(long long int (* f)(int, int, int, int), int, int, int, int);
response_packet * __cmd_trigger_exception(task_id, int);
response_packet * __cmd_trigger_stack_overflow(task_id, char *, int);
response_packet * __cmd_send_signal(task_id, int);
response_packet * __cmd_reloc_insn(void *, void *);
#endif

response_packet * __cmd_attach(void);
response_packet * __cmd_detach(void);
response_packet * __cmd_get_num_tasks(void);
response_packet * __cmd_get_task_info(task_id);
response_packet * __cmd_get_task_state(task_id);
response_packet * __cmd_stop_task(task_id);
response_packet * __cmd_resume_task(task_id);
response_packet * __cmd_read_memory(void *, unsigned int);
response_packet * __cmd_write_memory(void *, void *, int);
response_packet * __cmd_read_registers(task_id);
response_packet * __cmd_write_registers(task_id, context *);
response_packet * __cmd_insert_breakpoint(void *, char);
response_packet * __cmd_remove_breakpoint(void *);

response_packet * __cmd_trace_clear(void);
response_packet * __cmd_trace_status(void);
response_packet * __cmd_get_trace_variable(unsigned short);
response_packet * __cmd_set_trace_variable(unsigned short, int);

#endif

