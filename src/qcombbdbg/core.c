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
 *  core.c: The debugger core functions.
 */

#include "rex.h"
#include "mmu.h"
#include "core.h"
#include "trace.h"
#include "relocator.h"

int initialized = 0;
breakpoint * bps = 0;
task_list tlist;
rex_heap dbg_heap;
rex_task *diag_task;

extern trace_engine tengine;

/* 
 * Dummy entry point. Used by GDB to store temporary things like:
 *  - copy instructions in displaced stepping (not implemented for thumb)
 *  - return bkpt in function calls
 */
char __scratch_buffer[128];

#define DBG_HEAP_BASE_ADDR 0x1e00000
#define DBG_HEAP_SIZE 0x100000

#define CHECK_INITIALIZED \
  if (!initialized) return 0;

#define foreach_breakpoint(var) for ( var = bps; var != 0; var = var->next )

/*
 *  Initialize the debugger heap.
 */
void create_dbg_heap(void * base, int size)
{
  heap_create(&dbg_heap, base, size, 0);
}

/*
 *  Memory allocation in the debugger heap.
 */
void * malloc(int size)
{
  return heap_malloc(&dbg_heap, size);
}

/*
 *  Memory free in the debugger heap.
 */
void free(void * chunk)
{
  return heap_free(&dbg_heap, chunk);
}

/*
 *  Allocates a DIAG packet of the specified size.
 *  Automatically freed when processed by the task.
 */
void * alloc_packet(int size)
{
  return diag_alloc_packet(DBG_CMD, size);
}

/* 
 * Allocates a new response packet from the diag task heap.
 * Argument is size of the packet, not counting first two mandatory header bytes (type and error_code).
 */
response_packet * alloc_response_packet(int data_size)
{
  response_packet * response;

  response = alloc_packet(2 + data_size);
  if ( response )
  {
    response->type = PACKET_RESPONSE;
    response->error_code = 0;
  }

  return response;
}

/* 
 *  Allocates a new event packet from the diag task heap.
 */
event_packet * alloc_event_packet(void)
{
  event_packet * event;

  event = alloc_packet(sizeof(event_packet));
  if ( event )
    event->type = PACKET_EVENT;

  return event;
}

/*
 *  Enumerates the list of tasks and assigns each of them a unique identifier.
 */
void create_tasks_mapping(void)
{
  rex_task * task;
  int num_tasks, id;

  num_tasks = 0;
  task = rex_self();

  NO_INTERRUPTS(

    /* Get to the head of the task list */
    while ( task->prev_task )
      task = task->prev_task;

    while ( task->next_task ) 
    {
      ++num_tasks;
      task = task->next_task;
    }

    tlist.num_tasks = num_tasks;
    tlist.tasks = malloc(num_tasks * sizeof(task_entry));

    /* 
     * Tasks list is ordered by priority and is subject to be modified
     *  during a scheduling event. We disable interrupts for the time of associating
     *  each task control structure with a unique task id.
     *
     *  Task with least priority should always be the idle task, we assign it here id 1.
     */
    for ( id = 1; id <= num_tasks; ++id, task = task->prev_task )
    {
      tlist.tasks[id - 1].task = task;
      tlist.tasks[id - 1].state = TASK_STATE_ALIVE;
    }
  
  );
}

/*
 *  Retrieves a task structure from its identifier.
 */
rex_task * get_task_from_id(task_id tid)
{
  if ( tid <= 0 || tid > tlist.num_tasks )
    return 0;

  return tlist.tasks[tid - 1].task;
}

/*
 *  Retrieves the currently executing task id.
 */
task_id get_current_task_id(void)
{
  rex_task * current;
  int tid;

  current = rex_self();
  for ( tid = 1; tid <= tlist.num_tasks; ++tid )
    if ( tlist.tasks[tid - 1].task == current )
      return tid;

  return 0;
}

/*
 *  Sets the task state for the debugger to keep track of it.
 *  Do not actually modify the task executing state.
 */
void set_task_state(task_id tid, int state)
{
  if ( tid > 0 && tid <= tlist.num_tasks )
    tlist.tasks[tid - 1].state = state;
}

/*
 *  Retrieves the task state.
 */
int get_task_state(task_id tid)
{
  if ( tid > 0 && tid <= tlist.num_tasks )
    return tlist.tasks[tid - 1].state;

  return TASK_STATE_UNKNOWN;
}

/*
 *  Get the breakpoint put at a given address.
 */
breakpoint * get_breakpoint_at_address(void * addr)
{
  breakpoint * bp;
  
  foreach_breakpoint(bp)
  {
    if ( bp->type == BREAKPOINT_NORMAL && bp->address == addr )
      return bp;
  }

  return 0;
}

/*
 *  Gets the tracepoint put at a given address.
 */
breakpoint * get_tracepoint_at_address(void * addr)
{
  breakpoint * bp;
  
  foreach_breakpoint(bp)
  {
    if ( bp->type == BREAKPOINT_TRACE && bp->address == addr )
      return bp;
  }

  return 0;
}

/*
 *  Emits an asynchronous debug event to the debugger client.
 *  pkt argument must be allocated on the debugger heap and is freed automatically upon return.
 */
void send_event_packet(event_packet * pkt)
{
  event_packet * packet;

  packet = alloc_event_packet();
  if ( pkt )
  {
    __memcpy(&packet->tid, &pkt->tid, sizeof(event_packet) - 1);
    diag_queue_response_packet(packet);
  }

  free(pkt);
}

/*
 *  Callback routine handling all break events.
 */
void __attribute__((naked)) dbg_break_handler(int event, void * address)
{
  event_packet * packet;
  task_id current_tid;
  int saved_sigs;
  rex_task * self;
  saved_context * saved_ctx;

  asm("push {lr}");

  if ( event == EVENT_BREAKPOINT && !get_breakpoint_at_address(address) )
    event = EVENT_MEMORY_FAULT;

  stack -= sizeof(int); // $sp = $sp - 4
  *(int *)stack = event; // store this one to help gcc

  current_tid = get_current_task_id();
  set_task_state(current_tid, TASK_STATE_HALTED);
  
  /* 
   * The diagnostic task code checks whether it is actually executing in the diag task context.
   * We instruct the diag task to execute send_event_packet as a DPC.
   */
  packet = malloc(sizeof(event_packet));
  if ( packet )
  {
    packet->tid = current_tid;
    packet->event = event;

    switch ( event ) 
    {
      case EVENT_STOP:
        saved_ctx = (saved_context *)&stack[8 + REX_EXECUTE_APC_STACK_SIZE];
        break;

      default:
        saved_ctx = (saved_context *)&stack[8];
        break;
    }
      
    tlist.tasks[current_tid - 1].ctx = saved_ctx; /* For future access to task registers */
    tlist.tasks[current_tid - 1].saved_sp = (int)(saved_ctx + 1);
    dbg_get_task_registers(current_tid, &packet->ctx);
     
    rex_queue_dpc((rex_apc_routine)&send_event_packet, diag_task, packet);
  }

  self = rex_self();

  /*
   *  Those few next lines are important and deserve some explanation.
   *  We can be executing here in interrupt or APC context.
   *  Consequently, the current task might be waiting for some signals.
   *  As we do not want them to awake us, we must disable them and restore them later.
   *
   *  Also, the task will be scheduled even in a waiting state if it has pending APCs.
   *  Especially if we ordered the task to halt, we are here executing in APC context, so the task
   *  cannot just be put in wait state directly. 
   *
   *  TASK_DISABLE() will set the task as non-schedulable for this reason.
   */
  saved_sigs = self->wait_signals;
  self->wait_signals = 0;
  TASK_DISABLE(self);

  rex_wait(SIGNAL_DEBUG);
 
  /* Remove the debug signal */
  rex_clear_task_signals(self, SIGNAL_DEBUG);

  /* Handle the case where pending signals have been set while the task was halted */
  if ( saved_sigs & self->active_signals )
    self->wait_signals = 0;
  else
    self->wait_signals = saved_sigs;
  
  set_task_state(current_tid, TASK_STATE_ALIVE);

  /* Load return address */
  asm(
    "ldr r6, [sp, #4]\n"
    "mov r8, r6\n"
  );

  /* 
   * $sp might have been modified while the task was halted 
   * We need to adjust it so that we return properly.
   */
  if ( (int)(saved_ctx + 1) != tlist.tasks[current_tid - 1].saved_sp )
    switch ( *(int *)stack ) /* event */
    {
      case EVENT_STOP:
        /* 
         * We have to account for the return to rex_execute_apc().
         * Duplicate the stack frame {r3-r7, lr}
         */
        __memmove(
          (char *)tlist.tasks[current_tid - 1].saved_sp - REX_EXECUTE_APC_STACK_SIZE - sizeof(saved_context),
          (char *)saved_ctx - REX_EXECUTE_APC_STACK_SIZE, 
          REX_EXECUTE_APC_STACK_SIZE + sizeof(saved_context)
        );
        
        stack = (char *)tlist.tasks[current_tid - 1].saved_sp - REX_EXECUTE_APC_STACK_SIZE - sizeof(saved_context);

        break;
      
      default:
        __memmove(
          (char *)tlist.tasks[current_tid - 1].saved_sp - sizeof(saved_context),
          (char *)saved_ctx,
          sizeof(saved_context)
        );

        stack = (char *)tlist.tasks[current_tid - 1].saved_sp - sizeof(saved_context);

        break;
    }
  else
    stack += 8; // $sp unmodified, $sp = $sp + 8

  /* Return to context */
  asm("bx r8");
}

/*
 *  Instruct a given task to stop execution.
 */
int dbg_stop_task(task_id tid)
{
  rex_task * task;
  event_packet * event;

  task = get_task_from_id(tid);
  if ( !task )
    return ERROR_TASK_NOT_FOUND;

  if ( get_task_state(tid) != TASK_STATE_ALIVE )
    return ERROR_INVALID_TASK_STATE;

  /*
   * APCs do not work against the IDLE task.
   * It is not a good idea to stop it anyway, just fake it.
   */
  if ( tid == TASK_IDLE )
  {
    set_task_state(tid, TASK_STATE_HALTED);
    
    tlist.tasks[tid - 1].ctx = tlist.tasks[tid - 1].task->stack_ptr;
    tlist.tasks[tid - 1].saved_sp = (int)(tlist.tasks[tid - 1].ctx + 1);

    event = alloc_event_packet();
    event->tid = tid;
    event->event = EVENT_STOP;
    dbg_get_task_registers(tid, &event->ctx);
    
    diag_queue_response_packet(event);
  }
  else
    rex_queue_dpc((rex_apc_routine)&dbg_break_handler, task, EVENT_STOP);
  
  return 0;
}

/*
 *  Resumes task execution.
 */
int dbg_resume_task(task_id tid)
{
  rex_task * task;

  task = get_task_from_id(tid);
  if ( !task )
    return ERROR_TASK_NOT_FOUND;

  if ( get_task_state(tid) != TASK_STATE_HALTED )
    return ERROR_INVALID_TASK_STATE;

  if ( tid == TASK_IDLE )
  {
    /* Fake resume of IDLE */
    set_task_state(tid, TASK_STATE_ALIVE); 
  }
  else
  {
    TASK_ENABLE(task);
    rex_set_task_signals(task, SIGNAL_DEBUG);
  }

  return 0;
}

/*
 *  Resumes any halted task.
 *  Used when detaching the debugger.
 */
void dbg_resume_all_tasks(void)
{
  int tid;

  for ( tid = 1; tid <= tlist.num_tasks; ++tid )
    dbg_resume_task(tid);
}

/*
 *  Gets the registers of a halted task.
 */
int dbg_get_task_registers(task_id tid, context * ctx)
{
  saved_context * saved_ctx;
  int saved_sp;

  if ( !get_task_from_id(tid) ) 
    return ERROR_TASK_NOT_FOUND;

  if ( get_task_state(tid) != TASK_STATE_HALTED )
    return ERROR_INVALID_TASK_STATE;

  saved_ctx = tlist.tasks[tid - 1].ctx;
  saved_sp = tlist.tasks[tid - 1].saved_sp;

  __memcpy(&ctx->saved_ctx, saved_ctx, sizeof(saved_context));
  ctx->sp = saved_sp;

  return 0;
}

/*
 *  Modifies the registers of a halted task.
 */
int dbg_set_task_registers(task_id tid, context * ctx)
{
  rex_task * task;

  task = get_task_from_id(tid);
  if ( !task )
    return ERROR_TASK_NOT_FOUND;

  if ( get_task_state(tid) != TASK_STATE_HALTED )
    return ERROR_INVALID_TASK_STATE;

  __memcpy(tlist.tasks[tid - 1].ctx, &ctx->saved_ctx, sizeof(saved_context));
  tlist.tasks[tid - 1].saved_sp = ctx->sp;

  return 0;
}

/*
 *  Reads instruction at address.
 */
int dbg_read_insn(void * addr, char kind, int * insn)
{
  switch ( kind )
  {
    case ARM_CODE:
      if ( (int)addr % 4 )
        return ERROR_BAD_ADDRESS_ALIGNMENT;

      if ( !mmu_probe_read(addr, 4) )
        return ERROR_INVALID_MEMORY_ACCESS;

      *insn = *(arm_insn *)addr;
      break;

    case THUMB_CODE:
      if ( (int)addr % 2 )
        return ERROR_BAD_ADDRESS_ALIGNMENT;

      if ( !mmu_probe_read(addr, 2) )
        return ERROR_INVALID_MEMORY_ACCESS;

      *insn = *(thumb_insn *)addr;
      break;

    default:
      return ERROR_INVALID_CPU_MODE;
  }

  return 0;
}

/*
 *  Rewrites a single instruction in memory.
 *  Temporarily sets the destination page as writable if necessary.
 */
void dbg_write_insn(void * addr, char kind, int insn)
{
  int prot;

  NO_INTERRUPTS(
    /* Enforces write access on the page */
    prot = mmu_set_access_protection(addr, MMU_PROT_READ_WRITE);

    if ( kind == ARM_CODE )
      *(arm_insn *)addr = insn;
    else
      *(thumb_insn *)addr = insn;
    
    /* Restore page access */
    mmu_set_access_protection(addr, prot);
    
    /* Invalidate the instruction cache line */
    mmu_invalidate_insn_cache_line(addr);
  );
}

/*
 *  Inserts a BKPT instruction at a specified address.
 */
void dbg_insert_bkpt_insn(void * addr, char kind)
{
  int prot;

  if ( kind == ARM_CODE )
    dbg_write_insn(addr, kind, ARM_BKPT);
  else
    dbg_write_insn(addr, kind, THUMB_BKPT);
}

/*
 *  Links the breakpoint structure into the breakpoint list.
 */
void dbg_register_breakpoint(breakpoint * bp)
{
  breakpoint * last;

  last = bps;
  while ( last && last->next )
    last = last->next;

  if ( !last )
  {
    bps = bp;
    bp->prev = 0;
  }
  else
  {
    last->next = bp;
    bp->prev = last;
  }
}

/*
 *  Unlinks the breakpoint from the breakpoint list.
 *  Frees the breakpoint structure.
 */
void dbg_unregister_breakpoint(breakpoint * bp)
{
  if ( bp->prev )
    bp->prev->next = bp->next;

  if ( bp->next )
    bp->next->prev = bp->prev;

  if ( !bp->prev && !bp->next )
    bps = 0;

  free(bp);
}

/*
 *  Inserts a new memory breakpoint at the specified address.
 */
int dbg_insert_breakpoint(void * addr, char kind)
{
  breakpoint * bp;
  int insn, ret;

  if ( get_breakpoint_at_address(addr) )
    return ERROR_BREAKPOINT_ALREADY_EXISTS; 

  /* Saves the original instruction at the specified address */
  ret = dbg_read_insn(addr, kind, &insn);
  if ( ret < 0 )
    return ret;

  /* Create the breakpoint structure */
  bp = malloc(sizeof(breakpoint));
  bp->type = BREAKPOINT_NORMAL;
  bp->kind = kind;
  bp->address = addr;
  bp->original_insn = insn;
  bp->next = 0;

  /* Insert it in the breakpoint list */
  dbg_register_breakpoint(bp);

  /* Insert the breakpoint in memory */
  dbg_insert_bkpt_insn(addr, kind);

  return 0;
}

/*
 *  Removes a breakpoint.
 */
int dbg_remove_breakpoint(void * addr)
{
  breakpoint * bp;
  int prot;

  bp = get_breakpoint_at_address(addr);
  if ( !bp )
    return ERROR_NO_BREAKPOINT;

  /* Restore the original instruction */
  dbg_write_insn(addr, bp->kind, bp->original_insn);

  /* Remove it from the breakpoint list */
  dbg_unregister_breakpoint(bp);

  return 0;
}

/*
 * Cleans all defined breakpoints.
 */
void dbg_remove_all_breakpoints(void)
{
  breakpoint * bp;
  breakpoint * current;
  int prot;

  bp = bps;
  while ( bp )
  {
    current = bp;

    /* Restore the original instruction */
    dbg_write_insn(current->address, current->kind, current->original_insn);

    bp = bp->next;
    free(current);
  }

  bps = 0;
}

/*
 *  Reads a piece of memory.
 *  Returned data hides defined memory breakpoints.
 */
int dbg_read_memory(void * start, void * out,  unsigned int size)
{
  breakpoint * bp;
  int bp_size;
  void * bp_end, * data_end;

  if ( mmu_probe_read(start, size) )
    __memcpy(out, start, size);
  else
    return ERROR_INVALID_MEMORY_ACCESS;
  
  data_end = start + size - 1;

  foreach_breakpoint(bp)
  {
    bp_size = (bp->kind == ARM_CODE) ? 4 : 2;
    bp_end = bp->address + bp_size - 1;
    
    /* Last breakpoint byte in range */
    if ( bp_end >= start && bp_end <= data_end ) 
    {
      /* Full breakpoint in range */
      if ( bp->address >= start ) 
        __memcpy(bp->address - start + out, &bp->original_insn, bp_size);
      else /* Missing first breakpoint bytes */
        __memcpy(out, (void *)&bp->original_insn + (start - bp->address), bp_size - (start - bp->address));
    }
    
    /* First breakpoint bytes in range, missing last bytes*/
    else if ( bp->address >= start && bp->address <= data_end ) 
      __memcpy(bp->address - start + out, (void *)&bp->original_insn, bp_size - (bp_end - data_end));
  }

  return 0;
}

/*************************
******** COMMANDS ********
*************************/

#ifdef DEBUG

/*
 *  Echo command (debug purpose only).
 */
response_packet * __cmd_echo(request_packet * pkt, int size)
{
  response_packet * response;

  response = alloc_packet(size); 
  if ( response )
    __memcpy(response, pkt, size);

  return response;
}

/*
 *  Calls external function and returns result (debug purpose only).
 */
response_packet * __cmd_call_routine(long long int (* f)(int, int, int, int), int arg1, int arg2, int arg3, int arg4)
{
  response_packet * response;
  long long int result;

  result = f(arg1, arg2, arg3, arg4);
  
  response = alloc_response_packet(sizeof(long long int));
  response->call.result = result;

  return response;
}

/*
 *  Triggers a specific exception (debug purpose only).
 */
void trigger_exception(int exception)
{
  switch ( exception )
  {
    case EXCEPTION_UNDEF_INSN: /* should report a SIGILL to gdb */
      asm(".hword 0xde00");
      break;

    case EXCEPTION_PREFETCH_ABORT: /* should report a SIGSEGV to gdb */
      ((void (*)(void))0xd0000000)();
      break;

    case EXCEPTION_DATA_ABORT: /* should report a SIGSEGV to gdb */
      *(char *)0xd0000000 |= 1;
      break;

    default:
    case EXCEPTION_SOFTWARE: /* SIGSYS ? */
      asm("swi #0");
      break;
  }
}

/* 
 * Triggers a specific exception in a given task context (debug purpose only).
 */
response_packet * __cmd_trigger_exception(task_id tid, int exception)
{
  response_packet * response;
  rex_task * target;

  response = alloc_response_packet(0);
  target = get_task_from_id(tid);
  if ( !target )
    response->error_code = ERROR_TASK_NOT_FOUND;
  else
    rex_queue_dpc((rex_apc_routine)trigger_exception, target, (void *)exception);

  return response;
}

/*
 *  Triggers a stack overflow (debug purpose only).
 */
void trigger_stack_overflow(char * payload)
{
  char buf[8];

  __strcpy(buf, payload);
}

/*
 *  Triggers a stack overflow in a given task context (debug purpose only).
 */
response_packet * __cmd_trigger_stack_overflow(task_id tid, char * str, int size)
{
  response_packet * response;
  rex_task * target;
  char ** payload;

  payload = malloc(size + 1);
  __memcpy(payload, str, size + 1);

  response = alloc_response_packet(0);
  target = get_task_from_id(tid);
  if ( !target )
    response->error_code = ERROR_TASK_NOT_FOUND;
  else
    rex_queue_dpc((rex_apc_routine)trigger_stack_overflow, target, payload);
  
  return response;
}

response_packet * __cmd_send_signal(task_id tid, int signals)
{
  response_packet * response;
  rex_task * task;

  response = alloc_response_packet(0);
 
  task = get_task_from_id(tid);
  if ( !task )
    response->error_code = ERROR_TASK_NOT_FOUND;
  else
    rex_set_task_signals(task, signals);

  return response;
}

response_packet * __cmd_reloc_insn(void * src, void * dst)
{
  response_packet * response;
  int output_size, ret;

  response = alloc_response_packet(4);
  ret = relocate_thumb_insn(src, dst, &output_size);

  if ( ret )
    response->error_code = ret;
  else
    response->size = output_size;

  return response;
}

#endif /* DEBUG commands */

/*
 *  Initializes the debugger state.
 *    - Creates a separate heap for the debugger
 *    - Retrieves the list of tasks
 *    - Installs interrupt handlers
 */
response_packet * __cmd_attach(void)
{
  response_packet * response;

  if ( !initialized )
  {
    diag_task = rex_self();
    create_dbg_heap((void *)DBG_HEAP_BASE_ADDR, DBG_HEAP_SIZE);
    create_tasks_mapping();
    mmu_set_access_protection(0, MMU_PROT_READ_WRITE);
    *(int *)0 = 0;
    install_interrupt_handlers();
    __memset(__scratch_buffer, 0, sizeof(__scratch_buffer));

    trace_engine_init();

    initialized = 1;
  }

  response = alloc_response_packet(0);
  return response;
}

/*
 *  Detaches from the debugger.
 *    - Removes all defined breakpoints
 *    - Restores the interrupt vector table
 *    - Resumes all stopped tasks.
 */
response_packet * __cmd_detach(void)
{
  response_packet * response;

  if ( initialized )
  {
    dbg_remove_all_breakpoints();
    restore_interrupt_handlers();
    dbg_resume_all_tasks();

    initialized = 0;
  }

  response = alloc_response_packet(0);
  return response;
}

response_packet * __cmd_get_num_tasks(void)
{
  response_packet * response;
  CHECK_INITIALIZED;

  response = alloc_response_packet(sizeof(int));
  response->num_tasks = tlist.num_tasks;

  return response;
}

response_packet * __cmd_get_task_info(task_id tid)
{
  rex_task * task;
  response_packet * response;
  CHECK_INITIALIZED;

  response = alloc_response_packet(TASK_NAME_SIZE + 8);
  task = get_task_from_id(tid);
  if ( task )
  {
    response->task_info.wait_signals = task->wait_signals;
    response->task_info.active_signals = task->active_signals;
    __memcpy(response->task_info.name, task->name, TASK_NAME_SIZE);
  }
  else
    response->error_code = ERROR_TASK_NOT_FOUND;

  return response;
}

response_packet * __cmd_get_task_state(task_id tid)
{
  response_packet * response;
  CHECK_INITIALIZED;

  response = alloc_response_packet(sizeof(int));

  if ( tid <= 0 || tid > tlist.num_tasks )
    response->error_code = ERROR_INVALID_TASK_STATE;
  else
    response->task_state = get_task_state(tid);

  return response;
}

response_packet * __cmd_stop_task(task_id tid)
{
  response_packet * response;
  CHECK_INITIALIZED;
  
  response = alloc_response_packet(0);
  response->error_code = dbg_stop_task(tid);

  return response;
}

response_packet * __cmd_resume_task(task_id tid)
{
  response_packet * response;
  CHECK_INITIALIZED;

  response = alloc_response_packet(0);
  response->error_code = dbg_resume_task(tid);

  return response;
}

response_packet * __cmd_read_memory(void * start, unsigned int size)
{
  response_packet * response;

  if ( size > DBG_MAX_PACKET_SIZE )
    size = DBG_MAX_PACKET_SIZE;

  response = alloc_response_packet(size);
  response->error_code = dbg_read_memory(start, &response->data, size);

  return response;
}

response_packet * __cmd_write_memory(void * dest, void * data, int size)
{
  response_packet * response;

  response = alloc_response_packet(0);

  if ( mmu_probe_write(dest, size) )
  {
    __memcpy(dest, data, size);
  }
  else
    response->error_code = ERROR_INVALID_MEMORY_ACCESS;

  return response;
}

response_packet * __cmd_read_registers(task_id tid)
{
  response_packet * response;
  CHECK_INITIALIZED;

  response = alloc_response_packet(sizeof(context));
  response->error_code = dbg_get_task_registers(tid, &response->ctx);

  return response;
}

response_packet * __cmd_write_registers(task_id tid, context * ctx)
{
  response_packet * response;
  CHECK_INITIALIZED;

  response = alloc_response_packet(0);
  response->error_code = dbg_set_task_registers(tid, ctx);

  return response;
}

response_packet * __cmd_insert_breakpoint(void * address, char kind)
{
  response_packet * response;

  response = alloc_response_packet(0);
  response->error_code = dbg_insert_breakpoint(address, kind);

  return response;
}

response_packet * __cmd_remove_breakpoint(void * address)
{
  response_packet * response;

  response = alloc_response_packet(0);
  response->error_code = dbg_remove_breakpoint(address);

  return response;
}

/**********************
* Tracepoint commands *
***********************/

response_packet * __cmd_trace_clear(void)
{
  response_packet * response;

  trace_buffer_clear();
  /* TODO: Remove tracepoints */

  response = alloc_response_packet(0);
  return response;
}

response_packet * __cmd_trace_status(void)
{
  response_packet * response;

  response = alloc_response_packet(sizeof(response->tstatus));
  response->tstatus.status = tengine.status;
  response->tstatus.circular = tengine.tbuffer.circular;
  response->tstatus.tframes = tengine.tbuffer.frame_count;
  response->tstatus.tcreated = tengine.tbuffer.frame_created;
  response->tstatus.tsize = tengine.tbuffer.size;
  response->tstatus.tfree = tengine.tbuffer.size - tengine.tbuffer.used;

  return response;
}

response_packet * __cmd_get_trace_variable(unsigned short id)
{
  response_packet * response;
  trace_variable * tvar;

  response = alloc_response_packet(sizeof(int));

  tvar = trace_get_variable(id);
  if ( tvar )
    response->tvar_value = tvar->value;
  else
    response->error_code = ERROR_NO_TRACE_VARIABLE;


  return response;
}

response_packet * __cmd_set_trace_variable(unsigned short id, int value)
{
  response_packet * response;

  response = alloc_response_packet(0);
  trace_set_variable(id, value);

  return response;
}
