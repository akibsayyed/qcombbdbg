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
#include "interrupts.h"
#include "mmu.h"
#include "core.h"
#include "trace.h"
#include "relocator.h"


int initialized = 0;
breakpoint * bps = 0;
task_list tlist;
rex_heap dbg_heap;
rex_task *dbg_task;

extern trace_engine tengine;

/* 
 * Dummy entry point. Used by GDB to store temporary things like:
 *  - copy instructions in displaced stepping (not implemented for thumb)
 *  - return bkpt in debuggee calls
 */
char __scratch_buffer[128];

#define TASK_INFO(tid) tlist.tasks[tid - 1]

/*
 *  Returns the current stack pointer.
 */
static inline void * get_sp(void)
{
  void * sp;

  asm volatile(
    "mov %0, sp\n"
    : "=r" (sp)
  );
  return sp;
}

/*
 *  Sets the current stack pointer.
 */
static inline void set_sp(void * sp)
{
  asm volatile(
    "mov sp, %0\n"
    :: "r" (sp)
  );
}

static inline void * memmove_inline(void * dst, void * src, unsigned int size)
{
  int i;

  if ( dst < src )
    for ( i = 0; i < size; ++i )
      ((char *)dst)[i] = ((char *)src)[i];

  else if ( dst > src )
    for ( i = size - 1; i >= 0; --i )
      ((char *)dst)[i] = ((char *)src)[i];

  return dst;
}

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

  response = alloc_packet(__builtin_offsetof(response_packet, data) + data_size);
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

  WITHOUT_INTERRUPTS(

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
      TASK_INFO(id).task = task;
      TASK_INFO(id).state = TASK_STATE_ALIVE;
    }
  
  );
}

/*
 *  Frees task list memory.
 */
void remove_tasks_mapping(void)
{
  free(tlist.tasks);
  tlist.num_tasks = 0;
}

/*
 *  Retrieves a task structure from its identifier.
 */
rex_task * get_task_from_id(task_id tid)
{
  if ( tid <= 0 || tid > tlist.num_tasks )
    return 0;

  return TASK_INFO(tid).task;
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
    if ( TASK_INFO(tid).task == current )
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
    TASK_INFO(tid).state = state;
}

/*
 *  Retrieves the task state.
 */
int get_task_state(task_id tid)
{
  if ( tid > 0 && tid <= tlist.num_tasks )
    return TASK_INFO(tid).state;

  return TASK_STATE_UNKNOWN;
}

/*
 *  Check if a breakpoint or tracepoint has been defined at address.
 */
int has_breakpoint_at_address(void * addr)
{
  breakpoint * bp;

  foreach_breakpoint(bp) {
    if ( bp->address == addr )
      return 1;
  }

  return 0;
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

  saved_ctx = TASK_INFO(tid).ctx;
  saved_sp = TASK_INFO(tid).saved_sp;

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

  __memcpy(TASK_INFO(tid).ctx, &ctx->saved_ctx, sizeof(saved_context));
  TASK_INFO(tid).saved_sp = ctx->sp;

  return 0;
}

/*
 *  Reads a single instruction at address.
 */
int dbg_read_insn(void * addr, char kind, int * insn)
{
  switch ( kind )
  {
    case ARM_CODE:
      if ( (int)addr % sizeof(arm_insn) )
        return ERROR_BAD_ADDRESS_ALIGNMENT;

      if ( !mmu_probe_read(addr, sizeof(arm_insn)) )
        return ERROR_INVALID_MEMORY_ACCESS;

      *insn = *(arm_insn *)addr;
      break;

    case THUMB_CODE:
      if ( (int)addr % sizeof(thumb_insn) )
        return ERROR_BAD_ADDRESS_ALIGNMENT;

      if ( !mmu_probe_read(addr, sizeof(thumb_insn)) )
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
 *
 *  This function preserves instruction cache coherency.
 */
void dbg_write_insn(void * addr, char kind, int insn)
{
  int prot;

  WITHOUT_INTERRUPTS(
    /* Enforces write access on the page */
    prot = mmu_set_access_protection(addr, MMU_PROT_READ_WRITE);

    if ( kind == ARM_CODE )
      *(arm_insn *)addr = insn;
    else
      *(thumb_insn *)addr = insn;
    
    /* Restore page access */
    mmu_set_access_protection(addr, prot);
    
    /* Clean the data cache, invalidate the instruction cache line */
    mmu_sync_insn_cache_at(addr);
  );
}

/*
 *  Inserts a BKPT instruction at a specified address.
 */
void dbg_insert_bkpt_insn(void * addr, char kind)
{
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

  if ( bp->relocated_address )
    free(bp->relocated_address);

  free(bp);
}

/*
 *  Enables a tracepoint.
 *  Inserts the breakpoint instruction if the tracepoint was disabled.
 */
void dbg_enable_tracepoint(breakpoint * tp)
{
  if ( !tp->trace.enabled )
  {
    tp->trace.enabled = 1;
    dbg_insert_bkpt_insn(tp->address, tp->kind);
  }
}

/*
 *  Disables a tracepoint.
 *  Restores the original instruction if the tracepoint was enabled.
 */
void dbg_disable_tracepoint(breakpoint * tp)
{
  if ( tp->trace.enabled )
  {
    dbg_write_insn(tp->address, tp->kind, tp->original_insn);
    tp->trace.enabled = 0;
  }
}

/*
 *  Disables all defined tracepoints.
 */
void dbg_disable_all_tracepoints(void)
{
  breakpoint * tp;

  foreach_breakpoint(tp)
    if ( tp->type == BREAKPOINT_TRACE )
      dbg_disable_tracepoint(tp);
}

/*
 *  Enables all defined tracepoints.
 */
void dbg_enable_all_tracepoints(void)
{
  breakpoint * tp;

  foreach_breakpoint(tp)
    if ( tp->type == BREAKPOINT_TRACE )
      dbg_enable_tracepoint(tp);
}

/*
 *  Inserts a new memory breakpoint at the specified address.
 */
int dbg_insert_breakpoint(void * addr, char kind)
{
  breakpoint * bp;
  int insn, ret;

  if ( has_breakpoint_at_address(addr) )
    return ERROR_BREAKPOINT_ALREADY_EXISTS; 

  /* Saves the original instruction at the specified address */
  ret = dbg_read_insn(addr, kind, &insn);
  if ( ret < 0 )
    return ret;

  /* Create the breakpoint structure */
  bp = malloc(sizeof(breakpoint));
  if ( !bp )
    return ERROR_NO_MEMORY_AVAILABLE;

  bp->type = BREAKPOINT_NORMAL;
  bp->kind = kind;
  bp->address = addr;
  bp->relocated_address = 0;
  bp->original_insn = insn;
  bp->next = 0;

  /* Insert it in the breakpoint list */
  dbg_register_breakpoint(bp);

  /* Insert the breakpoint in memory */
  dbg_insert_bkpt_insn(addr, kind);

  return 0;
}

/*
 *  Add an action to a tracepoint.
 */
void dbg_tracepoint_add_action(breakpoint * tp, trace_action * action)
{
  trace_action * last;

  action->next = 0;

  if ( tp->trace.actions )
  {
    last = tp->trace.actions;
    while ( last->next ) last = last->next;
    last->next = action;
  }
  else
    tp->trace.actions = action;
}

/*
 *  Inserts a new tracepoint in memory.
 *  Relocate the target instruction. The tracepoint is disabled by default.
 */
int dbg_insert_tracepoint(void * addr, char kind, unsigned int pass, void ** relocated_addr)
{
  breakpoint * tp;
  int insn, ret, output_size;

  /* No support for ARM tracepoints yet */
  if ( kind != THUMB_CODE )
    return ERROR_INVALID_CPU_MODE;

  if ( has_breakpoint_at_address(addr) )
    return ERROR_BREAKPOINT_ALREADY_EXISTS;

  ret = dbg_read_insn(addr, kind, &insn);
  if ( ret < 0 )
    return ret;

  /* Create the tracepoint structure */
  tp = malloc(sizeof(breakpoint));
  if ( !tp )
    return ERROR_NO_MEMORY_AVAILABLE;

  tp->type = BREAKPOINT_TRACE;
  tp->kind = kind;
  tp->address = addr;

  /* Relocate the target instruction */
  tp->relocated_address = malloc(RELOC_INSN_DEFAULT_BUFFER_SIZE);
  if ( !tp->relocated_address )
  {
    free(tp);
    return ERROR_NO_MEMORY_AVAILABLE;
  }
  if ( relocate_thumb_insn(addr, tp->relocated_address, &output_size) < 0 )
  {
    free(tp->relocated_address);
    free(tp);
    return ERROR_RELOCATION_FAILURE;
  }
  *relocated_addr = tp->relocated_address;

  tp->original_insn = insn;
  tp->trace.enabled = 0;
  tp->trace.processing = 0;
  tp->trace.hits = 0;
  tp->trace.pass = pass;
  tp->trace.actions = 0;
  tp->trace.condition.code = 0;
  tp->trace.condition.size = 0;
  tp->next = 0;

  /* Insert the tracepoint in the breakpoint list */
  dbg_register_breakpoint(tp);

  return 0;
}

/* 
 * Removes a tracepoint 
 */
int dbg_remove_tracepoint(void * addr)
{
  breakpoint * tp;
  trace_action * action, * next;

  tp = get_tracepoint_at_address(addr);
  if ( !tp )
    return ERROR_NO_BREAKPOINT;

  /* Restore the original instruction */
  dbg_disable_tracepoint(tp);

  /* Free tracepoint actions */
  action = tp->trace.actions;
  while ( action )
  {
    next = action->next;
    free(action);
    action = next;
  }

  /* Free tracepoint condition */
  if ( tp->trace.condition.code )
    free(tp->trace.condition.code);

  /* Destroy the tracepoint */
  dbg_unregister_breakpoint(tp);

  return 0;
}

/*
 *  Removes a breakpoint.
 */
int dbg_remove_breakpoint(void * addr)
{
  breakpoint * bp;

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
  trace_action * action, * next;

  bp = bps;
  while ( bp )
  {
    current = bp;

    /* Restore the original instruction */
    dbg_write_insn(current->address, current->kind, current->original_insn);

    /* Free the relocation buffer */
    if ( bp->relocated_address )
      free(bp->relocated_address);

    /* Free tracepoint structures */
    if ( bp->type == BREAKPOINT_TRACE )
    {
      action = bp->trace.actions;
      while ( action )
      {
        next = action->next;
        free(action);
        action = next;
      }

      if ( bp->trace.condition.code )
        free(bp->trace.condition.code);
    }

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
    bp_size = (bp->kind == ARM_CODE) ? sizeof(arm_insn) : sizeof(thumb_insn);
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

/*
 *  Execute a tracepoint action.
 */
int dbg_tracepoint_do_action(trace_action * action, trace_frame * tframe, saved_context * ctx)
{
  int ret;
  trace_vm_state * state;

  ret = 0;
  state = 0;
  switch ( action->type )
  {
    case TRACEPOINT_ACTION_COLLECT_REGS:
      ret = trace_buffer_trace_registers(tframe, ctx);
      break;

    case TRACEPOINT_ACTION_EXEC_GDB:
      state = trace_vm_state_create(ctx, tframe);
      if ( !state )
      {
        trace_stop(ret = TRACE_STOP_UNKNOWN);
        break;
      }

      ret = trace_vm_exec(state, action->exec.code, action->exec.size);
      break;

    default:
      trace_stop(ret = TRACE_STOP_UNKNOWN);
      break;
  }

  if ( state )
    trace_vm_state_destroy(state);

  return ret;
}

/*
 *  Evaluate a tracepoint condition.
 *  Returns 0 if the condition is met.
 */
int dbg_tracepoint_check_condition(breakpoint * tp, saved_context * ctx)
{
  int ret;
  trace_vm_state * state;

  ret = 0;
  state = 0;
  switch ( tp->trace.condition.type )
  {
    case TRACEPOINT_ACTION_EXEC_GDB:
      state = trace_vm_state_create(ctx, 0);
      if ( !state )
      {
        trace_stop(TRACE_STOP_UNKNOWN);
        break;
      }

      if ( trace_vm_eval(state, tp->trace.condition.code, tp->trace.condition.size, &ret) )
        trace_stop(TRACE_STOP_UNKNOWN);
      break;

    default:
      trace_stop(TRACE_STOP_UNKNOWN);
      break;
  }

  if ( state )
    trace_vm_state_destroy(state);

  return ret;
}

/*
 *  Checks whether any tracepoint is still enabled.
 */
int dbg_any_tracepoint_alive(void)
{
  breakpoint * tp;
  int alive;
  
  alive = 0;
  foreach_breakpoint(tp)
    if ( tp->type == BREAKPOINT_TRACE && tp->trace.enabled )
      alive = 1;

  return alive;
}

/*
 *  Callback routine handling trace events.
 */
void __attribute__((noinline)) dbg_trace_handler(breakpoint * tp, saved_context * ctx)
{
  register void (*relocated_addr)(void);
  trace_action * action;
  trace_frame * tframe;

  /* 
   * Ignore trace calls from the debugger itself ! 
   * TODO: irq-safe tracepoints ?
   */
  if ( rex_self() != dbg_task && !cpu_is_in_irq_mode() && xchg_b(&tp->trace.processing, 1) == 0 )
  {
    /* Check tracepoint condition */
    if ( !tp->trace.condition.code || dbg_tracepoint_check_condition(tp, ctx) )
    {
      /* Increase hits counter */
      tp->trace.hits++;
      if ( tp->trace.pass != 0 && tp->trace.hits >= tp->trace.pass )
      {
        dbg_disable_tracepoint(tp);
        if ( tengine.status == 0 && !dbg_any_tracepoint_alive() )
          tengine.status = TRACE_STOP_NO_MORE_PASS;
      }

      tframe = trace_buffer_create_frame(tp);

      /* Execute tracepoint actions */
      foreach_tracepoint_action(tp, action)
        if ( dbg_tracepoint_do_action(action, tframe, ctx) )
          break;
    }

    tp->trace.processing = 0;
  }
  

  relocated_addr = tp->relocated_address;
  if ( tp->kind == THUMB_CODE )
    relocated_addr += 1;
  set_sp(ctx); /* restore stack pointer */
  return_at_relocated_insn(relocated_addr); /* no return */
}

/*
 *  Notifies a debug event to the debugger client.
 */
void dbg_notify_event(task_id tid, int event)
{
  event_packet * packet;

  /* 
   * The diagnostic task code checks whether it is actually executing in the diag task context.
   * We instruct the diag task to execute send_event_packet as a DPC.
   */
  packet = malloc(sizeof(event_packet));
  if ( packet )
  {
    packet->tid = tid;
    packet->event = event;
    dbg_get_task_registers(tid, &packet->ctx);
     
    rex_queue_dpc((rex_apc_routine)&send_event_packet, dbg_task, packet);
  }
}

/*
 *  Invokes the REX kernel API to put the current task in a wait state.
 *  Task can be resumed by sending it the DEBUGGER_SIGNAL.
 */
void dbg_enter_wait_state()
{
  rex_task * self;
  int saved_sigs;

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
}

/*
 *  Interrupts the current task and notifies the debugger.
 */
void dbg_do_break(int event, saved_context * saved_ctx)
{
  task_id current_tid;

  current_tid = get_current_task_id();

  /* 
   * Save the pointer to the task context in the task structure,
   * for future access to task registers.
   */
  TASK_INFO(current_tid).ctx = saved_ctx;
  TASK_INFO(current_tid).saved_sp = (int)(saved_ctx + 1);

  set_task_state(current_tid, TASK_STATE_HALTED);

  /* Notify for task break */
  dbg_notify_event(current_tid, event);

  /* Put the current task in a wait state */
  dbg_enter_wait_state();
  
  set_task_state(current_tid, TASK_STATE_ALIVE);
}

/*
 *  Callback routine handling all break events.
 */
void dbg_break_handler(int event, saved_context * saved_ctx)
{
  task_id current_tid;
  breakpoint * bp;
  int saved_sp, sp_delta, frame_size;
  char * current_sp;

  /* Transfer control to tracepoint handler if we hit a tracepoint */
  if ( event == EVENT_BREAKPOINT && (bp = get_tracepoint_at_address((void *)saved_ctx->pc)) )
    return dbg_trace_handler(bp, saved_ctx);

  /* Handle the break event */
  else
  {
    current_sp = get_sp();

    /* A prefetch abort interrupt occurred */
    if ( event == EVENT_BREAKPOINT )
    {
      /* Check if a breakpoint has been defined at the exception address */
      bp = get_breakpoint_at_address((void *)saved_ctx->pc);
      if ( !bp )
        event = EVENT_MEMORY_FAULT;
    }

    /* Save the original stack pointer before breaking */
    saved_sp = (int)(saved_ctx + 1);

    /*
     *  Interrupts the current task.
     */
    WITH_INTERRUPTS(
      dbg_do_break(event, saved_ctx);
    );

    /* 
     * $sp might have been modified while the task was halted.
     * We need to adjust it so that we return properly.
     */
    current_tid = get_current_task_id();
    sp_delta = TASK_INFO(current_tid).saved_sp - saved_sp;
    if ( sp_delta )
    {
      frame_size = (char *) saved_sp - current_sp; /* Includes active stack frames + task context */
      memmove_inline(
        (char *) TASK_INFO(current_tid).saved_sp - frame_size,
        current_sp,
        frame_size
      );
      set_sp(current_sp + sp_delta);
    }
  }
}

/*
 *  Wrapper callback function when user forces a task interrupt.
 *  Transfers control to dbg_break_handler with pointer to saved task context.
 */
void __attribute__((naked)) dbg_interrupt_from_apc(void)
{
  asm(
    "add r1, sp, %[ctx_offset]\n"
    "mov r0, %[event]\n"
    "b dbg_break_handler\n"
    :: [event] "i" (EVENT_STOP), [ctx_offset] "i" (REX_EXECUTE_APC_STACK_SIZE)
  );
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
    
    TASK_INFO(tid).ctx = TASK_INFO(tid).task->stack_ptr;
    TASK_INFO(tid).saved_sp = (int)(TASK_INFO(tid).ctx + 1);

    event = alloc_event_packet();
    event->tid = tid;
    event->event = EVENT_STOP;
    dbg_get_task_registers(tid, &event->ctx);
    
    diag_queue_response_packet(event);
  }
  else
    rex_queue_dpc((rex_apc_routine)&dbg_interrupt_from_apc, task, 0);
  
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
  
  response = alloc_response_packet(sizeof(response->result));
  response->result = result;

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

  response = alloc_response_packet(sizeof(response->size));
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
    dbg_task = rex_self();
    create_dbg_heap((void *)DBG_HEAP_BASE_ADDR, DBG_HEAP_SIZE);
    create_tasks_mapping();
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
 *    - Free allocated memory.
 */
response_packet * __cmd_detach(void)
{
  response_packet * response;

  if ( initialized )
  {
    dbg_remove_all_breakpoints();
    restore_interrupt_handlers();
    dbg_resume_all_tasks();
    remove_tasks_mapping();
    trace_buffer_clear();

    initialized = 0;
  }

  response = alloc_response_packet(0);
  return response;
}

response_packet * __cmd_get_num_tasks(void)
{
  response_packet * response;

  response = alloc_response_packet(sizeof(response->num_tasks));
  response->num_tasks = tlist.num_tasks;

  return response;
}

response_packet * __cmd_get_task_info(task_id tid)
{
  rex_task * task;
  response_packet * response;

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

  response = alloc_response_packet(sizeof(response->task_state));

  if ( tid <= 0 || tid > tlist.num_tasks )
    response->error_code = ERROR_INVALID_TASK_STATE;
  else
    response->task_state = get_task_state(tid);

  return response;
}

response_packet * __cmd_stop_task(task_id tid)
{
  response_packet * response;
  
  response = alloc_response_packet(0);
  response->error_code = dbg_stop_task(tid);

  return response;
}

response_packet * __cmd_resume_task(task_id tid)
{
  response_packet * response;

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

  response = alloc_response_packet(sizeof(response->ctx));
  response->error_code = dbg_get_task_registers(tid, &response->ctx);

  return response;
}

response_packet * __cmd_write_registers(task_id tid, context * ctx)
{
  response_packet * response;

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
  breakpoint *tp, * next;

  trace_buffer_clear();
  tp = bps;
  while ( tp )
  {
    next = tp->next;
    if ( tp->type == BREAKPOINT_TRACE )
    {
      dbg_disable_tracepoint(tp);
      dbg_unregister_breakpoint(tp);
    }

    tp = next;
  }

  response = alloc_response_packet(0);
  return response;
}

response_packet * __cmd_trace_start(void)
{
  response_packet * response;

  response = alloc_response_packet(0);
  if ( tengine.status == 0 )
    response->error_code = ERROR_TRACE_ALREADY_RUNNING;
  else
    trace_start();

  return response;
}

response_packet * __cmd_trace_stop(void)
{
  response_packet * response;

  response = alloc_response_packet(0);
  if ( tengine.status != 0 )
    response->error_code = ERROR_TRACE_NOT_RUNNING;
  else
    trace_stop(TRACE_STOP_USER);

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

  response = alloc_response_packet(sizeof(response->tvar_value));

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

response_packet * __cmd_insert_tracepoint(void * address, char kind, unsigned int pass)
{
  response_packet * response;
  void * reloc;

  response = alloc_response_packet(sizeof(response->num_tasks));
  response->error_code = dbg_insert_tracepoint(address, kind, pass, &reloc);
  response->num_tasks = (int)reloc;

  return response;
}

response_packet * __cmd_remove_tracepoint(void * address)
{
  response_packet * response;

  response = alloc_response_packet(0);
  response->error_code = dbg_remove_tracepoint(address);

  return response;
}

response_packet * __cmd_enable_tracepoint(void * address)
{
  response_packet * response;
  breakpoint * tp;
  int ret;

  tp = get_tracepoint_at_address(address);
  if ( tp )
  {
    dbg_enable_tracepoint(tp);
    ret = 0;
  }
  else
    ret = ERROR_NO_TRACEPOINT;

  response = alloc_response_packet(0);
  response->error_code = ret;
  
  return response;
}

response_packet * __cmd_disable_tracepoint(void * address)
{
  response_packet * response;
  breakpoint * tp;
  int ret;

  tp = get_tracepoint_at_address(address);
  if ( tp )
  {
    dbg_disable_tracepoint(tp);
    if ( tengine.status == 0 && !dbg_any_tracepoint_alive() )
      tengine.status = TRACE_STOP_NO_MORE_PASS;

    ret = 0;
  }
  else
    ret = ERROR_NO_TRACEPOINT;

  response = alloc_response_packet(0);
  response->error_code = ret;
  
  return response;
}

response_packet * __cmd_get_tracepoint_status(void * address)
{
  response_packet * response;
  breakpoint * tp;
  trace_frame * tframe;
  int ret;

  response = alloc_response_packet(2 + sizeof(response->tpstatus)); 
  tp = get_tracepoint_at_address(address);
  if ( tp )
  {
    response->tpstatus.enabled = tp->trace.enabled;
    response->tpstatus.hits = tp->trace.hits;
    response->tpstatus.usage = 0;
    if ( tengine.tbuffer.frame_count > 0 )
      foreach_trace_frame(tframe)
        if ( tframe->tp == tp )
          response->tpstatus.usage += trace_frame_get_size(tframe);
    ret = 0;
  }
  else
    ret = ERROR_NO_TRACEPOINT;

  response->error_code = ret;
  return response;
}

response_packet * __cmd_set_tracepoint_condition(void * address, char type, char * code, unsigned int size)
{
  response_packet * response;
  breakpoint * tp;

  response = alloc_response_packet(0);

  tp = get_tracepoint_at_address(address);
  if ( !tp )
  {
    response->error_code = ERROR_NO_TRACEPOINT;
    return response;
  }

  if ( tp->trace.condition.code )
    free(tp->trace.condition.code);

  tp->trace.condition.code = malloc(size);
  if ( !tp->trace.condition.code )
  {
    response->error_code = ERROR_NO_MEMORY_AVAILABLE;
    return response;
  }

  switch ( type )
  {
    case TRACEPOINT_ACTION_EXEC_GDB:
    case TRACEPOINT_ACTION_EXEC_NATIVE:
      tp->trace.condition.type = type;
      tp->trace.condition.size = size;
      __memcpy(tp->trace.condition.code, code, size);
      break;

    default:
      response->error_code = ERROR_INVALID_TRACE_ACTION;
      free(tp->trace.condition.code);
  }

  return response;
}

response_packet * __cmd_add_tracepoint_action(void * address, char type, char * code, unsigned int size)
{
  response_packet * response;
  breakpoint * tp;
  trace_action * action;

  response = alloc_response_packet(0);

  tp = get_tracepoint_at_address(address);
  if ( !tp )
  {
    response->error_code = ERROR_NO_TRACEPOINT;
    return response;
  }

  action = malloc(sizeof(trace_action));
  if ( !action )
  {
    response->error_code = ERROR_NO_MEMORY_AVAILABLE;
    return response;
  }
  
  switch ( type )
  {
    case TRACEPOINT_ACTION_COLLECT_REGS: 
      break;

    case TRACEPOINT_ACTION_EXEC_GDB:
    case TRACEPOINT_ACTION_EXEC_NATIVE:
      action->exec.code = malloc(size);
      if ( !action->exec.code )
      {
        response->error_code = ERROR_NO_MEMORY_AVAILABLE;
        free(action);
        break;
      }
      __memcpy(action->exec.code, code, size);
      action->exec.size = size;
      break;

    default:
      response->error_code = ERROR_INVALID_TRACE_ACTION;
      free(action);
      break;
  }

  action->type = type;
  dbg_tracepoint_add_action(tp, action);
  
  return response;
}

response_packet * __cmd_get_tracebuffer_frame(unsigned int n)
{
  response_packet * response; 
  trace_frame * tframe;
  trace_entry * tentry;
  void * pentry;
  unsigned int entry_size;

  if ( n >= tengine.tbuffer.frame_count )
  {
    response = alloc_response_packet(0);
    response->error_code = ERROR_NO_TRACE_FRAME;
    return response;
  }

  tframe = tengine.tbuffer.frames;
  while ( n-- > 0 )
    tframe = tframe->next;

  response = alloc_response_packet(4 + trace_frame_get_size(tframe));
  response->trace_frame.tracepoint_addr = tframe->tp->address;
  
  pentry = &response->trace_frame.entries;
  foreach_trace_entry(tframe, tentry)
  {
    entry_size = trace_entry_get_size(tentry);
    __memcpy(pentry, &tentry->type, entry_size);
    pentry += entry_size;
  }

  return response;
}

