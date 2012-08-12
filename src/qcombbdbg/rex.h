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

#ifndef __REX_H
#define __REX_H

#include <stddef.h>

#define ARM_CODE 0
#define THUMB_CODE 1

#define TASK_NAME_SIZE 12

typedef struct __attribute__((packed, aligned(4))) _rex_task
{
  void * stack_ptr;
  void * stack_limit;
  unsigned int switches_cnt;
  int active_signals;
  int wait_signals;
  int priority;
  unsigned int total_exec_time;
  int unknown_1c;
  unsigned int num_apc;
  struct _rex_task * next_task;
  struct _rex_task * prev_task;
  struct _rex_task * next_task_in_crit_sect;
  struct _rex_task * prev_task_in_crit_sect;
  int unknown_34;
  int unknown_38;
  int unknown_3c;
  int unknown_40;
  int unknown_44;
  int unknown_48;
  int unknown_4c;
  int unknown_50;
  void * critical_sections;
  char disabled;
  char unknown_59;
  char unknown_5a;
  char unknown_5b;
  struct _rex_task * unknown_task_ptr;
  char name[TASK_NAME_SIZE];
  struct _rex_task * self;
  size_t stack_size;
  int unknown_74;
  int heartbeat_id;
  int auto_heartbeat;
  int unknown_80;
} rex_task;

typedef struct __attribute__((packed)) _rex_critical_section
{
  char count;
  char pad1;
  char pad2;
  char pad3;
  rex_task * owner_task;
  rex_task * pending_task;
  int owner_priority;
} rex_critical_section;

typedef struct __attribute__((packed)) _rex_heap_chunk
{
  struct _rex_heap_chunk * forw_offset;
  char free_flag;
  char last_flag;
  char extra;
  char pad1;
  char unknown_8;
  char unknown_9;
  char unknown_a;
  char unknown_b;
} rex_heap_chunk;

typedef struct __attribute__((packed)) _rex_heap
{
  rex_heap_chunk * first_chunk;
  rex_heap_chunk * next_chunk;
  unsigned int total_chunks;
  size_t total_bytes;
  size_t used_bytes;
  size_t max_used_bytes;
  size_t max_chunk_size;
  void (* malloc_failover_routine)();
  void (* lock_routine)();
  void (* unlock_routine)();
} rex_heap;

typedef struct __attribute__((packed)) _rex_queue_item
{
  struct _rex_queue_item * next;
} rex_queue_item;

typedef struct __attribute__((packed)) _rex_queue
{
  rex_queue_item * next;
  rex_queue_item * last;
  unsigned int count;
} rex_queue;

typedef void * (* rex_apc_routine)(void *);

#define REX_EXECUTE_APC_STACK_SIZE 6 * sizeof(int) // @0x1375ec: push {r3-r7,lr}

#define TASK_ENABLE(task) task->disabled = 0;
#define TASK_DISABLE(task) task->disabled = 1;

extern char * __strcpy(char *, const char *);

extern rex_task * rex_self(void);
extern void rex_find_best_task(rex_task *);
extern void rex_context_switch(void);
extern int rex_wait(int signals);
extern int rex_set_task_signals(rex_task *, int);
extern int rex_clear_task_signals(rex_task *, int);
extern int rex_queue_dpc(rex_apc_routine, rex_task *, void *);

extern void rex_initialize_critical_section(rex_critical_section *);
extern void rex_enter_critical_section(rex_critical_section *);
extern void rex_leave_critical_section(rex_critical_section *);

extern void heap_create(rex_heap *, void *, size_t, void (*)(rex_heap *));
extern void * heap_malloc(rex_heap *, size_t);
extern void heap_free(rex_heap *, void *);

extern void rex_fatal_error(int, const char *, const char *);

extern char * diag_alloc_packet(char, size_t);
extern void diag_queue_response_packet(void *);

extern rex_task * tasks_head;

#endif

