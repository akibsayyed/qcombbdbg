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
  int total_exec_time;
  int unknown_1c;
  int num_apc;
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
  int stack_size;
  int unknown_74;
  int heartbeat_id;
  int auto_heartbeat;
  int unknown_80;
} rex_task;

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
  int total_chunks;
  int total_bytes;
  int used_bytes;
  int max_used_bytes;
  int max_chunk_size;
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
  int count;
} rex_queue;

typedef void * (* rex_apc_routine)(void *);

#define REX_EXECUTE_APC_STACK_SIZE 6 * sizeof(int) // @0x1375ec: push {r3-r7,lr}

#define NO_INTERRUPTS(code) \
  cpu_interrupts_disable(); \
  code; \
  cpu_interrupts_enable(); \

#define TASK_ENABLE(task) task->disabled = 0;
#define TASK_DISABLE(task) task->disabled = 1;

extern __attribute__((long_call)) void __memcpy(void *, void *, int);
extern __attribute__((long_call)) void __memmove(void *, void *, int);
extern __attribute__((long_call)) void __memset(void *, char, int);
extern __attribute__((long_call)) char * __strcpy(char *, const char *);

extern __attribute__((long_call)) unsigned long long int __idivsi3(int, int);
extern __attribute__((long_call)) unsigned long long int __udivsi3(unsigned int, unsigned int);

extern __attribute__((long_call)) rex_task * rex_self(void);
extern __attribute__((long_call)) void rex_find_best_task(rex_task *);
extern __attribute__((long_call)) void rex_context_switch(void);
extern __attribute__((long_call)) int rex_wait(int signals);
extern __attribute__((long_call)) int rex_set_task_signals(rex_task *, int);
extern __attribute__((long_call)) int rex_clear_task_signals(rex_task *, int);
extern __attribute__((long_call)) int rex_queue_dpc(rex_apc_routine, rex_task *, void *);

extern __attribute__((long_call)) void heap_create(rex_heap *, void *, int, void (*)(rex_heap *));
extern __attribute__((long_call)) void * heap_malloc(rex_heap *, int);
extern __attribute__((long_call)) void heap_free(rex_heap *, void *);

extern __attribute__((long_call)) char * diag_alloc_packet(char, int);
extern __attribute__((long_call)) void diag_queue_response_packet(void *);

extern rex_task * tasks_head;

#endif

