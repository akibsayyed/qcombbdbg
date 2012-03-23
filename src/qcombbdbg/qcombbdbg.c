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
 *  qcombbdbg.c: Debugger entry point. Main command handler.
 */

#include "core.h"

/*
 * Important: I instructed GCC to preserve code order (-fno-toplevel-reorder).
 * Do not place anything before the first function in order to preserve this
 * as the entry point.
 */

response_packet * __cmd_dispatcher(request_packet * packet, int size)
{
  response_packet * response;

  response = 0;
  switch ( packet->cmd_type )
  {
    case CMD_ATTACH:
      response = __cmd_attach();
      break;

    case CMD_DETACH:
      response = __cmd_detach();
      break;

    case CMD_GET_NUM_TASKS:
      response = __cmd_get_num_tasks();
      break;

    case CMD_GET_TASK_INFO:
      response = __cmd_get_task_info(packet->tid);
      break;

    case CMD_GET_TASK_STATE:
      response = __cmd_get_task_state(packet->tid);
      break;

    case CMD_STOP_TASK:
      response = __cmd_stop_task(packet->tid);
      break;

    case CMD_RESUME_TASK:
      response = __cmd_resume_task(packet->tid);
      break;

    case CMD_READ_MEM:
      response = __cmd_read_memory(packet->read.base, packet->read.size);
      break;

    case CMD_WRITE_MEM:
      response = __cmd_write_memory(
        packet->write.dest, 
        packet->write.data, 
        size - __builtin_offsetof(request_packet, write.data)
      );
      break;

    case CMD_GET_REGS:
      response = __cmd_read_registers(packet->tid);
      break;

    case CMD_SET_REGS:
      response = __cmd_write_registers(packet->set_regs.tid, &packet->set_regs.ctx);
      break;

    case CMD_INSERT_BREAKPOINT:
      response = __cmd_insert_breakpoint(packet->breakpoint.address, packet->breakpoint.kind);
      break;

    case CMD_REMOVE_BREAKPOINT:
      response = __cmd_remove_breakpoint(packet->breakpoint.address);
      break;

    case CMD_TRACE_CLEAR:
      response = __cmd_trace_clear();
      break;

    case CMD_TRACE_START:
      response = __cmd_trace_start();
      break;

    case CMD_TRACE_STOP:
      response = __cmd_trace_stop();
      break;

    case CMD_TRACE_STATUS:
      response = __cmd_trace_status();
      break;

    case CMD_GET_TVAR:
      response = __cmd_get_trace_variable(packet->tvar.id);
      break;

    case CMD_SET_TVAR:
      response = __cmd_set_trace_variable(packet->tvar.id, packet->tvar.value);
      break;

    case CMD_INSERT_TRACEPOINT:
      response = __cmd_insert_tracepoint(
        packet->tracepoint.address,
        packet->tracepoint.kind,
        packet->tracepoint.pass
      );
      break;

    case CMD_REMOVE_TRACEPOINT:
      response = __cmd_remove_tracepoint(packet->breakpoint.address);
      break;

    case CMD_ENABLE_TRACEPOINT:
      response = __cmd_enable_tracepoint(packet->breakpoint.address);
      break;

    case CMD_DISABLE_TRACEPOINT:
      response = __cmd_disable_tracepoint(packet->breakpoint.address);
      break;

    case CMD_GET_TRACEPOINT_STATUS:
      response = __cmd_get_tracepoint_status(packet->breakpoint.address);
      break;

    case CMD_ADD_TRACEPOINT_ACTION:
      response = __cmd_add_tracepoint_action(
        packet->taction.address, 
        packet->taction.type, 
        packet->taction.code, 
        size - __builtin_offsetof(request_packet, taction.code)
      );
      break;

    case CMD_GET_TRACE_FRAME:
      response = __cmd_get_tracebuffer_frame(packet->frame_num);
      break;

#ifdef DEBUG
    case CMD_DEBUG_ECHO:
      response = __cmd_echo(packet, size);
      break;

    case CMD_DEBUG_CALL:
      response = __cmd_call_routine(
        packet->call.f,
        packet->call.arg1,
        packet->call.arg2,
        packet->call.arg3,
        packet->call.arg4
      );
      break;

    case CMD_DEBUG_TRIGGER_EXCEPTION:
      response = __cmd_trigger_exception(packet->exception.tid, packet->exception.exception);
      break;

    case CMD_DEBUG_TRIGGER_STACK_OVERFLOW:
      response = __cmd_trigger_stack_overflow(
        packet->overflow.tid, 
        packet->overflow.data,
        size - __builtin_offsetof(request_packet, overflow.data)
      );
      break;

    case CMD_DEBUG_SEND_SIGNAL:
      response = __cmd_send_signal(packet->signal.tid, packet->signal.sigs);
      break;

    case CMD_DEBUG_RELOC_INSN:
      response = __cmd_reloc_insn(packet->reloc.src, packet->reloc.dst);
      break;

#endif

    default:
      response = alloc_response_packet(0);
      response->error_code = ERROR_CMD_NOT_FOUND;
      break;
  }

  return response;
}

