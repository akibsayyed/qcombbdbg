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

    default:
      response = alloc_response_packet(0);
      response->error_code = ERROR_CMD_NOT_FOUND;
      break;
  }

  return response;
}

