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

#include "string.h"
#include "rex.h"
#include "core.h"

/*
 *  Allocates a DIAG packet of the specified size.
 *  Automatically freed when processed by the task.
 */
void * alloc_packet(size_t size)
{
  return diag_alloc_packet(DBG_CMD, size);
}

/* 
 * Allocates a new response packet from the diag task heap.
 * Argument is size of the packet, not counting first two mandatory header bytes (type and error_code).
 */
response_packet * alloc_response_packet(size_t data_size)
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

response_packet * __cmd_read_memory(void * start, size_t size)
{
  response_packet * response;

  response = alloc_response_packet(size);
  memcpy(&response->data, start, size);

  return response;
}

response_packet * __cmd_write_memory(void * dest, void * data, size_t size)
{
  response_packet * response;

  response = alloc_response_packet(0);
  memcpy(dest, data, size);

  return response;
}

