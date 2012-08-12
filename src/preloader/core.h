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

#include <stddef.h>

#include "rex.h"

/* Hooked command from the diagnostic task */
#define DBG_CMD 0x7b

#define ERROR_CMD_NOT_FOUND -1
#define ERROR_INVALID_MEMORY_ACCESS -8

enum packet_type 
{
  PACKET_RESPONSE,
  PACKET_EVENT
};

enum cmd_type 
{
  /* Basic debugger commands */
  CMD_READ_MEM = 7,
  CMD_WRITE_MEM = 8,
};

/* Command structures */
typedef struct __attribute__((packed, aligned(4)))
{
  char hooked_cmd; // DBG_CMD
  char cmd_type;
  union 
  {
    struct {
      void * base;
      size_t size;
    } read;
    
    struct {
      void * dest;
      char data[1];
    } write;
  };
} request_packet;

typedef struct __attribute__((packed, aligned(4)))
{
  char type;
  char error_code;
  char data[1];

} response_packet;

response_packet * alloc_response_packet(size_t);

response_packet * __cmd_read_memory(void *, size_t);
response_packet * __cmd_write_memory(void *, void *, size_t);

#endif

