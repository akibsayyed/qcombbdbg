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

