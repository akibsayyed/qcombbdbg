#include "rex.h"
#include "mmu.h"
#include "core.h"

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

response_packet * __cmd_read_memory(void * start, int size)
{
  response_packet * response;

  response = alloc_response_packet(size);
  __memcpy(&response->data, start, size);

  return response;
}

response_packet * __cmd_write_memory(void * dest, void * data, int size)
{
  response_packet * response;

  response = alloc_response_packet(0);
  __memcpy(dest, data, size);

  return response;
}

