#ifndef __CMD_H
#define __CMD_H

#include "rex.h"

register char * stack asm("sp");

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
      unsigned int size;
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

response_packet * alloc_response_packet(int);

response_packet * __cmd_read_memory(void *, int);
response_packet * __cmd_write_memory(void *, void *, int);

#endif

