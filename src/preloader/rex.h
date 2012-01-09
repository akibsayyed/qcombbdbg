#ifndef __REX_H
#define __REX_H

extern __attribute__((long_call)) void __memcpy(void *, void *, int);
extern __attribute__((long_call)) char * diag_alloc_packet(char, int);

#endif

