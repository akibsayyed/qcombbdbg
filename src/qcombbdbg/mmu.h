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

#ifndef __MMU_H
#define __MMU_H

#include <stddef.h>

typedef struct 
{
  void * base_address;
  size_t length;
  struct 
  {
    int read : 1;
    int write : 1;
    int exec : 1;
  } rights;
} memory_region;

typedef union 
{
  unsigned int i;

  struct __attribute__((packed))
  {
    unsigned int revision : 4;
    unsigned int reserved : 8;
    unsigned int primary : 4;
    unsigned int arch : 4;
    unsigned int variant : 4;
    unsigned int implementor : 8;
  } bits;
} cpu_id_register;

#define MMU_PAGE_SECTION_SHIFT 20
#define MMU_PAGE_SECTION_SIZE (1 << MMU_PAGE_SECTION_SHIFT)

#define MMU_PAGE_TYPE_UNMAPPED 0
#define MMU_PAGE_TYPE_COARSE 1
#define MMU_PAGE_TYPE_SECTION 2
#define MMU_PAGE_TYPE_FINE 3

/* Defined for ROM Protect bit set */
#define MMU_SECTION_AP_READ_ONLY 0
#define MMU_SECTION_AP_READ_WRITE 3

#define MMU_CACHE_TYPE_WRITE_THROUGH 0

typedef union
{
  unsigned int i;

  struct __attribute__((packed))
  {
    unsigned int isize_len : 2;
    unsigned int isize_m : 1;
    unsigned int isize_assoc : 3;
    unsigned int isize_size : 3;
    unsigned int isize_sbz : 3;
    
    unsigned int dsize_len : 2;
    unsigned int dsize_m : 1;
    unsigned int dsize_assoc : 3;
    unsigned int dsize_size : 3;
    unsigned int dsize_sbz : 3;

    unsigned int separate : 1;
    unsigned int ctype : 4;
    unsigned int sbz : 3;
  } bits;
} cache_type_register;

/* Page protections */
enum page_access
{
  MMU_PROT_NOACCESS,
  MMU_PROT_READ_ONLY,
  MMU_PROT_READ_WRITE
};

typedef union
{
  unsigned int i;
  
  struct __attribute__((packed))
  {
    unsigned int type : 2;
    unsigned int b : 1;
    unsigned int c : 1;
    unsigned int xn : 1; /* ARMv6 */
    unsigned int domain : 4;
    unsigned int imp : 1;
    unsigned int ap : 2;
    unsigned int tex : 3;
    unsigned int apx : 1; /* ARMv6 */
    unsigned int s : 1;
    unsigned int ng : 1;
    unsigned int super : 1;
    unsigned int sbz : 1;
    unsigned int base_address : 12;
  } bits;
} mmu_section_descriptor;

typedef mmu_section_descriptor *mmu_page_table;

#define MMU_CONTROL_ENABLE (1 << 0)
#define MMU_CONTROL_ALIGN_CHECK (1 << 1)
#define MMU_CONTROL_L1_DATA_CACHE_ENABLE (1 << 2)
#define MMU_CONTROL_WRITE_BUFFER (1 << 3)
#define MMU_CONTROL_SYSTEM_PROTECT (1 << 8)
#define MMU_CONTROL_ROM_PROTECT (1 << 9)
#define MMU_CONTROL_BRANCH_PREDICT_ENABLE (1 << 11)
#define MMU_CONTROL_L1_INSTRUCTION_CACHE_ENABLE (1 << 12)
#define MMU_CONTROL_HIGH_VECTORS (1 << 13)
#define MMU_CONTROL_CACHE_RR_STRATEGY (1 << 14)

#define MMU_CONTROL_EXTENDED_PAGE_TABLE (1 << 23)
#define MMU_CONTROL_EXCEPTION_ENDIAN (1 << 25)

cpu_id_register cpuid(void);
void mmu_enable(void);
void mmu_disable(void);
int mmu_probe_read(void *, size_t);
int mmu_probe_write(void *, size_t);
int mmu_probe_execute(void *);
int mmu_set_access_protection(void *, int);
void mmu_sync_insn_cache_at(void * addr);
void mmu_sync_insn_cache_range(void * addr, size_t);
int mmu_get_memory_map(memory_region **, unsigned int *);
void mmu_put_memory_map(memory_region *);

#endif

