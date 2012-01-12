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
 *  mmu.c: Handling of the memory management unit.
 */

#include "mmu.h"

#define ARM_ASSEMBLY(code) \
  asm( \
    "bx pc\n" \
    "nop\n" \
    ".arm\n" \
    ".code 32\n" \
    code \
  ) \

/*
 *  Get ARM processor identification information.
 */
cpu_id_register __attribute__((naked)) cpuid(void)
{
  ARM_ASSEMBLY(
    "mrc p15, 0, r0, c0, c0, 0\n"
    "bx lr\n"
  );
}

/*
 *  Retrieves page translation table base register (TTBR0).
 */
mmu_page_table __attribute__((naked)) mmu_get_translation_table(void)
{
  ARM_ASSEMBLY(
    "mrc p15, 0, r0, c2, c0, 0\n" /* assume we use TTBR0 here */
    "lsr r0, r0, #14\n"
    "lsl r0, r0, #14\n"
    "bx lr\n"
  );
}

/*
 *  Retrieves MMU cache type register.
 */
unsigned int __attribute__((naked)) mmu_get_cache_type_register(void)
{
  ARM_ASSEMBLY(
    "mrc p15, 0, r0, c0, c0, 1\n"
    "bx lr\n"
  );
}

/*
 *  Retrieves MMU control register.
 */
unsigned int __attribute__((naked)) mmu_get_control_register(void)
{
  ARM_ASSEMBLY(
    "mrc p15, 0, r0, c1, c0, 0\n"
    "bx lr\n"
  );
}

/*
 *  Invalidates a single instruction TLB entry.
 */
void __attribute__((naked)) mmu_invalidate_insn_tlb_entry(void * addr)
{
  ARM_ASSEMBLY(
    "mcr p15, 0, r0, c8, c5, 1\n"
    "bx lr\n"
  );
}

/*
 *  Invalidates a single data TLB entry.
 */
void __attribute__((naked)) mmu_invalidate_data_tlb_entry(void * addr)
{
  ARM_ASSEMBLY(
    "mcr p15, 0, r0, c8, c6, 1\n"
    "bx lr\n"
  );
}

/*
 *  Invalidates a single unified TLB entry.
 */
void __attribute__((naked)) mmu_invalidate_unified_tlb_entry(void * addr)
{
  ARM_ASSEMBLY(
    "mcr p15, 0, r0, c8, c7, 1\n"
    "bx lr\n"
  );
}

/*
 *  Invalidates a single line in the instruction cache.
 */
void __attribute__((naked)) mmu_invalidate_insn_cache_line(void * addr)
{
  ARM_ASSEMBLY(
    "mcr p15, 0, r0, c7, c5, 1\n"
    "bx lr\n"
  );
}

/*
 *  Cleans a single line in the data cache (commits cache to memory).
 */
void __attribute__((naked)) mmu_clean_data_cache_line(void * addr)
{
  ARM_ASSEMBLY(
    "mcr p15, 0, r0, c7, c10, 1\n"
    "bx lr\n"
  );
}

/*
 *  Invalidates a single TLB entry.
 */
void mmu_invalidate_tlb_entry(void * addr)
{
  if ( mmu_get_cache_type_register() & MMU_CACHE_CONTROL_SEPARATE )
  {
    mmu_invalidate_insn_tlb_entry(addr);
    mmu_invalidate_data_tlb_entry(addr);
  }
  else
    mmu_invalidate_unified_tlb_entry(addr);
}

/*
 *  Clean a single data cache line.
 *  Then invalidates the instruction cache line.
 *
 *  This is only relevant if we are using separate caches for instructions/data.
 *  In that case, rewriting a instruction in memory will only update the data cache.
 *  As the original instruction may still be present in the instruction cache, 
 *  we need to invalidate its line.
 */
void mmu_sync_insn_cache_at(void * addr)
{
  unsigned int cache_type;

  cache_type = mmu_get_cache_type_register();
  if ( cache_type & MMU_CACHE_CONTROL_SEPARATE )
  {
    if ( cache_type & MMU_CACHE_TYPE_MASK != MMU_CACHE_TYPE_WRITE_THROUGH )
      mmu_clean_data_cache_line(addr);

    mmu_invalidate_insn_cache_line(addr);
  }
}

/*
 *  Invalidates entire TLB.
 */
void __attribute__((naked)) mmu_invalidate_tlb(void)
{
  ARM_ASSEMBLY(
    "mov r0, #0\n"
    "mcr p15, 0, r0, c8, c7, 0\n"
    "bx lr\n"
  );
}

/*
 *  Enables the memory management unit.
 */
void __attribute__((naked)) mmu_enable(void)
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "mrc p15, 0, r0, c1, c0, 0\n"
    "orr r0, r0, %[rom_protect_flag]\n"
    "mcr p15, 0, r0, c1, c0, 0\n"
    "mov r0, #0\n"
    "mcr p15, 0, r0, c7, c7, 0\n" /* invalidate L1 cache */
    //"mcr p15, 0, r0, c8, c7, 0\n" /* invalidate TLB */
    "mrc p15, 0, r0, c1, c0, 0\n"
    "orr r0, r0, %[mmu_flag]\n"
    "mcr p15, 0, r0, c1, c0, 0\n"
    "mrc p15, 0, r0, c1, c0, 0\n"
    "orr r0, r0, %[L1_insn_flag]\n"
    "orr r0, r0, %[L1_data_flag]\n"
    "mcr p15, 0, r0, c1, c0, 0\n"
    "bx lr\n" 
    :: [rom_protect_flag] "i" (MMU_CONTROL_ROM_PROTECT),
       [mmu_flag] "i" (MMU_CONTROL_ENABLE),
       [L1_insn_flag] "i" (MMU_CONTROL_L1_INSTRUCTION_CACHE_ENABLE),
       [L1_data_flag] "i" (MMU_CONTROL_L1_DATA_CACHE_ENABLE)
  );
}

/*
 *  Disables the memory management unit.
 */
void __attribute__((naked)) mmu_disable(void)
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "mov r0, %[disable_mmu_control]\n"
    "mcr p15, 0, r0, c1, c0, 0\n"
    "mrc p15, 0, r0, c1, c0, 0\n"
    "orr r0, r0, %[L1_insn_flag]\n"
    "mcr p15, 0, r0, c1, c0, 0\n"
    "bx lr\n"
    ::
    [disable_mmu_control] "i" (MMU_CONTROL_WRITE_BUFFER),
    [L1_insn_flag] "i" (MMU_CONTROL_L1_INSTRUCTION_CACHE_ENABLE)
  );
}

/*
 *  Checks if a memory area is readable.
 *  ARMv5 only, assumes APX is not implemented.
 *  Assumes section granularity is used.
 */
int mmu_probe_read(void * addr, unsigned int length)
{
  mmu_page_table ttbr;
  mmu_section_descriptor * section_desc_entry;
  unsigned int mmu_ctrl;
  unsigned int sections_nr, section_end;
  int i;

  ttbr = mmu_get_translation_table();
  mmu_ctrl = mmu_get_control_register();

  /* Computes number of impacted sections */
  sections_nr = 0;
  section_end = ((unsigned int)addr + MMU_PAGE_SECTION_SIZE) & ~(MMU_PAGE_SECTION_SIZE - 1);

  if ( length > section_end - (unsigned int)addr )
  {
    sections_nr++;
    length -= section_end - (unsigned int)addr;
  }

  /* length / MMU_PAGE_SECTION_SIZE */
  sections_nr += (length >> MMU_PAGE_SECTION_SHIFT);

  /* length % MMU_PAGE_SECTION_SIZE */
  if ( length - ((length >> MMU_PAGE_SECTION_SHIFT) << MMU_PAGE_SECTION_SHIFT) )
    sections_nr++;

  /* Checks access right for each section */
  for ( i = 0; i < sections_nr; ++i )
  {
    section_desc_entry = &ttbr[((unsigned int)addr >> MMU_PAGE_SECTION_SHIFT) + i];

    if ( section_desc_entry->type == MMU_PAGE_TYPE_UNMAPPED )
      return 0;

    if ( ! (mmu_ctrl & (MMU_CONTROL_SYSTEM_PROTECT | MMU_CONTROL_ROM_PROTECT)) )
    {
      if ( section_desc_entry->ap == 0 )
        return 0;
    }
  }

  return 1;
}

/*
 *  Checks if a memory area is writable.
 *  ARMv5 only, assumes APX is not implemented.
 *  Assumes section granularity is used.
 */
int mmu_probe_write(void * addr, unsigned int length)
{
  mmu_page_table ttbr;
  mmu_section_descriptor * section_desc_entry;
  unsigned int sections_nr, section_end;
  int i;

  ttbr = mmu_get_translation_table();
  
  /* Computes number of impacted sections */
  sections_nr = 0;
  section_end = ((unsigned int)addr + MMU_PAGE_SECTION_SIZE) & ~(MMU_PAGE_SECTION_SIZE - 1);

  if ( length > section_end - (unsigned int)addr )
  {
    sections_nr++;
    length -= section_end - (unsigned int)addr;
  }

  /* length / MMU_PAGE_SECTION_SIZE */
  sections_nr += (length >> MMU_PAGE_SECTION_SHIFT);
  
  /* length % MMU_PAGE_SECTION_SIZE */
  if ( length - ((length >> MMU_PAGE_SECTION_SHIFT) << MMU_PAGE_SECTION_SHIFT) )
    sections_nr++;

  /* Checks access right for each section */
  for ( i = 0; i < sections_nr; ++i )
  {
    section_desc_entry = &ttbr[((unsigned int)addr >> MMU_PAGE_SECTION_SHIFT) + i];

    if ( section_desc_entry->type == MMU_PAGE_TYPE_UNMAPPED )
      return 0;

    if ( section_desc_entry->ap == 0 )
      return 0;
  }

  return 1;
}

/*
 *  Checks if a memory address is executable.
 *  ARMv5 only, assumes XN is not implemented.
 */
int mmu_probe_execute(void * addr)
{
  return mmu_probe_read(addr, 4);
}

/* 
 *  Modifies access protection at specified address.
 */
int mmu_set_access_protection(void * addr, int prot)
{
  mmu_page_table ttbr;
  mmu_section_descriptor * section_desc_entry;
  int prev_prot;

  /* Get the section entry */
  ttbr = mmu_get_translation_table();
  section_desc_entry = &ttbr[(unsigned int)addr >> MMU_PAGE_SECTION_SHIFT];

  /* Saving previous access protections */
  if ( section_desc_entry->type == MMU_PAGE_TYPE_UNMAPPED )
    prev_prot = MMU_PROT_NOACCESS;
  else if ( section_desc_entry->ap == MMU_SECTION_AP_READ_ONLY )
    prev_prot = MMU_PROT_READ_ONLY;
  else
    prev_prot = MMU_PROT_READ_WRITE;

  mmu_disable();

  /* Modify section access rights */
  switch ( prot )
  {
    case MMU_PROT_READ_ONLY:
      section_desc_entry->type = MMU_PAGE_TYPE_SECTION;
      section_desc_entry->ap = MMU_SECTION_AP_READ_ONLY;
      break;

    case MMU_PROT_READ_WRITE:
      section_desc_entry->type = MMU_PAGE_TYPE_SECTION;
      section_desc_entry->ap = MMU_SECTION_AP_READ_WRITE;
      break;

    case MMU_PROT_NOACCESS:
      section_desc_entry->type = MMU_PAGE_TYPE_UNMAPPED;
      break;
  }
  
  /* Invalidate TLB line */
  mmu_invalidate_tlb_entry(addr);
  mmu_enable();

  return prev_prot;
}

