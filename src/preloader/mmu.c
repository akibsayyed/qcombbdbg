#include "mmu.h"

/*
 *  Get ARM processor identification information.
 */
cpu_id_register __attribute__((naked)) cpuid(void)
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "mrc p15, 0, r0, c0, c0, 0\n"
    "bx lr\n"
  );
}

/*
 *  Retrieves page translation table base register (TTBR0).
 */
mmu_page_table __attribute__((naked)) mmu_get_translation_table(void)
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "mrc p15, 0, r0, c2, c0, 0\n" /* assume we use TTBR0 here */
    "lsr r0, r0, %[section_shift]\n"
    "lsl r0, r0, %[section_shift]\n"
    "bx lr\n"
    :: [section_shift] "i" (MMU_PAGE_SECTION_SHIFT)
  );
}

/*
 *  Retrieves MMU control register.
 */
unsigned int __attribute__((naked)) mmu_get_control_register(void)
{
  asm(
    "bx pc\n"
    "nop\n"
    ".arm\n"
    ".code 32\n"
    "mrc p15, 0, r0, c1, c0, 0\n"
    "bx lr\n"
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
  section_end = ((unsigned int)addr + MMU_PAGE_SECTION_SIZE) & (MMU_PAGE_SECTION_SIZE - 1);

  if ( length > section_end - (unsigned int)addr )
  {
    sections_nr++;
    length -= section_end - (unsigned int)addr;
  }

  sections_nr += (length >> MMU_PAGE_SECTION_SHIFT);
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
  section_end = ((unsigned int)addr + MMU_PAGE_SECTION_SIZE) & (MMU_PAGE_SECTION_SIZE - 1);

  if ( length > section_end - (unsigned int)addr )
  {
    sections_nr++;
    length -= section_end - (unsigned int)addr;
  }

  sections_nr += (length >> MMU_PAGE_SECTION_SHIFT);
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

