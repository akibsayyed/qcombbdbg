#ifndef __MMU_H
#define __MMU_H

typedef struct __attribute__((packed))
{
  unsigned int revision : 4;
  unsigned int reserved : 8;
  unsigned int primary : 4;
  unsigned int arch : 4;
  unsigned int variant : 4;
  unsigned int implementor : 8;
} cpu_id_register;

#define MMU_PAGE_SECTION_SHIFT 20
#define MMU_PAGE_SECTION_SIZE (1 << MMU_PAGE_SECTION_SHIFT)

#define MMU_PAGE_TYPE_UNMAPPED 0
#define MMU_PAGE_TYPE_COARSE 1
#define MMU_PAGE_TYPE_SECTION 2
#define MMU_PAGE_TYPE_FINE 3

typedef struct __attribute__((packed))
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
} mmu_section_descriptor;

typedef mmu_section_descriptor *mmu_page_table;

#define MMU_CONTROL_ENABLE (1 << 0)
#define MMU_CONTROL_ALIGN_CHECK (1 << 1)
#define MMU_CONTROL_WRITE_BUFFER (1 << 3)
#define MMU_CONTROL_SYSTEM_PROTECT (1 << 8)
#define MMU_CONTROL_ROM_PROTECT (1 << 9)
#define MMU_CONTROL_EXTENDED_PAGE_TABLE (1 << 23)
#define MMU_CONTROL_EXCEPTION_ENDIAN (1 << 25)

int mmu_probe_read(void *, unsigned int);
int mmu_probe_write(void *, unsigned int);
int mmu_probe_execute(void *);

#endif

