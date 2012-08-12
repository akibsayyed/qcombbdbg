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

#ifndef __ABI_H
#define __ABI_H

#include <stddef.h>

void * memmove(void *, const void *, size_t);
void * memcpy(void *, const void *, size_t);
void * memset(void *, int, size_t);

extern void * __memmove(void *, const void *, size_t);
extern void * __memcpy(void *, const void *, size_t);
extern void * __memset(void *, int, size_t);

#endif

