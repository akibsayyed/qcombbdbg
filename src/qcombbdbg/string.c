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

#include "string.h"

#ifdef REUSE_EXTERNAL_STRING_FUNCS

void * memmove(void * dest, const void * src, size_t n)
{
  return __memmove(dest, src, n);
}

void * memcpy(void * dest, const void * src, size_t n)
{
  return __memcpy(dest, src, n);
}

void * memset(void * s, int c, size_t n)
{
  return __memset(s, c, n);
}

#else

/* Redefinition of string functions */
void * memmove(void * dest, const void * src, size_t n)
{
  int i;

  if ( dest < src )
    for ( i = 0; i < n; ++i )
      ((char *)dest)[i] = ((char *)src)[i];

  else if ( dest > src )
    for ( i = n - 1; i >= 0; --i )
      ((char *)dest)[i] = ((char *)src)[i];

  return dest;
}

void * memcpy(void * dest, const void * src, size_t n)
{
  return memmove(dest, src, n);
}

void * memset(void * s, int c, size_t n)
{
  while ( n-- )
    ((char *)s)[n] = c;

  return s;
}

#endif

