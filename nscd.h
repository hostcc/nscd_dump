/* Copyright (c) 1998-2001, 2003-2008, 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@suse.de>, 1998.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.
 */

#ifndef _NSCD_H
#define _NSCD_H	1

#include <time.h>

/* The declarations for the request and response types are in the file
   "nscd-client.h", which should contain everything needed by client
   functions.
 */
#include "nscd-client.h"

/* Maximum alignment requirement we will encounter. */
#define BLOCK_ALIGN_LOG 3
#define BLOCK_ALIGN (1 << BLOCK_ALIGN_LOG)
#define BLOCK_ALIGN_M1 (BLOCK_ALIGN - 1)

/* Default value for the maximum size of the database files. */
#define DEFAULT_MAX_DB_SIZE	(32 * 1024 * 1024)

/* Number of bytes of data we initially reserve for each hash table bucket. */
#define DEFAULT_DATASIZE_PER_BUCKET 1024

/* Default module of hash table.  */
#define DEFAULT_SUGGESTED_MODULE 211

/* Number of seconds between two cache pruning runs if we do not have
   better information when it is really needed.
 */
#define CACHE_PRUNE_INTERVAL	15

#endif /* nscd.h */
