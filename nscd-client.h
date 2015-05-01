/* Copyright (c) 1998, 1999, 2000, 2003, 2004, 2005, 2006, 2007
   Free Software Foundation, Inc.
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

/* This file defines everything that client code should need to
   know to talk to the nscd daemon.  */

#ifndef _NSCD_CLIENT_H
#define _NSCD_CLIENT_H	1

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "nscd-types.h"
//#include <sys/uio.h>

/* Maximum allowed length for the key.  */
#define MAXKEYLEN 1024

/* Available services.  */
typedef enum
{
	GETPWBYNAME,
	GETPWBYUID,
	GETGRBYNAME,
	GETGRBYGID,
	GETHOSTBYNAME,
	GETHOSTBYNAMEv6,
	GETHOSTBYADDR,
	GETHOSTBYADDRv6,
	SHUTDOWN,			/* Shut the server down.  */
	GETSTAT,			/* Get the server statistic.  */
	INVALIDATE,         /* Invalidate one special cache.  */
	GETFDPW,
	GETFDGR,
	GETFDHST,
	GETAI,
	INITGROUPS,
	LASTREQ
} request_type;

/* Header common to all requests */
typedef struct
{
  int32_t version;		/* Version number of the daemon interface.  */
  request_type type;	/* Service requested.  */
  int32_t key_len;		/* Key length.  */
} request_header;


/* Structure sent in reply to host query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t h_name_len;
  nscd_ssize_t h_aliases_cnt;
  int32_t h_addrtype;
  int32_t h_length;
  nscd_ssize_t h_addr_list_cnt;
  int32_t error;
} hst_response_header;

/* Structure sent in reply to addrinfo query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t naddrs;
  nscd_ssize_t addrslen;
  nscd_ssize_t canonlen;
  int32_t error;
} ai_response_header;

/* Structure filled in by __nscd_getai.  */
struct nscd_ai_result
{
  int naddrs;
  char *canon;
  uint8_t *family;
  char *addrs;
};

/* Type for offsets in data part of database. */
typedef uint32_t ref_t;
/* Value for invalid/no reference. */
#define ENDREF	UINT32_MAX

/* Timestamp type.  */
typedef uint64_t nscd_time_t;

/* Alignment requirement of the beginning of the data region. */
#define ALIGN 16

/* Head of record in data part of database. */
struct datahead
{
	nscd_ssize_t allocsize;	/* Allocated Bytes. */
	nscd_ssize_t recsize;	/* Size of the record. */
	nscd_time_t timeout;	/* Time when this entry becomes invalid. */
	uint8_t notfound;		/* Nonzero if data has not been found. */
	uint8_t nreloads;		/* Reloads without use. */
	uint8_t usable;			/* False if the entry must be ignored. */
	uint64_t :40;			/* Alignment. */

	/* We need to have the following element aligned for the response
	   header data types and their use in the 'struct dataset' types
	   defined in the XXXcache.c files.
	 */
	union
	{
		hst_response_header hstdata;
		ai_response_header aidata;
		nscd_ssize_t align1;
		nscd_time_t align2;
	} data[0];
};


/* Structure for one hash table entry.  */
struct hashentry
{
  request_type type:8;		/* Which type of dataset.  */
  bool first;			/* True if this was the original key.  */
  nscd_ssize_t len;		/* Length of key.  */
  ref_t key;			/* Pointer to key.  */
  int32_t owner;		/* If secure table, this is the owner.  */
  ref_t next;			/* Next entry in this hash bucket list.  */
  ref_t packet;			/* Records for the result.  */
  union
  {
    struct hashentry *dellist;	/* Next record to be deleted.  This can be a
				   pointer since only nscd uses this field.  */
    ref_t *prevp;		/* Pointer to field containing forward
				   reference.  */
  };
};

/* Current persistent database version. */
#define DB_VERSION	1

/* Maximum time allowed between updates of the timestamp. */
#define MAPPING_TIMEOUT (5 * 60)

/* Header of persistent database file. */
struct database_pers_head
{
	int32_t version;
	int32_t header_size;
	volatile int32_t gc_cycle;
	volatile int32_t nscd_certainly_running;
	volatile nscd_time_t timestamp;

	nscd_ssize_t module;
	nscd_ssize_t data_size;

	nscd_ssize_t first_free;	/* Offset of first free byte in data area.  */

	nscd_ssize_t nentries;
	nscd_ssize_t maxnentries;
	nscd_ssize_t maxnsearched;

	uint64_t poshit;
	uint64_t neghit;
	uint64_t posmiss;
	uint64_t negmiss;

	uint64_t rdlockdelayed;
	uint64_t wrlockdelayed;

	uint64_t addfailed;

	ref_t array[0];
};

#endif /* nscd.h */
