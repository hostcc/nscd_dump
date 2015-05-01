/* A simple program to dump NSCD persistent database contents.
   Based on /nscd/connections.c from 
    CentOS Glibc package 'glibc-2.5-20061008T1257':
	 Copyright (C) 1998-2007, 2008, 2009 Free Software Foundation, Inc.
   	 Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <alloca.h>
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "nscd.h"

/* Map request type to a string.  */
const char *const serv2str[LASTREQ] =
{
  [GETPWBYNAME] = "GETPWBYNAME",
  [GETPWBYUID] = "GETPWBYUID",
  [GETGRBYNAME] = "GETGRBYNAME",
  [GETGRBYGID] = "GETGRBYGID",
  [GETHOSTBYNAME] = "GETHOSTBYNAME",
  [GETHOSTBYNAMEv6] = "GETHOSTBYNAMEv6",
  [GETHOSTBYADDR] = "GETHOSTBYADDR",
  [GETHOSTBYADDRv6] = "GETHOSTBYADDRv6",
  [SHUTDOWN] = "SHUTDOWN",
  [GETSTAT] = "GETSTAT",
  [INVALIDATE] = "INVALIDATE",
  [GETFDPW] = "GETFDPW",
  [GETFDGR] = "GETFDGR",
  [GETFDHST] = "GETFDHST",
  [GETAI] = "GETAI",
  [INITGROUPS] = "INITGROUPS"
};

enum usekey
  {
    use_not = 0,
    /* The following three are not really used, they are symbolic constants.  */
    use_first = 16,
    use_begin = 32,
    use_end = 64,

    use_he = 1,
    use_he_begin = use_he | use_begin,
    use_he_end = use_he | use_end,
#if SEPARATE_KEY
    use_key = 2,
    use_key_begin = use_key | use_begin,
    use_key_end = use_key | use_end,
    use_key_first = use_key_begin | use_first,
#endif
    use_data = 3,
    use_data_begin = use_data | use_begin,
    use_data_end = use_data | use_end,
    use_data_first = use_data_begin | use_first
  };


static int
check_use (const char *data, nscd_ssize_t first_free, uint8_t *usemap,
	   enum usekey use, ref_t start, size_t len)
{
  assert (len >= 2);

  if (start > first_free || start + len > first_free
      || (start & BLOCK_ALIGN_M1))
    return 0;

  if (usemap[start] == use_not)
    {
      /* Add the start marker.  */
      usemap[start] = use | use_begin;
      use &= ~use_first;

      while (--len > 0)
	if (usemap[++start] != use_not)
	  return 0;
	else
	  usemap[start] = use;

      /* Add the end marker.  */
      usemap[start] = use | use_end;
    }
  else if ((usemap[start] & ~use_first) == ((use | use_begin) & ~use_first))
    {
      /* Hash entries can't be shared.  */
      if (use == use_he)
	return 0;

      usemap[start] |= (use & use_first);
      use &= ~use_first;

      while (--len > 1)
	if (usemap[++start] != use)
	  return 0;

      if (usemap[++start] != (use | use_end))
	return 0;
    }
  else
    /* Points to a wrong object or somewhere in the middle.  */
    return 0;

  return 1;
}


/* Verify data in persistent database.  */
const char *
verify_persistent_db (void *mem, struct database_pers_head *readhead)
{
	time_t now = time (NULL);

	struct database_pers_head *head = mem;
	struct database_pers_head head_copy = *head;

	/* Check that the header that was read matches the head in the database. */
	if (memcmp (head, readhead, sizeof (*head)) != 0)
		return "Header read differs from databas header";

	/* First some easy tests: make sure the database header is sane.  */
	if (head->version != DB_VERSION)
		return "Invalid database version";

	if (head->header_size != sizeof (*head))
		return "Header size in database differs from expected";

    /* Allow a timestamp to be one hour ahead of the current time.
	   This should cover daylight saving time changes.
	 */
	if (head->timestamp > now + 60 * 60 + 60)
		return "Future timestamp in header";

	if (head->gc_cycle & 1)
		return "Invalid GC cycle value";

	if (head->module == 0)
		return "No data modules in database";

	if ((size_t) head->module > INT32_MAX / sizeof (ref_t))
		return "Excessive number of data modules";

    if ((size_t) head->data_size > INT32_MAX - head->module * sizeof (ref_t))
		return "Data size is larger than in data modules";

	if (head->first_free < 0)
		return "Negative offset of first free byte";
      
	if (head->first_free > head->data_size)
		return "Offset to first free byte is larger than data size";

	if ((head->first_free & BLOCK_ALIGN_M1) != 0)
		return "Offset of first free byte isn't properly aligned";

	if (head->maxnentries < 0)
		return "Negative number of maximum entries";

	if (head->maxnsearched < 0)
		return "Negative number of maximum search entries";
    
  uint8_t *usemap = calloc (head->first_free, 1);
  if (usemap == NULL)
    return "Memory allocation failure";

  const char *data = (char *) &head->array[roundup (head->module,
						    ALIGN / sizeof (ref_t))];

  nscd_ssize_t he_cnt = 0;
  for (nscd_ssize_t cnt = 0; cnt < head->module; ++cnt)
    {
      ref_t trail = head->array[cnt];
      ref_t work = trail;
      int tick = 0;

      while (work != ENDREF)
	{
	  if (! check_use (data, head->first_free, usemap, use_he, work,
			   sizeof (struct hashentry)))
	    goto fail;

	  /* Now we know we can dereference the record.  */
	  struct hashentry *here = (struct hashentry *) (data + work);

	  ++he_cnt;

	  /* Make sure the record is for this type of service.  */
	  if (here->type >= LASTREQ) {
	      printf ("record type is out of bounds\n");
	      goto fail;
	  }

	  if (!(here->type == GETHOSTBYNAME
		  || here->type == GETHOSTBYNAMEv6
		  || here->type == GETHOSTBYADDR
		  || here->type == GETHOSTBYADDRv6
		  || here->type == GETAI)) {
	    printf ("invalid record type: %s\n", serv2str[here->type]);
	    goto fail;
	  }

	  /* Validate boolean field value.  */
	  if (here->first != false && here->first != true) {
	      printf ("invalid boolean field\n");
	    goto fail;
	  }

	  if (here->len < 0) {
	    printf ("invalid record length\n");
	    goto fail;
	  }

	  /* Now the data.  */
	  if (here->packet < 0
	      || here->packet > head->first_free
	      || here->packet + sizeof (struct datahead) > head->first_free)
	    goto fail;

	  struct datahead *dh = (struct datahead *) (data + here->packet);

	  if (! check_use (data, head->first_free, usemap,
			   use_data | (here->first ? use_first : 0),
			   here->packet, dh->allocsize))
	    goto fail;

	  if (dh->allocsize < sizeof (struct datahead)
	      || dh->recsize > dh->allocsize
	      || (dh->notfound != false && dh->notfound != true)
	      || (dh->usable != false && dh->usable != true))
	    goto fail;

	  if (here->key < here->packet + sizeof (struct datahead)
	      || here->key > here->packet + dh->allocsize
	      || here->key + here->len > here->packet + dh->allocsize)
	    {
#if SEPARATE_KEY
	      /* If keys can appear outside of data, this should be done
		 instead.  But gc doesn't mark the data in that case.  */
	      if (! check_use (data, head->first_free, usemap,
			       use_key | (here->first ? use_first : 0),
			       here->key, here->len))
#endif
		goto fail;
	    }

	  work = here->next;

	  if (work == trail)
	    /* A circular list, this must not happen.  */
	    goto fail;
	  if (tick)
	    trail = ((struct hashentry *) (data + trail))->next;
	  tick = 1 - tick;
	}
    }

  if (he_cnt != head->nentries) {
      printf ("Actual number of records (%i) doesn't match with one in header (%i)\n",
      		he_cnt, head->nentries);
    goto fail;
  }

  /* See if all data and keys had at least one reference from
     he->first == true hashentry.  */
  for (ref_t idx = 0; idx < head->first_free; ++idx)
    {
#if SEPARATE_KEY
      if (usemap[idx] == use_key_begin)
	goto fail;
#endif
      if (usemap[idx] == use_data_begin)
	goto fail;
    }

  /* Finally, make sure the database hasn't changed since the first test.  */
  if (memcmp (mem, &head_copy, sizeof (*head)) != 0)
    goto fail;

  free (usemap);
  return NULL;

fail:
  free (usemap);
  return "Error";
}


void
print_db_header_stats (struct database_pers_head *head) {
	/* See struct database_pers_head definition in nscd-client.h */
    printf ("Database version          : %u\n", head->version);
    printf ("Database header size      : %u\n", head->header_size);
  	printf ("GC cycles                 : %u\n", head->gc_cycle);
	printf ("Taken from running daemon : %u\n", head->nscd_certainly_running);
	printf ("Timestamp, UTC            : %s",
			asctime (gmtime ((time_t *) &head->timestamp)));
	printf ("Modules                   : %u\n", head->module);
	printf ("Data size                 : %u\n", head->data_size);
	printf ("First free byte offset    : %u\n", head->first_free);
	printf ("Number of entries         : %u\n", head->nentries);
	printf ("Maximum number of entries : %u\n", head->maxnentries);
	printf ("Maximum number of enties searched: %u\n", head->maxnsearched);
	printf ("Positive hits             : %lu\n", head->poshit);
	printf ("Negative hits             : %lu\n", head->neghit);
	printf ("Positive misses           : %lu\n", head->posmiss);
	printf ("Negative misses           : %lu\n", head->negmiss);
	printf ("Delayed on read lock      : %lu\n", head->rdlockdelayed);
	printf ("Delayed on write lock     : %lu\n", head->wrlockdelayed);
	printf ("Additions failed          : %lu\n", head->addfailed);
}

#ifdef O_CLOEXEC
# define EXTRA_O_FLAGS O_CLOEXEC
#else
# define EXTRA_O_FLAGS 0
#endif

int
main (int argc, char *argv[])
{

	const char *db_filename = argv[1];
 	/* Try to open the appropriate file on disk.  */
	int fd = open (db_filename, O_RDWR | EXTRA_O_FLAGS);
	if (fd != -1)
	{
		const char *msg = NULL;
		struct stat64 st;
		void *mem;
		size_t total;
		struct database_pers_head head;
		ssize_t n = read (fd, &head, sizeof (head));
		if (n != sizeof (head) || fstat64 (fd, &st) != 0)
		  {
		  fail_db_errno:
		    /* The code is single-threaded at this point so
		       using strerror is just fine.  */
		    msg = strerror (errno);
		  fail_db:
		    printf ("invalid persistent database file \"%s\": %s\n",
		    	    db_filename, msg);
		  }
		else if (head.module == 0 && head.data_size == 0)
		  {
		    /* The file has been created, but the head has not
		       been initialized yet.  */
		    msg = "uninitialized header";
		    goto fail_db;
		  }
		else if (head.header_size != (int) sizeof (head))
		  {
		    msg = "header size does not match";
		    goto fail_db;
		  }
		else if ((total = (sizeof (head)
				   + roundup (head.module * sizeof (ref_t),
					      ALIGN)
				   + head.data_size))
			 > st.st_size
			 || total < sizeof (head))
		  {
		    msg = "file size does not match";
		    goto fail_db;
		  }
		/* Note we map with the maximum size allowed for the
		   database.  This is likely much larger than the
		   actual file size.  This is OK on most OSes since
		   extensions of the underlying file will
		   automatically translate more pages available for
		   memory access.  */
		else if ((mem = mmap (NULL,  DEFAULT_MAX_DB_SIZE,
				      PROT_READ | PROT_WRITE,
				      MAP_SHARED, fd, 0))
			 == MAP_FAILED)
		  goto fail_db_errno;
		else if ((msg = verify_persistent_db (mem, &head)) != NULL)
		  {
		    munmap (mem, total);
		    goto fail_db;
		  }
		else
		  {
			print_db_header_stats (&head);
		    munmap (mem, total);
		  }

		/* Close the file descriptors in case something went
		   wrong in which case the variable have not been
		   assigned -1.  */
		if (fd != -1)
		  close (fd);
	      }
	    else
	{
	      printf ("cannot access '%s': %s\n", db_filename, strerror (errno));
	      return 1;
	}
}
