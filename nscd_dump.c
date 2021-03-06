/* A simple program to dump NSCD persistent database contents.

   Supports DB version 1 only, version 2 has introduced in 2.14.90 by
   commit 3a2c02424d9824f5cdea4ebd32ff929b2b1f49c6
   (Git head: de7827ff96076cb4d181ed781c418601906fa772).

   Based on nscd/connections.c from 
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
#include <arpa/inet.h>

#include "nscd.h"

const char *af2str[AF_MAX] = {
	[AF_INET] = "IPv4",
	[AF_INET6] = "IPv6"
};

/* Map request type to a string.  */
const char *const serv2str[LASTREQ] = {
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

enum usekey {
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

const char *
check_use (const char *data, nscd_ssize_t first_free, uint8_t *usemap,
		   enum usekey use, ref_t start, size_t len) {
	assert (len >= 2);

	if (    start > first_free || start + len > first_free
		|| (start & BLOCK_ALIGN_M1))
		return "Hash entry isn't properly aligned";

	if (usemap[start] == use_not) {
		/* Add the start marker. */
		usemap[start] = use | use_begin;
		use &= ~use_first;

		while (--len > 0)
			if (usemap[++start] != use_not)
				return "Hash entry isn't marked as free where it has to be";
			else
				usemap[start] = use;

		/* Add the end marker. */
		usemap[start] = use | use_end;
	} else if (    (usemap[start] & ~use_first)
				== ((use | use_begin) & ~use_first)) {
    	/* Hash entries can't be shared. */
    	if (use == use_he)
			return "Hash entry can't be shared";
	
		usemap[start] |= (use & use_first);
    	use &= ~use_first;

    	while (--len > 1)
			if (usemap[++start] != use)
				return "Hash entry isn't marked as in use where it has to be";

    	if (usemap[++start] != (use | use_end))
			return "Hash entry isn't marked as last onee where it has to be";
    } else
    	/* Points to a wrong object or somewhere in the middle. */
		return "Invalid pointer to a hash entry";

	return NULL;
}

/* Verify data in persistent database.  */
const char *
verify_persistent_db (void *mem, struct database_pers_head *readhead)
{
	const char *msg;
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
	for (nscd_ssize_t cnt = 0; cnt < head->module; ++cnt) {
		ref_t trail = head->array[cnt];
		ref_t work = trail;
		int tick = 0;

		while (work != ENDREF) {
			msg = check_use (data, head->first_free, usemap, use_he, work,
							sizeof (struct hashentry));
			if (msg != NULL) {
				free (usemap);
				return msg;
			}

			/* Now we know we can dereference the record.  */
			struct hashentry *here = (struct hashentry *) (data + work);

			++he_cnt;

			/* Make sure the record is for this type of service. */
			if (here->type >= LASTREQ) {
				free (usemap);
				return "Record type is out of bounds";
			}

			if (! (here->type == GETHOSTBYNAME
				|| here->type == GETHOSTBYNAMEv6
				|| here->type == GETHOSTBYADDR
				|| here->type == GETHOSTBYADDRv6
				|| here->type == GETAI)) {
				free (usemap);
				return "Invalid record type";
			}

			/* Validate boolean field value.  */
			if (here->first != false && here->first != true) {
				free (usemap);
				return "Invalid boolean field";
			}

			if (here->len < 0) {
				free (usemap);
				return "Negative record length";
			}

			/* Now the data. */
			if (here->packet < 0) {
				free (usemap);
				return "Negative packet offset";
			}

			if (here->packet > head->first_free) {
				free (usemap);
				return "Packet offset beyond first free byte";
			}

			if (here->packet + sizeof (struct datahead) > head->first_free) {
				free (usemap);
				return "Packet data offset beyond first free byte";
			}

			if (here->first != false && here->first != true) {
				free (usemap);
				return "Invalid \"first\" field contents";
			}

			struct datahead *dh = (struct datahead *) (data + here->packet);

			msg = check_use (data, head->first_free, usemap,
			   				use_data | (here->first ? use_first : 0),
			   				here->packet, dh->allocsize);
			if (msg != NULL) {
				free (usemap);
				return msg;
			}

			if (dh->allocsize < sizeof (struct datahead)) {
				free (usemap);
				return "Short data header size";
			}
			if (dh->recsize > dh->allocsize) {
				free (usemap);
				return "Data size is above allocated one";
			}
			if (dh->notfound != false && dh->notfound != true) {
				free (usemap);
				return "Invalid \"notfound\" field contents";
			}
			if (dh->usable != false && dh->usable != true) {
				free (usemap);
				return "Invalid \"usable\" field contents";
			}

			if (   here->key < here->packet + sizeof (struct datahead)
				|| here->key > here->packet + dh->allocsize
				|| here->key + here->len > here->packet + dh->allocsize) {
#if SEPARATE_KEY
			/* If keys can appear outside of data, this should be done
			   instead.  But gc doesn't mark the data in that case.
			 */
				msg = check_use (data, head->first_free, usemap,
				   				 use_key | (here->first ? use_first : 0),
				   				 here->key, here->len);
				if (msg != NULL) {
					free (usemap);
					return msg;
				}
#endif
				free (usemap);
				return "Invalid hash entry";
			}

			work = here->next;

			/* A circular list, this must not happen.  */
			if (work == trail) {
				free (usemap);
				return "Circullar list detected";
			}
			
			if (tick)
				trail = ((struct hashentry *) (data + trail))->next;
			
			tick = 1 - tick;
		}
	}

	if (he_cnt != head->nentries) {
		free (usemap);
		return "Actual number of records doesn't match with one in header";
	}

	/* See if all data and keys had at least one reference from
	   he->first == true hashentry.
	 */
	for (ref_t idx = 0; idx < head->first_free; ++idx) {
#if SEPARATE_KEY
		if (usemap[idx] == use_key_begin) {
			free (usemap);
			return "Unreferenced data and/or keys found";
		}
#endif
		if (usemap[idx] == use_data_begin) {
			free (usemap);
			return "Unreferenced data and/or keys found";
		}
	}

	/* Finally, make sure the database hasn't changed since the first test. */
	if (memcmp (mem, &head_copy, sizeof (*head)) != 0) {
		free (usemap);
		return "Database header changed in transit";
	}

	free (usemap);
	return NULL;
}

void
print_db_header_stats (struct database_pers_head *head) {
	/* See struct database_pers_head definition in nscd-client.h */
    printf ("Database version          : %u\n", head->version);
    printf ("Database header size      : %u\n", head->header_size);
  	printf ("GC cycles                 : %u\n", head->gc_cycle);
	printf ("Taken from running daemon : %u\n", head->nscd_certainly_running);
	const char *tstamp = asctime (gmtime ((time_t *) &head->timestamp));
	printf ("Timestamp, UTC            : %s", tstamp ? tstamp : "Invalid");
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
	printf ("\n");
}

void
print_hashentry_datahead (struct hashentry *he, struct datahead *dh,
						  const char *key, int nr, int verbose) {
	char ip_addr_buf[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	printf ("#%u. Key: \"", nr);
	if (   he->type == GETHOSTBYADDR
		|| he->type == GETHOSTBYADDRv6) {
		printf ("%s",
			inet_ntop (he->type == GETHOSTBYADDRv6
						? AF_INET6 : AF_INET,
					   key, ip_addr_buf, sizeof (ip_addr_buf)));
	} else {
		for (int i = 0; i < he->len - 1; i++)
			printf ("%c", key[i]);
	}

	const char *tstamp = asctime (gmtime ((time_t *) &dh->timeout));
	printf ("\". Expires, UTC: %s", tstamp ? tstamp : "Invalid");
	printf (" Record is %susable", dh->usable ? "" : "un");
	printf (", %s response", dh->notfound ? "negative" : "positive");
	printf (", reloads in cache w/o change: %u", dh->nreloads);
	printf (", first: %s\n", he->first ? "yes" : "no");

	if (verbose) {
		printf (" Key len: %u", he->len);
		printf (", allocated size: %u", dh->allocsize);
		printf (", record size: %u\n", dh->recsize);
		printf (" Service: %s", serv2str[he->type]);
	}
}

void
print_ip_addr (int af_family, void *addr) {
	char ip_addr_buf[MAX(INET_ADDRSTRLEN,INET6_ADDRSTRLEN)];
	const char *output;

	output = inet_ntop (af_family, addr, ip_addr_buf, sizeof (ip_addr_buf));
	printf ("%s", output ? output : strerror (errno));
}

ref_t
print_hst_resp_data (request_type type, hst_response_header *hst_resp,
					 char *resp_data, int verbose) {
	ref_t consumed = 0;

	if (verbose) {
		printf (", version: %u", hst_resp->version);
		printf (", %s response\n", hst_resp->found < 0
				? "disabled" : hst_resp->found
					? "positive" : "negative");
		printf (" Name len: %u", hst_resp->h_name_len);
		printf (", aliases count: %u", hst_resp->h_aliases_cnt);
		printf (", length: %u", hst_resp->h_length);
		printf (", address list count: %u", hst_resp->h_addr_list_cnt);
		printf (", error: %u\n", hst_resp->error);
	}
	consumed += sizeof (*hst_resp);

	printf ("  Name: \"");
	for (int i = 0; i < hst_resp->h_name_len-1; i++)
		printf ("%c", resp_data[i]);
	consumed += hst_resp->h_name_len;

	uint8_t *addr = (uint8_t *) resp_data + hst_resp->h_name_len;

	uint32_t *aliases_len = NULL;
	if (hst_resp->h_aliases_cnt) {
		aliases_len = (uint32_t *) addr;
		int aliases_len_sz = sizeof (uint32_t) * hst_resp->h_aliases_cnt;
		addr += aliases_len_sz;
		consumed += aliases_len_sz;
	}

	printf ("\"\n  Addresses: ");
	if (hst_resp->h_addr_list_cnt) {
		for (int i = 0 ; i < hst_resp->h_addr_list_cnt; i++) {
			printf ("%s ", i > 0 ? "," : "");

			printf ("(%s) ", af2str[hst_resp->h_addrtype]
						? af2str[hst_resp->h_addrtype] : "Unknown");
			print_ip_addr (    type == GETHOSTBYADDR
							|| type == GETHOSTBYNAME
								? AF_INET : AF_INET6, addr);

			addr += hst_resp->h_length;
			consumed += hst_resp->h_length;
		}
	} else
		printf ("none");

	printf ("\n  Aliases: ");
	if (hst_resp->h_aliases_cnt) {
		for (int i = 0 ; i < hst_resp->h_aliases_cnt; i++) {
			printf ("%s ", i > 0 ? "," : "");

			printf ("\"");
			for (int j = 0; j < aliases_len[i] - 1; j++)
				printf ("%c", addr[j]);
			printf ("\"");

			addr += aliases_len[i];
			consumed += aliases_len[i];
		}
	} else
		printf ("none");
	printf ("\n");

	return consumed;
}

ref_t
print_ai_resp_data (ai_response_header *ai_resp,
					char *resp_data, int verbose) {
	ref_t consumed = 0;

	if (verbose) {
		printf (", version: %u", ai_resp->version);
		printf (", %s response\n", ai_resp->found < 0
				? "disabled" : ai_resp->found
					? "positive" : "negative");
		printf (" Number of addresses: %u", ai_resp->naddrs);
		printf (", address length: %u", ai_resp->addrslen);
		printf (", canonical address lenght: %u", ai_resp->canonlen);
		printf (", error: %u\n", ai_resp->error);
	}
	consumed += sizeof (*ai_resp);


	uint8_t *addrs = (uint8_t *) resp_data;
	uint8_t *families = addrs + ai_resp->addrslen;
	printf ("  Addresses: ");
	for (int i = 0 ; i < ai_resp->naddrs; i++) {
		printf ("%s ", i > 0 ? "," : "");
		printf ("(%s) ", af2str[families[i]] ? af2str[families[i]] : "Unknown");
		print_ip_addr (families[i], addrs);
		int addr_sz = families[i] == AF_INET6
			? sizeof (struct in6_addr) : sizeof (struct in_addr);
		addrs += addr_sz;
		consumed += addr_sz;
		consumed += sizeof (families[i]);
	}

	unsigned char *canon = families + sizeof (uint8_t) * ai_resp->naddrs;
	printf ("\n  Canonical name: \"");
	for (int i = 0; i < ai_resp->canonlen - 1; i++)
		printf ("%c", canon[i]);
	printf ("\"");
	consumed += ai_resp->canonlen;
	printf ("\n");

	return consumed;
}

void
print_entries (void *mem, int verbose) {

	struct database_pers_head *head = mem;

	const char *data = (char *) &head->array[roundup (head->module,
					   ALIGN / sizeof (ref_t))];

	nscd_ssize_t he_cnt = 0;
	for (nscd_ssize_t cnt = 0; cnt < head->module; ++cnt) {
		ref_t work = head->array[cnt];

		while (work != ENDREF) {
			struct hashentry *here = (struct hashentry *) (data + work);
			struct datahead *dh = (struct datahead *) (data + here->packet);
			const char *key = data + here->key;

			++he_cnt;

			print_hashentry_datahead (here, dh, key, he_cnt, verbose);

			ref_t consumed = 0;
			if (   here->type == GETHOSTBYNAME
				|| here->type == GETHOSTBYNAMEv6
				|| here->type == GETHOSTBYADDR
				|| here->type == GETHOSTBYADDRv6) {
				hst_response_header hst_resp = dh->data[0].hstdata;
				char *resp_data = (char *) (&dh->data[0].hstdata + 1);
				consumed = print_hst_resp_data (here->type, &hst_resp,
												resp_data, verbose);
			}

			if (here->type == GETAI) {
				ai_response_header ai_resp = dh->data[0].aidata;
				char *resp_data = (char *) (&dh->data[0].aidata + 1);
				consumed = print_ai_resp_data (&ai_resp, resp_data, verbose);
			}

			if (consumed != dh->recsize) {
				fprintf (stderr, "Not all of data is processed for record #%u:"
						 " allocated %u, processed %u\n",
						 he_cnt, dh->recsize, consumed);
			}

			printf ("\n");
			work = here->next;
		}
	}
}

int
main (int argc, char *argv[])
{
	if (!(argc == 2 || argc == 3)) {
		printf ("Usage: nscd_dump [-v] <NSCD persistent database file>\n");
		return 1;
	}

	const char *db_filename;
	int verbose = 0;

	for (argv++; *argv; argv++) {
		if (!strcmp (*argv, "-v")) {
			verbose = 1;
			continue;
		}

		db_filename = *argv;
		continue;
	}

 	/* Try to open the appropriate file on disk. */
	int fd = open (db_filename, O_RDONLY);
	if (fd == -1) {
    	fprintf (stderr, "Cannot access database file \"%s\": %s\n",
				 db_filename, strerror (errno));
    	return 1;
	}

	struct stat64 st;
	void *mem;
	size_t total;
	struct database_pers_head head;

	ssize_t n = read (fd, &head, sizeof (head));
	if (n != sizeof (head)) {
		fprintf (stderr, "Short read on database file \"%s\"\n",
				 db_filename);
		close (fd);
		return 1;
	}

	if (fstat64 (fd, &st) != 0) {
		fprintf (stderr, "fstat() error on database file \"%s\": %s\n",
				 db_filename, strerror (errno));
		close (fd);
		return 1;
	}

	/* The file has been created, but the head has not
	   been initialized yet.  */
	if (head.module == 0 && head.data_size == 0) {
		fprintf (stderr, "Invalid persistent database file \"%s\": "
				"uninitialized header\n",
				db_filename);
		close (fd);
		return 1;
	}
	
	if (head.header_size != (int) sizeof (head)) {
		fprintf (stderr, "Invalid persistent database file \"%s\": "
				"header size does not match\n",
				db_filename);
		close (fd);
		return 1;
	}
	
	if ((total = (sizeof (head)
			   + roundup (head.module * sizeof (ref_t),
					  ALIGN)
			   + head.data_size))
		 > st.st_size
		 || total < sizeof (head)) {
		fprintf (stderr, "Invalid persistent database file \"%s\": "
				"file size does not match\n",
				db_filename);
		close (fd);
		return 1;
	}

	/* Note we map with the maximum size allowed for the
	   database. This is likely much larger than the
	   actual file size.  This is OK on most OSes since
	   extensions of the underlying file will
	   automatically translate more pages available for
	   memory access.
	 */
	if ((mem = mmap (NULL, DEFAULT_MAX_DB_SIZE,
					 PROT_READ,
					 MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
		fprintf (stderr, "mmap() error on database file \"%s\": %s\n",
				 db_filename, strerror (errno));
		close (fd);
		return 1;
	}

	const char *msg = verify_persistent_db (mem, &head);
	if (msg != NULL) {
		fprintf (stderr, "Error validating database file \"%s\": %s\n",
				 db_filename, msg);
		munmap (mem, total);
		close (fd);
		return 1;
	}
	printf ("Database file \"%s\" validated\n\n",	db_filename);

	print_db_header_stats (&head);
	print_entries (mem, verbose);

	munmap (mem, total);
  	close (fd);
}
