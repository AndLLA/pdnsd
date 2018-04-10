/* dns_query.c - Execute outgoing dns queries and write entries to cache

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2004, 2005 Paul A. Rombouts

This file is part of the pdnsd package.

pdnsd is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

pdnsd is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pdsnd; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <config.h>
#include <sys/types.h>
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "list.h"
#include "consts.h"
#include "ipvers.h"
#include "dns_query.h"
#include "cache.h"
#include "dns.h"
#include "conff.h"
#include "servers.h"
#include "helpers.h"
#include "netdev.h"
#include "error.h"
#include "debug.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns_query.c,v 1.59 2002/08/07 08:55:33 tmm Exp $";
#endif

#if defined(NO_TCP_QUERIES) && M_PRESET!=UDP_ONLY
# error "You may not define NO_TCP_QUERIES when M_PRESET is not set to UDP_ONLY"
#endif
#if defined(NO_UDP_QUERIES) && M_PRESET!=TCP_ONLY
# error "You may not define NO_UDP_QUERIES when M_PRESET is not set to TCP_ONLY"
#endif

/* --- structures and state constants for parallel query */
typedef struct {
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in  sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	}                   a;
	time_t              timeout;
	unsigned short      flags;
	short               nocache;
	short               state;
	short               qm;
        char                auth_serv;
	char                lean_query;
	char                needs_testing;
	unsigned char       *nsdomain;
	/* internal state for p_exec_query */
	int                 sock;
/*	dns_cent_t          nent;
	dns_cent_t          servent;*/
	unsigned short      transl;
	unsigned short      recvl;
#ifndef NO_TCP_QUERIES
	int                 iolen;  /* number of bytes written or read up to now */
#endif
	dns_hdr_t           *hdr;
	dns_hdr_t           *recvbuf;
	unsigned short      myrid;
	unsigned short      qt;
	int                 s_errno;
} query_stat_t;
typedef DYNAMIC_ARRAY(query_stat_t) *query_stat_array;


#define QS_INITIAL       0  /* This is the initial state. Set this before starting. */

#define QS_TCPINITIAL    1  /* Start a TCP query. */
#define QS_TCPWRITE      2  /* Waiting to write data. */
#define QS_TCPREAD       3  /* Waiting to read data. */

#define QS_UDPINITIAL    4  /* Start a UDP query */
#define QS_UDPRECEIVE    5  /* UDP query transmitted, waiting for response. */

#define QS_QUERY_CASES   case QS_TCPINITIAL: case QS_TCPWRITE: case QS_TCPREAD: case QS_UDPINITIAL: case QS_UDPRECEIVE

#define QS_CANCELED      7  /* query was started, but canceled before completion */
#define QS_DONE          8  /* done, resources freed, result is in stat_t */


/* Events to be polled/selected for */
#define QS_WRITE_CASES case QS_TCPWRITE
#define QS_READ_CASES  case QS_TCPREAD: case QS_UDPRECEIVE

/*
 * This is for error handling to prevent spewing the log files.
 * Races do not really matter here, so no locks.
 */
#define MAXPOLLERRS 10
volatile unsigned long poll_errs=0;

#define SOCK_ADDR(p) ((struct sockaddr *) &(p)->a)

#ifdef SIN_LEN
#undef SIN_LEN
#endif

#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
#  define SIN_LEN (run_ipv4?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6))
#  define PDNSD_A(p) (run_ipv4?((pdnsd_a *) &(p)->a.sin4.sin_addr):((pdnsd_a *) &(p)->a.sin6.sin6_addr))
# else
#  define SIN_LEN sizeof(struct sockaddr_in)
#  define PDNSD_A(p) ((pdnsd_a *) &(p)->a.sin4.sin_addr)
# endif
#else
#  define SIN_LEN sizeof(struct sockaddr_in6)
#  define PDNSD_A(p) ((pdnsd_a *) &(p)->a.sin6.sin6_addr)
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

typedef DYNAMIC_ARRAY(dns_cent_t) *dns_cent_array;

/*
 * Take the data from an RR and add it to an array of cache entries.
 */
static int rr_to_cache(dns_cent_array *centa, time_t ttl, unsigned char *oname, unsigned dlen, void *data,
		       int tp, unsigned flags, time_t queryts)
{
	int i,n;
	dns_cent_t *cent;

	n=DA_NEL(*centa);
	for(i=0;i<n;++i) {
		cent=&DA_INDEX(*centa,i);
		if (rhnicmp(cent->qname,oname)) {
			/* We already have an entry in the array for this name. add_cent_rr is sufficient. 
			   However, make sure there are no double records. This is done by add_cent_rr */
#ifdef RFC2181_ME_HARDER
			if (cent->rr[tp-T_MIN] && cent->rr[tp-T_MIN]->ttl!=ttl)
				return 0;
#endif
			return add_cent_rr(cent,tp,ttl,queryts,flags,dlen,data  DBG1);
		}
	}

	/* Add a new entry to the array for this name. */
	if (!(*centa=DA_GROW1_F(*centa,free_cent0)))
		return 0;
	cent=&DA_LAST(*centa);
	if (!init_cent(cent,oname, 0, queryts, 0  DBG1)) {
		*centa=DA_RESIZE(*centa,n);
		return 0;
	}
	return add_cent_rr(cent,tp,ttl,queryts,flags,dlen,data  DBG1);
}

/*
 * Takes a pointer (ptr) to a buffer with recnum rrs,decodes them and enters them
 * into a dns_cent_t. *ptr is modified to point after the last rr, and *lcnt is decremented
 * by the size of the rrs.
 */
static int rrs2cent(dns_cent_array *centa, unsigned char **ptr, long *lcnt, int recnum, unsigned char *msg, long msgsz,
		    unsigned flags, time_t queryts)
{
	int rc;
	int i;
	uint16_t type,class; uint32_t ttl; uint16_t rdlength;

	for (i=0;i<recnum;i++) {
		unsigned char oname[256];
		int len;
		if ((rc=decompress_name(msg, msgsz, ptr, lcnt, oname, &len))!=RC_OK) {
			return rc;
		}
		if (*lcnt<sizeof(rr_hdr_t)) {
			return RC_TRUNC;
		}
		*lcnt-=sizeof(rr_hdr_t);
		GETINT16(type,*ptr);
		GETINT16(class,*ptr);
		GETINT32(ttl,*ptr);
		GETINT16(rdlength,*ptr);
		if (*lcnt<rdlength) {
			return RC_TRUNC;
		}

		if (!(type<T_MIN || type>T_MAX || class!=C_IN)) {
			/* skip otherwise */
			/* Some types contain names that may be compressed, so these need to be processed.
			 * the other records are taken as they are
			 * The maximum lenth for a decompression buffer is 530 bytes (maximum SOA record length) */

			switch (type) {
				unsigned char *bptr,*nptr;
				long blcnt;
				int slen;
			case T_CNAME:
			case T_MB:
			case T_MD:
			case T_MF:
			case T_MG:
			case T_MR:
			case T_NS:
			case T_PTR:
			{
				unsigned char db[256];
				blcnt=rdlength;
				bptr=*ptr;  /* make backup for decompression, because rdlength is the authoritative
					       record length and pointer and size will by modified by that */
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, db, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, len, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
			case T_MINFO:
#ifdef DNS_NEW_RRS
			case T_RP:
#endif
			{
				unsigned char db[256+256];
				blcnt=rdlength;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/* PDNSD_ASSERT(len + 256 <= sizeof(db), "T_MINFO/T_RP: buffer limit reached"); */
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
			case T_MX:
#ifdef DNS_NEW_RRS
			case T_AFSDB:
			case T_RT:
			case T_KX:
#endif
			{
				unsigned char db[2+256];
				blcnt=rdlength;
				if (blcnt<2)
					goto record_too_short;
				memcpy(db,*ptr,2); /* copy the preference field*/
				blcnt-=2;
				bptr=*ptr+2;
				nptr=db+2;
				slen=2;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
			case T_SOA:
			{
				unsigned char db[256+256+20];
				blcnt=rdlength;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/* PDNSD_ASSERT(len + 256 <= sizeof(db), "T_SOA: buffer limit reached"); */
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen+=len;
				/* PDNSD_ASSERT(slen + 20 <= sizeof(db), "T_SOA: buffer limit reached"); */
				if (blcnt<20)
					goto record_too_short;
				memcpy(nptr,bptr,20); /*copy the rest of the SOA record*/
				blcnt-=20;
				slen+=20;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
#ifdef DNS_NEW_RRS
			case T_PX:
			{
				unsigned char db[2+256+256];
				blcnt=rdlength;
				if (blcnt<2)
					goto record_too_short;
				memcpy(db,*ptr,2); /* copy the preference field*/
				blcnt-=2;
				bptr=*ptr+2;
				nptr=db+2;
				slen=2;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/* PDNSD_ASSERT(len + 256 <= sizeof(db), "T_PX: buffer limit reached"); */
				nptr+=len;
				slen+=len;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/* nptr+=len; */
				slen+=len;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
			case T_SRV:
			{
				unsigned char db[6+256];
				blcnt=rdlength;
				if (blcnt<6)
					goto record_too_short;
				memcpy(db,*ptr,6);
				blcnt-=6;
				bptr=*ptr+6;
				nptr=db+6;
				slen=6;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
			case T_NXT:
			{
				unsigned char db[1040];
				blcnt=rdlength;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen=len+blcnt;
				if (slen > sizeof(db))
					goto buffer_overflow;
				memcpy(nptr,bptr,blcnt);
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
			case T_NAPTR:
			{
				int j;
				unsigned char db[4 + 4*256];
				blcnt=rdlength;
				bptr=*ptr;
				nptr=db;
				/*
				 * After the preference field, three text strings follow, the maximum length being 255
				 * characters for each (this is ensured by the type of *bptr), plus one length byte for
				 * each, so 3 * 256 = 786 in total. In addition, the name below is up to 256 characters
				 * in size, and the preference field is another 4 bytes in size, so the total length
				 * that can be taken up is 1028 characters. This means that the whole record will always
				 * fit into db.
				 */
				len=4;   /* also copy the preference field*/
				for (j=0;j<3;j++) {
					if (len>=blcnt)
						goto record_too_short;
					len += ((int)bptr[len])+1;
				}
				if(len>blcnt)
					goto record_too_short;
				memcpy(nptr,bptr,len);
				blcnt-=len;
				bptr+=len;
				nptr+=len;
				slen=len;

				/* PDNSD_ASSERT(slen+256 <= sizeof(db), "T_NAPTR: buffer limit reached (name)"); */
				if ((rc=decompress_name(msg, msgsz, &bptr, &blcnt, nptr, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (blcnt!=0)
					goto trailing_junk;
				if (!rr_to_cache(centa, ttl, oname, slen, db, type,flags,queryts))
					return RC_SERVFAIL;
			}
				break;
#endif
			default:
				/* Validate types we use internally */
				if (type==T_A && rdlength!=4)
					goto invalid_length;
#ifdef DNS_NEW_RRS
				if (type==T_AAAA && rdlength!=16)
					goto invalid_length;
#endif
				if (!rr_to_cache(centa, ttl, oname, rdlength, *ptr, type,flags,queryts))
					return RC_SERVFAIL;
			}
		}
		*lcnt-=rdlength;
		*ptr+=rdlength;
	}
	return RC_OK;

 trailing_junk:
	DEBUG_MSG("rrs2cent: %s record has trailing junk.\n",get_tname(type));
	return RC_FORMAT;

 record_too_short:
	DEBUG_MSG("rrs2cent: %s record too short.\n",get_tname(type));
	return RC_FORMAT;

 buffer_overflow:
	DEBUG_MSG("rrs2cent: buffer too small to process %s record.\n",get_tname(type));
	return RC_FORMAT;

 invalid_length:
	DEBUG_MSG("rrs2cent: %s record has length %u.\n",get_tname(type),rdlength);
	return RC_FORMAT;
}

/*
 * Try to bind the socket to a port in the given port range. Returns 1 on success, or 0 on failure.
 */
static int bind_socket(int s)
{
	int query_port_start=global.query_port_start,query_port_end=global.query_port_end;

	/*
	 * 0, as a special value, denotes that we let the kernel select an address when we
	 * first use the socket, which is the default.
	 */
	if (query_port_start > 0) {
		union {
#ifdef ENABLE_IPV4
			struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
			struct sockaddr_in6 sin6;
#endif
		} sin;
		socklen_t sinl;
		int i,j, range = query_port_end-query_port_start+1;

		if (range<=0) {
			log_warn("Illegal port range in %s line %d, dropping query!\n",__FILE__,__LINE__);
			return 0;
		}
		for (j=i=(get_rand16()%range)+query_port_start;;) {
#ifdef ENABLE_IPV4
			if (run_ipv4) {
				memset(&sin.sin4,0,sizeof(struct sockaddr_in));
				sin.sin4.sin_family=AF_INET;
				sin.sin4.sin_port=htons(i);
				SET_SOCKA_LEN4(sin.sin4);
				sinl=sizeof(struct sockaddr_in);
			}
#endif
#ifdef ENABLE_IPV6
			ELSE_IPV6 {
				memset(&sin.sin6,0,sizeof(struct sockaddr_in6));
				sin.sin6.sin6_family=AF_INET6;
				sin.sin6.sin6_port=htons(global.port);
				sin.sin6.sin6_flowinfo=IPV6_FLOWINFO;
				SET_SOCKA_LEN6(sin.sin6);
				sinl=sizeof(struct sockaddr_in6);
			}
#endif
			if (bind(s,(struct sockaddr *)&sin,sinl)==-1) {
				if (errno!=EADDRINUSE &&
				    errno!=EADDRNOTAVAIL) { /* EADDRNOTAVAIL should not happen here... */
					log_warn("Could not bind to socket: %s\n", strerror(errno));
					return 0;
				}
				/* If the address is in use, we continue. */
			} else
				break;	/* done. */
			if (++i>query_port_end)
				i=query_port_start;
			if (i==j) {
				/* Wraparound, scanned the whole range. Give up. */
				log_warn("Out of ports in the given range, dropping query!\n");
				return 0;
			}
		}
	}
	return 1;
}

/* ------ following is the parallel query code.
 * It has been observed that a whole lot of name servers are just damn lame, with response time
 * of about 1 min. If that slow one is by chance the first server we try, serializing the tries is quite
 * sub-optimal. Also when doing serial queries, the timeout values given in the config will add up, which
 * is not the Right Thing. Now that serial queries are in place, this is still true for CNAME recursion,
 * and for recursion in quest for the holy AA, but not totally for querying multiple servers.
 * The impact on network bandwith should be only marginal (given todays bandwith).
 *
 * The actual strategy is to do (max) PAR_QUERIES parallel queries, and, if these time out or fail, do again
 * that number of queries, until we are successful or there are no more servers to query.
 * Since the memory footprint of a thread is considerably large on some systems, and because we have better
 * control, we will do the parallel queries multiplexed in one thread.
 */

/* The query state machine that is called from p_exec_query. This is called once for initialization (state
 * QS_TCPINITIAL or QS_UDPINITIAL is preset), and the state that it gives back may either be state QS_DONE, 
 * in which case it must return a return code other than -1 and is called no more for this server 
 * (except perhaps in UDP mode if TCP failed). If p_query_sm returns -1, then the state machine is in a read
 * or write state, and a function higher up the calling chain can setup a poll() or select() together with st->sock. 
 * If that poll/select is succesful for that socket, p_exec_query is called again and will hand over to p_query_sm. 
 * So, you can assume that read(), write() and recvfrom() will not block at the start of a state handling when you 
 * have returned -1 (which means "call again") as last step of the last state handling. */
static int p_query_sm(query_stat_t *st)
{
	int rv;

	switch (st->state){
		/* TCP query code */
#ifndef NO_TCP_QUERIES
	case QS_TCPINITIAL:
		if ((st->sock=socket(PDNSD_PF_INET,SOCK_STREAM,IPPROTO_TCP))==-1) {
			DEBUG_MSG("Could not open socket: %s\n", strerror(errno));
			break;
		}
		/* sin4 or sin6 is intialized, hopefully. */

		/* maybe bind */
		if (!bind_socket(st->sock)) {
			close(st->sock);
			break;
		}

		/* transmit query by tcp*/
		/* make the socket non-blocking */
		{
			int oldflags = fcntl(st->sock, F_GETFL, 0);
			if (oldflags == -1 || fcntl(st->sock,F_SETFL,oldflags|O_NONBLOCK)==-1) {
				close(st->sock);
				DEBUG_PDNSDA_MSG("fcntl error while trying to make socket to %s non-blocking: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
				break;
			}
 		}
		st->iolen=0;
		if (connect(st->sock,SOCK_ADDR(st),SIN_LEN)==-1) {
			if (errno==EINPROGRESS || errno==EPIPE) {
				st->state=QS_TCPWRITE;
				/* st->event=QEV_WRITE; */ /* wait for writability; the connect is then done */
				return -1;
			} else if (errno==ECONNREFUSED) {
				st->s_errno=errno;
				close(st->sock);
				st->state=QS_DONE;
				return RC_TCPREFUSED;
			} else {
				/* Since immediate connect() errors do not cost any time, we do not try to switch the
				 * server status to offline */
				close(st->sock);
				DEBUG_PDNSDA_MSG("Error while connecting to %s: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
				break;
			}
		}
		st->state=QS_TCPWRITE;
		/* st->event=QEV_WRITE; */
		/* fall through in case of not EINPROGRESS */
	case QS_TCPWRITE:
		if(st->iolen==0) {
			uint16_t transl_net=htons(st->transl);
			rv=write(st->sock,&transl_net,sizeof(transl_net));
			if(rv==-1) {
				if(errno==EWOULDBLOCK)
					return -1;
				st->s_errno=errno;
				if (errno==ECONNREFUSED || errno==EPIPE) {
					/* This error may be delayed from connect() */
					close(st->sock);
					st->state=QS_DONE;
					return RC_TCPREFUSED;
				}
			}
			if(rv!=sizeof(transl_net)) {
				close(st->sock);
				DEBUG_PDNSDA_MSG("Error while sending data to %s: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
				break;
			}
			st->iolen=rv;
		}
		{
			int offset=st->iolen-sizeof(uint16_t);
			int rem=st->transl-offset;
			if(rem>0) {
				rv=write(st->sock,((unsigned char*)st->hdr)+offset,rem);
				if(rv==-1) {
					if(errno==EWOULDBLOCK)
						return -1;
					st->s_errno=errno;
					close(st->sock);
					DEBUG_PDNSDA_MSG("Error while sending data to %s: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
					break;
				}
				st->iolen += rv;
				if(rv<rem)
					return -1;
			}
		}
		st->state=QS_TCPREAD;
		st->iolen=0;
		/* st->event=QEV_READ; */
		/* fall through */
	case QS_TCPREAD:
	        if(st->iolen==0) {
			uint16_t recvl_net;
			rv=read(st->sock,&recvl_net,sizeof(recvl_net));
			if(rv==-1 && errno==EWOULDBLOCK)
				return -1;
			if(rv!=sizeof(recvl_net))
				goto error_receiv_data;
			st->iolen=rv;
			st->recvl=ntohs(recvl_net);
			if(!(st->recvbuf=(dns_hdr_t *)pdnsd_realloc(st->recvbuf,st->recvl))) {
				close(st->sock);
				DEBUG_MSG("Out of memory in query.\n");
				break;
			}
		}
		{
			int offset=st->iolen-sizeof(uint16_t);
			int rem=st->recvl-offset;
			if(rem>0) {
				rv=read(st->sock,((unsigned char*)st->recvbuf)+offset,rem);
				if(rv==-1) {
					if(errno==EWOULDBLOCK)
						return -1;
					goto error_receiv_data;
				}
				if(rv==0)
					goto error_receiv_data; /* unexpected EOF */
				st->iolen += rv;
				if(rv<rem)
					return -1;
			}
		}
		close(st->sock);
		st->state=QS_DONE;
		return RC_OK;
	error_receiv_data:
		if(rv==-1) st->s_errno=errno;
		close(st->sock);
		DEBUG_PDNSDA_MSG("Error while receiving data from %s: %s\n", PDNSDA2STR(PDNSD_A(st)),rv==-1?strerror(errno):"incomplete data");
		break;
#endif

#ifndef NO_UDP_QUERIES
		/* UDP query code */
	case QS_UDPINITIAL:
		if ((st->sock=socket(PDNSD_PF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1) {
			DEBUG_MSG("Could not open socket: %s\n", strerror(errno));
			break;
		}

		/* maybe bind */
		if (!bind_socket(st->sock)) {
			close(st->sock);
			break;
		}

		/* connect */
		if (connect(st->sock,SOCK_ADDR(st),SIN_LEN)==-1) {
			if (errno==ECONNREFUSED) st->s_errno=errno;
			close(st->sock);
			DEBUG_PDNSDA_MSG("Error while connecting to %s: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
			break;
		}

		/* transmit query by udp*/
		/* send will hopefully not block on a freshly opened socket (the buffer
		 * must be empty) */
		if (send(st->sock,st->hdr,st->transl,0)==-1) {
			st->s_errno=errno;
			close(st->sock);
			DEBUG_PDNSDA_MSG("Error while sending data to %s: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
			break;
		}
		st->state=QS_UDPRECEIVE;
		/* st->event=QEV_READ; */
		return -1;
	case QS_UDPRECEIVE:
		if(!(st->recvbuf=(dns_hdr_t *)pdnsd_realloc(st->recvbuf,512))) {
			close(st->sock);
			DEBUG_MSG("Out of memory in query.\n");
			break;
		}
		if ((rv=recv(st->sock,st->recvbuf,512,0))==-1) {
			st->s_errno=errno;
			close(st->sock);
			DEBUG_PDNSDA_MSG("Error while receiving data from %s: %s\n", PDNSDA2STR(PDNSD_A(st)),strerror(errno));
			break;
		}
		st->recvl=rv;
		if (st->recvl<sizeof(dns_hdr_t) || ntohs(st->recvbuf->id)!=st->myrid) {
			DEBUG_MSG("Bad answer received. Ignoring it.\n");
			/* no need to care about timeouts here. That is done at an upper layer. */
			st->state=QS_UDPRECEIVE;
			/* st->event=QEV_READ; */
			return -1;
		}
		close(st->sock);
		st->state=QS_DONE;
		return RC_OK;
#endif
	}

	/* If we get here, something has gone wrong */
	st->state=QS_DONE;
	return RC_SERVFAIL; /* mock error code */
}

inline static dns_cent_t *lookup_cent_array(dns_cent_array ca, const unsigned char *nm)
{
	int i,n=DA_NEL(ca);
	for(i=0;i<n;++i) {
		dns_cent_t *ce=&DA_INDEX(ca,i);
		if(rhnicmp(ce->qname,nm))
			return ce;
	}
	return NULL;
}

/* Extract the minimum ttl field from the SOA record stored in an rr bucket. */
static time_t soa_minimum(rr_bucket_t *rrs)
{
	uint32_t minimum;
	unsigned char *p=(unsigned char *)(rrs+1);

	/* Skip owner and maintainer. Lengths are validated in cache */
	p=skiprhn(skiprhn(p));
	/* Skip serial, refresh, retry, expire fields. */
	p += 4*sizeof(uint32_t);
	GETINT32(minimum,p);
	return minimum;
}

/*
 * The function that will actually execute a query. It takes a state structure in st.
 * st->state must be set to QS_INITIAL before calling. 
 * This may return one of the RC_* codes, where RC_OK indicates success, the other
 * RC codes indicate the appropriate errors. -1 is the return value that indicates that
 * you should call p_exec_query again with the same state for the result until you get
 * a return value >0. Alternatively, call p_cancel_query to cancel it.
 * Timeouts are already handled by this function.
 * Any records that the query has yielded and that are not a direct answer to the query
 * (i.e. are records for other domains) are added to the cache, while the direct answers
 * are returned in ent.
 * All ns records, to whomever they might belong, are additionally returned in the ns list.
 * Free it when done.
 * This function calls another query state machine function that supports TCP and UDP.
 *
 * If you want to tell me that this function has a truly ugly coding style, ah, well...
 * You are right, somehow, but I feel it is conceptually elegant ;-)
 */
static int p_exec_query(dns_cent_t **entp, unsigned char *name, int *aa,
			query_stat_t *st, dlist *ns, unsigned char *c_soa)
{
	int rv;

	switch (st->state){
	case QS_INITIAL: {
		unsigned int rrnlen=0;
		if (!st->lean_query)
			st->qt=QT_ALL;
		st->transl=sizeof(dns_hdr_t);
		if(name) {
			rrnlen=rhnlen(name);
			st->transl += rrnlen+4;
		}
		st->hdr=(dns_hdr_t *)pdnsd_malloc(st->transl);
		if (!st->hdr) {
			st->state=QS_DONE;
 			return RC_SERVFAIL; /* mock error code */
		}
		st->myrid=get_rand16();
		st->hdr->id=htons(st->myrid);
		st->hdr->qr=QR_QUERY;
		st->hdr->opcode=OP_QUERY;
		st->hdr->aa=0;
		st->hdr->tc=0;
		/* If nsdomain is NULL, it means we trust this nameserver. */
		st->hdr->rd=(name && !st->nsdomain);
		st->hdr->ra=0;
		st->hdr->z1=0;
		st->hdr->au=0;
		st->hdr->z2=0;
		st->hdr->rcode=RC_OK;
		st->hdr->qdcount=htons(name!=NULL);
		st->hdr->ancount=0;
		st->hdr->nscount=0;
		st->hdr->arcount=0;
		if(name) {
			unsigned char *p = mempcpy((unsigned char *)(st->hdr+1),name,rrnlen);
			PUTINT16(st->qt,p);
			PUTINT16(C_IN,p);
		}
		st->recvbuf=NULL;
		st->state=((st->qm==UDP_ONLY)?QS_UDPINITIAL:QS_TCPINITIAL);
		/* fall through */
	}
	QS_QUERY_CASES:
	tryagain:
		rv=p_query_sm(st);
		if (rv==-1) {
			return -1;
		}
		if (rv!=RC_OK) {
			if (rv==RC_TCPREFUSED) {
				if(st->qm==TCP_UDP) {
					st->qm=UDP_ONLY;
					st->myrid=get_rand16();
					st->hdr->id=htons(st->myrid);
					st->state=QS_UDPINITIAL;
					DEBUG_PDNSDA_MSG("TCP connection refused by %s. Trying to use UDP.\n", PDNSDA2STR(PDNSD_A(st)));
					goto tryagain;
				}
				DEBUG_PDNSDA_MSG("TCP connection refused by %s\n", PDNSDA2STR(PDNSD_A(st)));
				rv=RC_SERVFAIL;
			}
			pdnsd_free(st->hdr);
			pdnsd_free(st->recvbuf);
			st->state=QS_DONE;
			if(st->needs_testing) {
				switch(st->s_errno) {
				case ENETUNREACH:  /* network unreachable */
				case EHOSTUNREACH: /* host unreachable */
				case ENOPROTOOPT:  /* protocol unreachable */
				case ECONNREFUSED: /* port unreachable */
				case ENETDOWN:     /* network down */
				case EHOSTDOWN:    /* host down */
#ifdef ENONET
				case ENONET:       /* machine not on the network */
#endif
					/* Mark this server as down for a period of time */
					sched_server_test(PDNSD_A(st),1,0);
					st->needs_testing=0;
				}
			}
			return rv;
		}
		/* rv==RC_OK */
		DEBUG_DUMP_DNS_MSG(PDNSD_A(st), st->recvbuf, st->recvl);

		/* Basic sanity checks */
		if (st->recvl>=sizeof(dns_hdr_t) && ntohs(st->recvbuf->id)==st->myrid &&
		    st->recvbuf->qr==QR_RESP && st->recvbuf->opcode==OP_QUERY &&
		    !st->recvbuf->z1 && !st->recvbuf->z2)
		{
			if(st->needs_testing) {
				/* We got an answer from this server, so don't bother with up tests for a while. */
				sched_server_test(PDNSD_A(st),1,1);
				st->needs_testing=0;
			}

			rv=st->recvbuf->rcode;
			if(rv==RC_OK || rv==RC_NAMEERR) {
				/* success or at least no requery is needed */
				st->state=QS_DONE;
				break;
			}
			else if (rv==RC_NOTSUPP && st->hdr->rd && !st->recvbuf->ra) {
				/* seems as if we have got no recursion available.
				   We will have to do it by ourselves (sigh...) */
				st->hdr->rd=0;
				st->myrid=get_rand16();
				st->hdr->id=htons(st->myrid);
				st->state=((st->qm==UDP_ONLY)?QS_UDPINITIAL:QS_TCPINITIAL);
				DEBUG_PDNSDA_MSG("Server %s does not support recursive query. Querying non-recursively.\n", PDNSDA2STR(PDNSD_A(st)));
				goto tryagain;
			} 
		}
		/* report failure */
		pdnsd_free(st->hdr);
		pdnsd_free(st->recvbuf);
		/*close(st->sock);*/
		st->state=QS_DONE;
		if (rv!=RC_OK) {
			DEBUG_PDNSDA_MSG("Server %s returned error code: %s\n", PDNSDA2STR(PDNSD_A(st)),get_ename(rv));
			return rv;
		}
		DEBUG_PDNSDA_MSG("Server %s returned invalid answer\n", PDNSDA2STR(PDNSD_A(st)));
		return RC_SERVFAIL; /* mock error code */

	default: /* we shouldn't get here */
		st->state=QS_DONE;
		return RC_SERVFAIL; /* mock error code */
	}

        /* If we reach this code, we have successfully received an answer,
	 * because we have returned error codes on errors or -1 on AGAIN.
	 * conditions.
	 * So we *should* have a correct dns record in recvbuf by now.
	 */
	pdnsd_free(st->hdr);
	if(name) {
		time_t queryts=time(NULL);
		long lcnt=st->recvl;
		unsigned char *rrp=(unsigned char *)(st->recvbuf+1);
		dns_cent_array secs[3]={NULL,NULL,NULL};
#		define ans_sec  secs[0]
#		define auth_sec secs[1]
#		define add_sec  secs[2]
		dns_cent_t *ent;

		lcnt-=sizeof(dns_hdr_t);
		if (ntohs(st->recvbuf->qdcount)!=1) {
			DEBUG_PDNSDA_MSG("Bad number of query records in answer from %s\n",
					 PDNSDA2STR(PDNSD_A(st)));
			rv=RC_SERVFAIL;
			goto free_recvbuf_return;
		}
		/* check & skip the query record. */
		{
			unsigned char nbuf[256];
			if ((rv=decompress_name((unsigned char *)st->recvbuf, st->recvl, &rrp, &lcnt, nbuf, NULL))!=RC_OK) {
				DEBUG_PDNSDA_MSG("Cannot decompress QNAME in answer from %s\n",
						 PDNSDA2STR(PDNSD_A(st)));
				rv=RC_SERVFAIL;
				goto free_recvbuf_return;
			}
			if(!rhnicmp(nbuf,name)) {
				DEBUG_PDNSDA_MSG("Answer from %s does not match query.\n",
						 PDNSDA2STR(PDNSD_A(st)));
				rv=RC_SERVFAIL;
				goto free_recvbuf_return;
			}
		}

		if (lcnt<4) {
			rv=RC_SERVFAIL; /* mock error code */
			goto free_recvbuf_return;
		}
		rrp+=4; /* two shorts (qtype and qclass);*/
		lcnt-=4;

		if ((*aa=st->recvbuf->aa))
			st->flags|=CF_AUTH;

		/* Initialize a dns_cent_t in the array for the answer section */
		if (!(ans_sec=DA_GROW1(ans_sec))) {
			rv=RC_SERVFAIL; /* mock error code */
			goto free_recvbuf_return;
		}
		ent=&DA_INDEX(ans_sec,0);
		/* By marking DF_AUTH, we mean authoritative AND complete. */
		if (!init_cent(ent,name, 0, queryts, (*aa && st->qt==QT_ALL)?DF_AUTH:0  DBG1)) {
			rv=RC_SERVFAIL; /* mock error code */
			goto free_centarrays_recvbuf_return;
		}

		/* Now read the answer, authority and additional sections,
		   storing the results in the arrays ans_sec,auth_sec and add_sec.
		*/
		rv=rrs2cent(&ans_sec,&rrp,&lcnt,ntohs(st->recvbuf->ancount), (unsigned char *)st->recvbuf,st->recvl,
			    st->flags, queryts);

		if(rv==RC_OK) {
			uint16_t nscount=ntohs(st->recvbuf->nscount);
			if (nscount) {
				rv=rrs2cent(&auth_sec,&rrp,&lcnt,nscount, (unsigned char *)st->recvbuf,st->recvl,
					    st->flags|CF_ADDITIONAL, queryts);
			}
		}

		if(rv==RC_OK) {
			uint16_t arcount=ntohs(st->recvbuf->arcount);
			if (arcount) {
				rv=rrs2cent(&add_sec,&rrp,&lcnt,arcount, (unsigned char *)st->recvbuf,st->recvl,
					    st->flags|CF_ADDITIONAL, queryts);
			}
		}

		if(!(rv==RC_OK || (rv==RC_TRUNC && st->recvbuf->tc))) {
			DEBUG_PDNSDA_MSG(rv==RC_FORMAT?"Format error in reply from %s.\n":
					 rv==RC_TRUNC?"Format error in reply from %s (message unexpectedly truncated).\n":
					 "Out of memory while processing reply from %s.\n",
					 PDNSDA2STR(PDNSD_A(st)));
			rv=RC_SERVFAIL;
			goto free_ent_centarrays_recvbuf_return;
		}

		{
			/* Remember references to NS and SOA records in the answer or authority section
			   so that we can add this information to our own reply. */
			int i,n=DA_NEL(ans_sec);
			for(i=0;i<n;++i) {
				dns_cent_t *cent=&DA_INDEX(ans_sec,i);
				unsigned scnt=rhnsegcnt(cent->qname);

				if(cent->rr[T_NS-T_MIN])
					cent->c_ns=scnt;
				if(cent->rr[T_SOA-T_MIN])
					cent->c_soa=scnt;
				
				if((st->qt>=QT_MIN && st->qt<=QT_MAX) ||
				   ((st->qt>=T_MIN && st->qt<=T_MAX) && cent->rr[st->qt-T_MIN]) ||
				   (n==1 && cent->num_rrs==0))
				{
					/* Match this name with names in the authority section */
					int j,m=DA_NEL(auth_sec);
					for(j=0;j<m;++j) {
						dns_cent_t *ce=&DA_INDEX(auth_sec,j);
						int ml,rem;
						ml=domain_match(ce->qname,cent->qname, &rem, NULL);
						if(rem==0 &&
						   /* Don't accept records for the root domain from name servers
						      that were not listed in the configuration file. */
						   (ml || st->auth_serv!=2)) {
							if(ce->rr[T_NS-T_MIN]) {
								if(cent->c_ns==cundef || cent->c_ns<ml)
									cent->c_ns=ml;
							}
							if(ce->rr[T_SOA-T_MIN]) {
								if(cent->c_soa==cundef || cent->c_soa<ml)
									cent->c_soa=ml;
							}
						}
					}
				}
			}
		}

		/* negative caching for domains */
		if ((rv=st->recvbuf->rcode)==RC_NAMEERR) {
			DEBUG_PDNSDA_MSG("Server %s returned error code: %s\n", PDNSDA2STR(PDNSD_A(st)),get_ename(rv));
		name_error:
			{
				/* We did not get what we wanted. Cache according to policy */
				int neg_domain_pol=global.neg_domain_pol;
				if (neg_domain_pol==C_ON || (neg_domain_pol==C_AUTH && st->recvbuf->aa)) {
					time_t ttl=global.neg_ttl;

					/* Try to find a SOA record that came with the reply.
					 */
					if(ent->c_soa!=cundef) {
						unsigned scnt=rhnsegcnt(name);
						dns_cent_t *cent;
						if(ent->c_soa<scnt && (cent=lookup_cent_array(auth_sec,skipsegs(name,scnt-ent->c_soa)))) {
							rr_set_t *rrset=cent->rr[T_SOA-T_MIN];
							if (rrset && rrset->rrs) {
								time_t min=soa_minimum(rrset->rrs);
								ttl=rrset->ttl;
								if(ttl>min)
									ttl=min;
							}
						}
					}
					DEBUG_RHN_MSG("Caching domain %s negative with ttl %li\n",RHN2STR(name),(long)ttl);
					negate_cent(ent);
					ent->ttl=ttl;
					goto cleanup_return_OK;
				} else {
					if(c_soa) *c_soa=ent->c_soa;
					free_cent(ent  DBG1);
					rv=RC_NAMEERR;
					goto add_additional;
				}
			}
		}
		if(global.deleg_only_zones && st->auth_serv<3) { /* st->auth_serv==3 means this server is a root-server. */
			int missingdelegation,authcnt;
			/* The deleg_only_zones data may change due to runtime reconfiguration,
			   therefore use locks. */
			lock_server_data();
			missingdelegation=0; authcnt=0;
			{
				int i,n=DA_NEL(global.deleg_only_zones),rem,zrem;
				for(i=0;i<n;++i) {
					if(domain_match(name,DA_INDEX(global.deleg_only_zones,i),&rem,&zrem) && zrem==0)
						goto zone_match;
				}
				goto delegation_OK;
			zone_match:
				/* The name queried matches a delegation-only zone. */
				if(rem) {
					/* Check if we can find delegation in the answer or authority section. */
					/* dns_cent_array secs[2]={ans_sec,auth_sec}; */
					int j;
					for(j=0;j<2;++j) {
						dns_cent_array sec=secs[j];
						int k,m=DA_NEL(sec);
						for(k=0;k<m;++k) {
							dns_cent_t *ce=&DA_INDEX(sec,k);
							if(ce->rr[T_NS-T_MIN] || ce->rr[T_SOA-T_MIN]) {
								/* Found a NS or SOA record in the answer or authority section. */
								int l;
								++authcnt;
								for(l=0;l<n;++l) {
									if(domain_match(ce->qname,DA_INDEX(global.deleg_only_zones,l),&rem,&zrem) && zrem==0) {
										if(rem) break;
										else    goto try_next_auth;
									}
								}
								goto delegation_OK;
							}
						try_next_auth:;	
						}
					}
#if DEBUG>0
					{
						char nmbuf[256],zbuf[256];
						DEBUG_PDNSDA_MSG(authcnt?"%s is in %s zone, but no delegation found in answer returned by server %s\n"
								 :"%s is in %s zone, but no authority information provided by server %s\n",
								 rhn2str(name,nmbuf,sizeof(nmbuf)), rhn2str(DA_INDEX(global.deleg_only_zones,i),zbuf,sizeof(zbuf)),
								 PDNSDA2STR(PDNSD_A(st)));
					}
#endif
					missingdelegation=1;
				}
			delegation_OK:;
			}
			unlock_server_data();

			if(missingdelegation) {
				if(authcnt) {
					/* Treat this as a nonexistant name. */
					goto name_error;
				}
				else if(st->auth_serv<2) {
					/* If this is one of the servers obtained from the list
					   pdnsd was configured with, treat this as a failure.
					   Hopefully one of the other servers in the list will
					   return a non-empty authority section.
					*/
					rv=RC_SERVFAIL;
					goto free_ent_centarrays_recvbuf_return;
				}
			}
		}

		/* Negative caching of rr sets */
		if (st->qt>=T_MIN && st->qt<=T_MAX && !ent->rr[st->qt-T_MIN]) {
			/* We did not get what we wanted. Cache according to policy */
			int neg_rrs_pol=global.neg_rrs_pol;
			if (neg_rrs_pol==C_ON || (neg_rrs_pol==C_AUTH && st->recvbuf->aa)) {
				time_t ttl=global.neg_ttl;
				rr_set_t *rrset=ent->rr[T_SOA-T_MIN];
				dns_cent_t *cent;
				unsigned scnt;
				/* If we received a SOA, we should take the ttl of that record. */
				if ((rrset && rrset->rrs) ||
				    /* Try to find a SOA record higher up the hierarchy that came with the reply. */
				    ((cent=lookup_cent_array(auth_sec,
							     (ent->c_soa!=cundef && ent->c_soa<(scnt=rhnsegcnt(name)))?
							     skipsegs(name,scnt-ent->c_soa):
							     name)) && 
				     (rrset=cent->rr[T_SOA-T_MIN]) && rrset->rrs))
				{
					time_t min=soa_minimum(rrset->rrs);
					ttl=rrset->ttl;
					if(ttl>min)
						ttl=min;
				}
				DEBUG_RHN_MSG("Caching type %s for domain %s negative with ttl %li\n",get_tname(st->qt),RHN2STR(name),(long)ttl);
				if (!add_cent_rrset(ent, st->qt, ttl, queryts, CF_NEGATIVE|st->flags  DBG1)) {
					rv=RC_SERVFAIL;
					goto free_ent_centarrays_recvbuf_return;
				}
			}
		}
		{
			/* The domain names of all name servers found in the answer and authority sections are placed in *ns,
			   which is automatically grown. */
			/* dns_cent_array secs[2]={ans_sec,auth_sec}; */
			int i;
			for(i=0;i<2;++i) {
				dns_cent_array sec=secs[i];
				int j,n=DA_NEL(sec);
				for(j=0;j<n;++j) {
					dns_cent_t *cent=&DA_INDEX(sec,j);
					int rem;
					/* Don't accept records for the root domain from name servers
					   that were not listed in the configuration file. */
					if((*(cent->qname) || st->auth_serv!=2) &&
					   /* Don't accept possibly poisoning nameserver entries in paranoid mode */
					   (!st->nsdomain || (domain_match(st->nsdomain, cent->qname, &rem,NULL),rem==0))) {
						/* Some nameservers obviously choose to send SOA records instead of NS ones.
						 * Although I think that this is poor behaviour, we'll have to work around that. */
						static const unsigned short nstypes[2]={T_NS,T_SOA};
						int k;
						for(k=0;k<2;++k) {
							rr_set_t *rrset=cent->rr[nstypes[k]-T_MIN];
							if(rrset) {
								rr_bucket_t *rr=rrset->rrs;
								while(rr) {
									size_t sz1,sz2;
									unsigned char *p;
									/* Skip duplicate records */
									for(p=dlist_first(*ns); p; p=dlist_next(p)) {
										if(rhnicmp(skiprhn(p),(unsigned char *)(rr+1)))
											goto next_nsr;
									}
									/* add to the nameserver list. */
									sz1=rhnlen(cent->qname);
									sz2=rhnlen((unsigned char *)(rr+1));
									if (!(*ns=dlist_grow(*ns,sz1+sz2))) {
										rv=RC_SERVFAIL;
										goto free_ent_centarrays_recvbuf_return;
									}
									p=dlist_last(*ns);
									p=mempcpy(p,cent->qname,sz1);
									/* This will only copy the first name, which is the NS */
									memcpy(p,(unsigned char *)(rr+1),sz2);
								next_nsr:
									rr=rr->next;
								}
							}
						}
					}
				}
			}
		}
	cleanup_return_OK:
		if(!(*entp=malloc(sizeof(dns_cent_t)))) {
			rv=RC_SERVFAIL;
			goto free_ns_ent_centarrays_recvbuf_return;
		}
		**entp=*ent;
		rv=RC_OK;
	add_additional:
		{
			/* Add the additional RRs to the cache. */
			/* dns_cent_array secs[3]={ans_sec,auth_sec,add_sec}; */
			int i;
			for(i=0;i<3;++i) {
				dns_cent_array sec=secs[i];
				int j,n=DA_NEL(sec);
				/* The first entry in the answer section is treated separately, so skip that one. */
				for(j= !i; j<n; ++j) {
					dns_cent_t *cent=&DA_INDEX(sec,j);
					if(*(cent->qname) || st->auth_serv!=2) {
						int rem;
						if(!st->nsdomain || (domain_match(st->nsdomain, cent->qname, &rem, NULL),rem==0))
							add_cache(cent);
						else {
#if DEBUG>0
							char nmbuf[256],nsbuf[256];
							DEBUG_MSG("Record for %s not in nsdomain %s; dropped.\n",
								  rhn2str(cent->qname,nmbuf,sizeof(nmbuf)),rhn2str(st->nsdomain,nsbuf,sizeof(nsbuf)));
#endif
						}
					}
					else {
#if DEBUG>0
						static const char *secname[3]={"answer","authority","additional"};
						DEBUG_PDNSDA_MSG("Record(s) for root domain in %s section from %s dropped.\n", secname[i],PDNSDA2STR(PDNSD_A(st)));
#endif
					}
				}
			}
		}
		goto free_centarrays_recvbuf_return;

	free_ns_ent_centarrays_recvbuf_return:
		dlist_free(*ns); *ns=NULL;
	free_ent_centarrays_recvbuf_return:
		if(DA_NEL(ans_sec)>=1) free_cent(ent  DBG1);
	free_centarrays_recvbuf_return:
		{
			/* dns_cent_array secs[3]={ans_sec,auth_sec,add_sec}; */
			int i;
			for(i=0;i<3;++i) {
				dns_cent_array sec=secs[i];
				int j,n=DA_NEL(sec);
				/* The first entry in the answer section is treated separately, so skip that one. */
				for(j= !i; j<n; ++j)
					free_cent(&DA_INDEX(sec,j)  DBG1);
			}
		}
		da_free(ans_sec); da_free(auth_sec); da_free(add_sec);
#undef          ans_sec
#undef          auth_sec
#undef          add_sec
	}
 free_recvbuf_return:
	pdnsd_free(st->recvbuf);
	return rv;
}

/*
 * Cancel a query, freeing all resources. Any query state is valid as input (this may even be called
 * if a call to p_exec_query already returned error or success) 
 */
static void p_cancel_query(query_stat_t *st)
{
	switch (st->state) {
	QS_WRITE_CASES:
	QS_READ_CASES:
		close(st->sock);
		/* fall through */
	case QS_TCPINITIAL:
	case QS_UDPINITIAL:
		pdnsd_free(st->recvbuf);
		pdnsd_free(st->hdr);
	}
	if(st->state!=QS_INITIAL && st->state!=QS_DONE)
		st->state=QS_CANCELED;
}

/*
 * Initialize a query_serv_t (server list for parallel query)
 * This is there for historical reasons only.
 */
inline static void init_qserv(query_stat_array *q)
{
	*q=NULL;
}

/*
 * Add a server entry to a query_serv_t
 * Note: only a reference to nsdomain is copied, not the name itself.
 * Be sure to free the q-list before freeing the name.
 */
static int add_qserv(query_stat_array *q, pdnsd_a *a, int port, time_t timeout, unsigned flags,
		     int nocache, int thint, char lean_query, char auth_s, char needs_testing, unsigned char *nsdomain)
{
	query_stat_t *qs;

	if ((*q=DA_GROW1(*q))==NULL)
		return 0;

	qs=&DA_LAST(*q);
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		memset(&qs->a.sin4,0,sizeof(qs->a.sin4));
		qs->a.sin4.sin_family=AF_INET;
		qs->a.sin4.sin_port=htons(port);
		qs->a.sin4.sin_addr=a->ipv4;
		SET_SOCKA_LEN4(qs->a.sin4);
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		memset(&qs->a.sin6,0,sizeof(qs->a.sin6));
		qs->a.sin6.sin6_family=AF_INET6;
		qs->a.sin6.sin6_port=htons(port);
		qs->a.sin6.sin6_flowinfo=IPV6_FLOWINFO;
		qs->a.sin6.sin6_addr=a->ipv6;
		SET_SOCKA_LEN6(qs->a.sin6);
	}
#endif
	qs->timeout=timeout;
	qs->flags=flags;
	qs->nocache=nocache;
	qs->qt=thint;
	qs->lean_query=lean_query;
	qs->auth_serv=auth_s;
	qs->needs_testing=needs_testing;
	qs->nsdomain=nsdomain; /* Note: only a reference is copied, not the name itself! */
	qs->state=QS_INITIAL;
	qs->qm=global.query_method;
	qs->s_errno=0;
	return 1;
}

/*
 * Free resources used by a query_serv_t
 * There for historical reasons only.
 */
inline static void del_qserv(query_stat_array q)
{
	da_free(q);
}

struct qstatnode_s {
	query_stat_array    qa;
	struct qstatnode_s  *next;
};
typedef struct qstatnode_s qstatnode_t;

struct qhintnode_s {
	unsigned char       *nm;
	int                 tp;
	struct qhintnode_s  *next;
};
/* typedef struct qhintnode_s qhintnode_t; */  /* Already defined in dns_query.h */

static int p_dns_cached_resolve(query_stat_array q, unsigned char *name, dns_cent_t **cachedp,
				int hops, qstatnode_t *qslist, qhintnode_t *qhlist, int thint, time_t queryts,
				unsigned char *c_soa);

/*
 * Performs a semi-parallel query on the servers in q. PAR_QUERIES are executed parallel at a time.
 * name is the query name in dns protocol format (number.string etc),
 * ent is the dns_cent_t that will be filled.
 * hops is the number of recursions left.
 * qslist should refer to a list of server arrays used higher up in the calling chain. This way we can
 * avoid name servers that have already been tried for this name.
 * qhlist should refer to a list of names that we are trying to resolve higher up in the calling chain.
 * These names should be avoided further down the chain, or we risk getting caught in a wasteful cycle.
 * thint is a hint on the requested query type used to decide whether an aa record must be fetched
 * or a non-authoritative answer will be enough.
 *
 * nocache is needed because we add AA records to the cache. If the nocache flag is set, we do not
 * take the original values for the record, but flags=0 and ttl=0 (but only if we do not already have
 * a cached record for that set). These settings cause the record be purged on the next cache addition.
 * It will also not be used again.
 */
static int p_recursive_query(query_stat_array q, unsigned char *name, dns_cent_t **entp,
			     int *nocache, int hops, qstatnode_t *qslist, qhintnode_t *qhlist, int thint,
			     unsigned char *c_soa)
{
	dns_cent_t *ent;
	int aa=0;
	int i,j,k;
	int rv=RC_SERVFAIL;
	query_stat_t *qse=NULL;  /* Initialized to inhibit compiler warning */
	dlist ns=NULL;
	{
		time_t ts0=time(NULL),global_timeout=global.timeout;
		int dc=0,mc=0,parqueries=global.par_queries;

		for (j=0; j<DA_NEL(q); j += parqueries) {
			mc=j+parqueries;
			if (mc>DA_NEL(q)) mc=DA_NEL(q);

			/* First, call p_exec_query once for each parallel set to initialize.
			 * Then, as long as not all have the state QS_DONE or we have a timeout,
			 * build a poll/select set for all active queries and call them accordingly. */
			for (i=dc;i<mc;i++) {
				query_stat_t *qs=&DA_INDEX(q,i);
				if(i>=j) {
					/* The below should not happen any more, but may once again
					 * (immediate success) */
					DEBUG_PDNSDA_MSG("Sending query to %s\n", PDNSDA2STR(PDNSD_A(qs)));
					rv=p_exec_query(&ent, name, &aa, qs,&ns,c_soa);
					if (rv==RC_OK || rv==RC_NAMEERR) {
						qse=qs;
						for (k=dc;k<mc;k++) {
							p_cancel_query(&DA_INDEX(q,k));
						}
						goto done;
					}
				}
				if (qs->state==QS_DONE && i==dc)
					dc++;
			}
			if (dc<mc) {
				time_t ts,maxto,now;
				int pc,nevents;
#ifdef NO_POLL
				int maxfd;
				fd_set reads;
				fd_set writes;
				struct timeval tv;
#else
				int ic;
				struct pollfd polls[mc-dc];  /* Variable length array, may cause portability problems */
#endif
				/* we do time keeping by hand, because poll/select might be interrupted and
				 * the returned times are not always to be trusted upon */
				ts=time(NULL);
				do {
					/* build poll/select sets, maintain time. 
					 * If you do parallel queries, the highest timeout will be honored
					 * also for the other servers when their timeout is exceeded and
					 * the highest is not.
					 * Changed by Paul Rombouts: queries are not canceled until we receive
					 * a useful reply or everything has failed or timed out (also taking into
					 * account the global timeout option).
					 * Thus in the worst case all the queries in the q list will be active
					 * simultaneously. The downside is that we may be wasting more resources
					 * this way. The advantage is that we have a greater chance of catching a
					 * reply. After all, if we wait longer anyway, why not for more servers. */
					maxto=0;
					pc=0;
					rv=RC_SERVFAIL;

#ifdef NO_POLL
					FD_ZERO(&reads);
					FD_ZERO(&writes);
					maxfd=0;
#endif
					for (i=dc;i<mc;i++) {
						query_stat_t *qs=&DA_INDEX(q,i);
						if (qs->state!=QS_DONE) {
							if (i>=j && qs->timeout>maxto)
								maxto=qs->timeout;
#ifdef NO_POLL
							if (qs->sock>maxfd)
								maxfd=qs->sock;
							switch (qs->state) {
							QS_READ_CASES:
								FD_SET(qs->sock,&reads);
								break;
							QS_WRITE_CASES:
								FD_SET(qs->sock,&writes);
								break;
							}
#else
							polls[pc].fd=qs->sock;
							switch (qs->state) {
							QS_READ_CASES:
								polls[pc].events=POLLIN;
								break;
							QS_WRITE_CASES:
								polls[pc].events=POLLOUT;
								break;
							default:
								polls[pc].events=0;
							}
#endif
							pc++;
						}
					}
					if (pc==0) {
						/* In this case, ALL are done and we do not need to cancel any
						 * query. */
						break;
					}
					now=time(NULL);
					maxto -= now-ts;
					if (mc==DA_NEL(q)) {
						time_t globto=global_timeout-(now-ts0);
						if(globto>maxto) maxto=globto;
					}
#ifdef NO_POLL
					tv.tv_sec=(maxto>0)?maxto:0;
					tv.tv_usec=0;
					nevents=select(maxfd+1,&reads,&writes,NULL,&tv);
#else
					nevents=poll(polls,pc,(maxto>0)?(maxto*1000):0);
#endif
					if (nevents<0) {
						/* if(errno==EINTR)
							continue; */
						log_warn("poll/select failed: %s",strerror(errno));
						for (i=dc;i<mc;i++)
							p_cancel_query(&DA_INDEX(q,i));
						goto done;
					}
					if (nevents==0) {
						/* We have timed out. Mark the unresponsive servers so that we can consider
						   them for retesting later on. We will continue to listen for replies from
						   these servers as long as we have additional servers to try. */
						for (i=j;i<mc;i++) {
							query_stat_t *qs=&DA_INDEX(q,i);
							if (qs->state!=QS_DONE && qs->needs_testing)
								qs->needs_testing=2;
						}
						if (mc==DA_NEL(q)) {
							/* We will not try additional servers. Cancel everything. */
							for (i=dc;i<mc;i++)
								p_cancel_query(&DA_INDEX(q,i));
						} 
						break;
					}
#ifndef NO_POLL
					ic=0;
#endif
					for (i=dc;i<mc;i++) {
						query_stat_t *qs=&DA_INDEX(q,i);
						/* Check if we got a poll/select event */
						if (qs->state!=QS_DONE) {
							int srv_event=0;
							/* This detection may seem suboptimal, but normally, we have at most 2-3 parallel
							 * queries, and anything else would be higher overhead, */
#ifdef NO_POLL
							switch (qs->state) {
							QS_READ_CASES:
								srv_event=FD_ISSET(qs->sock,&reads);
								break;
							QS_WRITE_CASES:
								srv_event=FD_ISSET(qs->sock,&writes);
								break;
							}
#else
							do {
								PDNSD_ASSERT(ic<pc, "file descriptor not found in poll() array");
								k=ic++;
							} while(polls[k].fd!=qs->sock);
							/*
							 * In case of an error, reenter the state machine
							 * to catch it.
							 */
							switch (qs->state) {
							QS_READ_CASES:
								srv_event=polls[k].revents&(POLLIN|POLLERR|POLLHUP|POLLNVAL);
								break;
							QS_WRITE_CASES:
								srv_event=polls[k].revents&(POLLOUT|POLLERR|POLLHUP|POLLNVAL);
								break;
							}
#endif
							if (srv_event) {
								--nevents;
								rv=p_exec_query(&ent, name, &aa, qs,&ns,c_soa);
								if (rv==RC_OK || rv==RC_NAMEERR) {
									qse=qs;
									for (k=dc;k<mc;k++) {
										p_cancel_query(&DA_INDEX(q,k));
									}
									goto done;
								}
							}
						}
						/* recheck, this might have changed after the last p_exec_query */
						if (qs->state==QS_DONE && i==dc)
							dc++;
					}
					if(nevents>0) {
						/* We have not managed to handle all the events reported by poll/select.
						   Better call it quits, or we risk getting caught in a wasteful cycle.
						*/
						if(++poll_errs<=MAXPOLLERRS)
							log_error("%d unhandled poll/select event(s) in p_recursive_query() at %s, line %d.",nevents,__FILE__,__LINE__);
						for (i=dc;i<mc;i++)
							p_cancel_query(&DA_INDEX(q,i));
						rv=RC_SERVFAIL;
						goto done;
					}
				} while (dc<mc);
			}
		}
	done:
		{
			/* See if any servers need to be retested for availability.
			   We build up a list of addresses rather than call
			   sched_server_test() separately for each address to
			   reduce the overhead caused by locking and signaling */
			int n=0;
			for (i=0;i<mc;i++)
				if (DA_INDEX(q,i).needs_testing > 1)
					++n;
			if(n>0) {
				pdnsd_a addrs[n]; /* variable length array */
				k=0;
				for (i=0;i<mc;i++) {
					query_stat_t *qs=&DA_INDEX(q,i);
					if (qs->needs_testing > 1)
						addrs[k++]= *PDNSD_A(qs);
				}
				sched_server_test(addrs,n,-1);
			}
		}
	}

	if (rv!=RC_OK) {
		DEBUG_MSG("No query succeeded. Returning error code \"%s\"\n",get_ename(rv));
		return rv;
	}

	if(nocache) *nocache=qse->nocache;
	DEBUG_PDNSDA_MSG("Query to %s succeeded.\n", PDNSDA2STR(PDNSD_A(qse)));
	/*
	 * Look into the query type hint. If it is a wildcard (QT_*), we need an authoritative answer.
	 * Same if there is no record that answers the query. Mark the cache record if it is not an aa.
	 */

	/* This test will also fail if we have a negative cached record. This is done purposely. */
#define aa_needed ((thint>=QT_MIN && thint<=QT_MAX) || \
	           ((thint>=T_MIN && thint<=T_MAX) && (!ent->rr[thint-T_MIN] && !ent->rr[T_CNAME-T_MIN])))

	if (!aa && qse->auth_serv && aa_needed) {
		query_stat_array serv;
		init_qserv(&serv);
		/* Authority records present. Ask them, because the answer was non-authoritative.
		 * To do so, we first put the Authority and the additional section into a dns_cent_t
		 * and look for name servers in the Authority section and their addresses in
		 * the answer and additional sections. If none are found, we also need to 
		 * resolve the name servers.*/
		if (hops>0) {
			unsigned char *nsdomain;
			for (nsdomain=dlist_first(ns);nsdomain;nsdomain=dlist_next(nsdomain)) {
				unsigned char *nsname=skiprhn(nsdomain);
				pdnsd_a serva;
				
				if (global.paranoid) {
					int rem;
					/* paranoia mode: don't query name servers that are not responsible */
					domain_match(nsdomain,name,&rem,NULL);
					if (rem!=0)
						continue;
				}
				/* look it up in the cache or resolve it if needed. The records received should be in the cache now,
				   so it's ok */

#ifdef ENABLE_IPV4
				if (run_ipv4)
					serva.ipv4.s_addr=INADDR_ANY;
#endif
#ifdef ENABLE_IPV6
				ELSE_IPV6
					serva.ipv6=in6addr_any;
#endif
				{
					unsigned char *nm=name;
					int tp=thint;
					qhintnode_t *ql=qhlist;

					for(;;) {
						if(rhnicmp(nm,nsname) && tp==T_A) {
							DEBUG_RHN_MSG("Not looking up address for name server \"%s\": risk of infinite recursion.\n",RHN2STR(nsname));
							goto skip_server;
						}
						if(!ql) break;
						nm=ql->nm;
						tp=ql->tp;
						ql=ql->next;
					}
					{
						qhintnode_t qhn={name,thint,qhlist};
						dns_cent_t *servent;
						if (r_dns_cached_resolve(nsname, &servent, hops-1, &qhn,T_A,time(NULL),NULL)==RC_OK) {
#ifdef ENABLE_IPV4
							if (run_ipv4) {
								rr_set_t *rrset=servent->rr[T_A-T_MIN];
								if (rrset && rrset->rrs)
									memcpy(&serva.ipv4,rrset->rrs+1,sizeof(serva.ipv4));
							}
#endif
#ifdef ENABLE_IPV6
							ELSE_IPV6 {
								rr_set_t *rrset;
# ifdef DNS_NEW_RRS
								if ((rrset=servent->rr[T_AAAA-T_MIN]) && rrset->rrs)
									memcpy(&serva.ipv6,rrset->rrs+1,sizeof(serva.ipv6));
								else
# endif
									if ((rrset=servent->rr[T_A-T_MIN]) && rrset->rrs) {
										struct in_addr ina;
										/* XXX: memcpy for alpha (unaligned access) */
										memcpy(&ina,rrset->rrs+1,sizeof(ina));
										IPV6_MAPIPV4(&ina,&serva.ipv6);
									}

							}
#endif
							free_cent(servent  DBG1);
							pdnsd_free(servent);
						}
					}
				}

				if (!is_inaddr_any(&serva) && !is_local_addr(&serva)) {
					/* We've got an address. Add it to the list if it wasn't one of the servers we queried,
					   nor a local address (as defined in netdev.c) */
					query_stat_array qa=q;
					qstatnode_t *ql=qslist;
					for(;;) {
						for (i=0;i<DA_NEL(qa);i++) {
							/* If qa[i].state == QS_DONE, then p_exec_query() has been called,
							   and we should not query this server again */
							query_stat_t *qs=&DA_INDEX(qa,i);
							if (qs->state==QS_DONE && ADDR_EQUIV(PDNSD_A(qs),&serva)) {
								DEBUG_PDNSDA_MSG("Not trying name server %s, already queried.\n", PDNSDA2STR(&serva));
								goto skip_server;
							}
						}
						if(!ql) break;
						qa=ql->qa;
						ql=ql->next;
					}
					/* lean query mode is inherited. CF_AUTH and CF_ADDITIONAL are not (as specified
					 * in CFF_NOINHERIT). */
					if (!add_qserv(&serv, &serva, 53, qse->timeout, qse->flags&~CFF_NOINHERIT, 0,thint,
						       qse->lean_query,2,0,global.paranoid?nsdomain:NULL)) {
						rv=RC_SERVFAIL;
						free_cent(ent  DBG1);
						pdnsd_free(ent);
						goto free_ns_return;
					}
				}
			skip_server:;						
			}
			if (DA_NEL(serv)>0) {
				qstatnode_t qsn={q,qslist};
				unsigned char save_ns=ent->c_ns,save_soa=ent->c_soa;
				free_cent(ent  DBG1);
				pdnsd_free(ent);
				rv=p_dns_cached_resolve(serv,  name, &ent,hops-1,&qsn,qhlist,thint,time(NULL),c_soa);
				if(rv==RC_OK) {
					if(save_ns!=cundef && (ent->c_ns==cundef || ent->c_ns<save_ns))
						ent->c_ns=save_ns;
					if(save_soa!=cundef && (ent->c_soa==cundef || ent->c_soa<save_soa))
						ent->c_soa=save_soa;
				}
				else if(rv==RC_NAMEERR && c_soa) {
					if(save_soa!=cundef && (*c_soa==cundef || *c_soa<save_soa))
						*c_soa=save_soa;
				}
				/* return the answer in any case. */
			}
			else {
				DEBUG_MSG("No remaining authoritative name servers to try.\n");
				goto reset_ttl;
			}
		}
		else {
			DEBUG_MSG("Maximum hops count reached; not trying any more name servers.\n");
		reset_ttl:
			/*
			 * If we didn't get rrs from any of the authoritative servers, take the one we had.
			 * However, raise the CF_NOCACHE flag, so that it won't be used again (outside the
			 * cache latency period).
			 */
			for (j=0;j<T_NUM;j++) {
				if (ent->rr[j])
					ent->rr[j]->flags |= CF_NOCACHE;
			}
		}
		/* Always free the serv array before freeing the ns list,
		   because the serv array contains references to data within the ns list! */
		del_qserv(serv);
	}
 free_ns_return:
	dlist_free(ns);

	if(rv==RC_OK) *entp=ent;
	return rv;
#undef  aa_needed
}

/*
 * This checks the given name to resolve against the access list given for the server using the
 * include=, exclude= and policy= parameters.
 */
static int use_server(servparm_t *s, const unsigned char *name)
{
	int i,n=DA_NEL(s->alist);

	for (i=0;i<n;i++) {
		slist_t *sl=&DA_INDEX(s->alist,i);
		int nrem,lrem;
		domain_match(name,sl->domain,&nrem,&lrem);
		if(!lrem && (!sl->exact || !nrem))
			return sl->rule==C_INCLUDED;
	}

	if (s->policy==C_SIMPLE_ONLY || s->policy==C_FQDN_ONLY) {
                if(rhnsegcnt(name)<=1)
			return s->policy==C_SIMPLE_ONLY;
                else
			return s->policy==C_FQDN_ONLY;
        }

	return s->policy==C_INCLUDED;
}


/* Lookup addresses of nameservers provided by root servers for a given domain in the cache.
   Returns NULL if unsuccessful (or the cache entries have timed out).
*/
static addr_array lookup_ns(const unsigned char *domain)
{
	addr_array res=NULL;

	dns_cent_t *cent=lookup_cache(domain,NULL);
	if(cent) {
		rr_set_t *rrset=cent->rr[T_NS-T_MIN];
		if(rrset && (rrset->flags&CF_ROOTSERV) && !timedout(rrset)) {
			rr_bucket_t *rr=rrset->rrs;
			while(rr) {
				pdnsd_a *serva;
				dns_cent_t *servent;
				if(!(res=DA_GROW1(res)))
						break;
				serva=&DA_LAST(res);
#ifdef ENABLE_IPV4
				if (run_ipv4)
					serva->ipv4.s_addr=INADDR_ANY;
#endif
#ifdef ENABLE_IPV6
				ELSE_IPV6
					serva->ipv6=in6addr_any;
#endif
				servent=lookup_cache((unsigned char*)(rr+1),NULL);
				if(servent) {
#ifdef ENABLE_IPV4
					if (run_ipv4) {
						rr_set_t *rrset=servent->rr[T_A-T_MIN];
						if (rrset && !timedout(rrset) && rrset->rrs)
							memcpy(&serva->ipv4,rrset->rrs+1,sizeof(serva->ipv4));
					}
#endif
#ifdef ENABLE_IPV6
					ELSE_IPV6 {
						rr_set_t *rrset;
# ifdef DNS_NEW_RRS
						int tmdout;
						if ((rrset=servent->rr[T_AAAA-T_MIN]) && ((tmdout=timedout(rrset)) || !(rrset->flags&CF_NEGATIVE))) {
							if(!tmdout && rrset->rrs)
								memcpy(&serva->ipv6,rrset->rrs+1,sizeof(serva->ipv6));
						}
						else
# endif
							if ((rrset=servent->rr[T_A-T_MIN]) && !timedout(rrset) && rrset->rrs) {
								struct in_addr ina;
								/* XXX: memcpy for alpha (unaligned access) */
								memcpy(&ina,rrset->rrs+1,sizeof(ina));
								IPV6_MAPIPV4(&ina,&serva->ipv6);
							}
					}
#endif
					free_cent(servent  DBG1);
					pdnsd_free(servent);
				}
				if(is_inaddr_any(serva)) {
					/* Address lookup failed. */
					da_free(res); res=NULL;
					break;
				}
				rr=rr->next;
			}
		}
		free_cent(cent  DBG1);
		pdnsd_free(cent);
	}

	return res;
}

static int p_dns_resolve(unsigned char *name, dns_cent_t **cachedp, int hops, qhintnode_t *qhlist, int thint, unsigned char *c_soa)
{
	dns_cent_t *cached;
	int i,rc,nocache;
	int one_up=0,seenrootserv=0;
	query_stat_array serv;

	/* try the servers in the order of their definition */
	init_qserv(&serv);
	lock_server_data();
	for (i=0;i<DA_NEL(servers);i++) {
		servparm_t *sp=&DA_INDEX(servers,i);
		if(use_server(sp,name)) {
			int j;
			for(j=0;j<DA_NEL(sp->atup_a);++j) {
				atup_t *at=&DA_INDEX(sp->atup_a,j);
				if (at->is_up) {
					if(sp->rootserver) {
						if(!seenrootserv) {
							int nseg;
							seenrootserv=1;
							nseg=rhnsegcnt(name);
							if(nseg>=2) {
								unsigned char *topdomain=skipsegs(name,nseg-1);
								addr_array adrs=lookup_ns(topdomain);
								if(adrs) {
									/* The name servers for this top level domain have been found in the cache.
									   Instead of asking the root server, we will use this cached information.
									*/
									int k;
									for(k=0;k<DA_NEL(adrs);++k) {
										one_up=add_qserv(&serv, &DA_INDEX(adrs,k), 53, sp->timeout,
												 mk_flag_val(sp)&~CFF_NOINHERIT, sp->nocache,
												 thint,sp->lean_query,2,0,
												 global.paranoid?topdomain:NULL);
										if(!one_up) {
											da_free(adrs);
											goto done;
										}
									}
									da_free(adrs);
									DEBUG_PDNSDA_MSG("Not querying root-server %s, using cached information instead.\n", PDNSDA2STR(&at->a));
									seenrootserv=2;
									break;
								}
							}
						}
						else if(seenrootserv==2)
							break;
					}
					one_up=add_qserv(&serv, &at->a, sp->port, sp->timeout, mk_flag_val(sp),sp->nocache,
							 thint,sp->lean_query,sp->rootserver?3:(!sp->is_proxy),
							 needs_intermittent_testing(sp),NULL);
					if(!one_up)
						goto done;
				}
			}
		}
	}
 done:
	unlock_server_data();
	if (one_up) {
		rc=p_recursive_query(serv, name, &cached, &nocache, hops, NULL, qhlist, thint, c_soa);
		if (rc==RC_OK) {
			if (!nocache) {
				dns_cent_t *tc;
				add_cache(cached);
				if ((tc=lookup_cache(name,NULL))) {
					/* The cache may hold more information  than the recent query yielded.
					 * try to get the merged record. If that fails, revert to the new one. */
					free_cent(cached  DBG1);
					pdnsd_free(cached);
					cached=tc;
				} else
					DEBUG_MSG("p_dns_resolve: using local cent copy.\n");
			} else
				DEBUG_MSG("p_dns_resolve: nocache\n");

			*cachedp=cached;
		}
	}
	else {
		DEBUG_MSG("No server is marked up and allowed for this domain.\n");
		rc=RC_SERVFAIL; /* No server up */
	}
	del_qserv(serv);
	return rc;
}

static int set_flags_ttl(unsigned short *flags, time_t *ttl, dns_cent_t *cached, int i)
{
	rr_set_t *rrset=cached->rr[i-T_MIN];
	if (rrset) {
		time_t t;
		*flags|=rrset->flags;
		t=rrset->ts+CLAT_ADJ(rrset->ttl);
		if (!*ttl || *ttl>t)
			*ttl=t;
		return 1;
	}
	return 0;
}

/*
 * Resolve records for name into dns_cent_t, type thint
 * q is the set of servers to query from. Set q to NULL if you want to ask the servers registered with pdnsd.
 * qslist should refer to a list of server arrays already used higher up the calling chain (may be NULL).
 */
static int p_dns_cached_resolve(query_stat_array q, unsigned char *name, dns_cent_t **cachedp,
				int hops, qstatnode_t *qslist, qhintnode_t *qhlist, int thint, time_t queryts,
				unsigned char *c_soa)
{
	dns_cent_t *cached;
	int rc;
	int wild=0,need_req=0;
	unsigned short flags=0;

	DEBUG_RHN_MSG("Starting cached resolve for: %s, query %s\n",RHN2STR(name),get_tname(thint));
	if ((cached=lookup_cache(name,&wild))) {
		int neg=0,timed=0;
		time_t ttl=0;

		if (cached->flags&DF_LOCAL) {
#if DEBUG>0
			{
				char dflagstr[DFLAGSTRLEN];
				DEBUG_RHN_MSG("Entry found in cache for '%s' with dflags=%s.\n",
					      RHN2STR(cached->qname),dflags2str(cached->flags,dflagstr));
			}
#endif
			if((cached->flags&DF_NEGATIVE) || wild==w_locnerr) {
				if(c_soa) {
					if(cached->c_soa!=cundef)
						*c_soa=cached->c_soa;
					else if(have_rr(cached,T_SOA))
						*c_soa=rhnsegcnt(cached->qname);
					else {
						unsigned char *owner=getlocalowner(cached->qname,T_SOA);
						if(owner)
							*c_soa=rhnsegcnt(owner);
					}
				}
				free_cent(cached  DBG1);
				pdnsd_free(cached);
				return RC_NAMEERR;
			}
			else {
				*cachedp=cached;
				return RC_OK;
			}
		}
		DEBUG_RHN_MSG("Record found in cache for %s\n",RHN2STR(cached->qname));
		if (cached->flags&DF_NEGATIVE) {
			if ((ttl=cached->ts+CLAT_ADJ(cached->ttl))>=queryts)
				neg=1;
			else
				timed=1;
		} else {
			if (thint==QT_ALL) {
				int i;
				for (i=T_MIN;i<=T_MAX;i++)
					set_flags_ttl(&flags, &ttl, cached, i);
			}
			else if (!set_flags_ttl(&flags, &ttl, cached, T_CNAME) || (cached->rr[T_CNAME-T_MIN]->flags&CF_NEGATIVE)) {
				flags=0; ttl=0;
				if (thint>=T_MIN && thint<=T_MAX) {
					if (set_flags_ttl(&flags, &ttl, cached, thint))
						neg=cached->rr[thint-T_MIN]->flags&CF_NEGATIVE && ttl>=queryts;
				}
				else if (thint==QT_MAILB) {
					set_flags_ttl(&flags, &ttl, cached, T_MB);
					set_flags_ttl(&flags, &ttl, cached, T_MG);
					set_flags_ttl(&flags, &ttl, cached, T_MR);
				}
				else if (thint==QT_MAILA) {
					set_flags_ttl(&flags, &ttl, cached, T_MD);
					set_flags_ttl(&flags, &ttl, cached, T_MF);
				}
			}
			if(!(flags&CF_LOCAL)) {
				if (thint==QT_ALL) {
					if(!(cached->flags&DF_AUTH))
						need_req=1;
				}
				else if (thint>=QT_MIN && thint<=QT_MAX) {
					if(!(flags&CF_AUTH && !(flags&CF_ADDITIONAL)))
						need_req=1;
				}
				if (ttl<queryts)
					timed=1;
			}
		}
#if DEBUG>0
		{
			char dflagstr[DFLAGSTRLEN],cflagstr[CFLAGSTRLEN];
			DEBUG_MSG("Requery decision: dflags=%s, cflags=%s, req=%i, neg=%i, timed=%i, %s=%li\n",
				  dflags2str(cached->flags,dflagstr),cflags2str(flags,cflagstr),need_req,neg,timed,
				  ttl?"ttl":"timestamp",(long)(ttl?(ttl-queryts):ttl));
		}
#endif
		need_req = (!neg && (need_req || timed));
	}
	/* update server records set onquery */
	if(global.onquery) test_onquery();
	if (global.lndown_kluge && !(flags&CF_LOCAL)) {
		int i,linkdown=1;
		lock_server_data();
		for(i=0;i<DA_NEL(servers);++i) {
			servparm_t *sp=&DA_INDEX(servers,i);
			int j;
			for(j=0; j<DA_NEL(sp->atup_a);++j) {
				if (DA_INDEX(sp->atup_a,j).is_up) {
					linkdown=0;
					goto done;
				}
			}
		}
	done:
		unlock_server_data();
		if (linkdown) {
			DEBUG_MSG("Link is down.\n");
			rc=RC_SERVFAIL;
			goto cleanup_return;
		}
	}
	if (!cached || need_req) {
		dns_cent_t *ent;
		DEBUG_MSG("Trying name servers.\n");
		if (q)
			rc=p_recursive_query(q,name, &ent,NULL,hops,qslist,qhlist,thint,c_soa);
		else
			rc=p_dns_resolve(name, &ent,hops,qhlist,thint,c_soa);
		if (rc!=RC_OK) {
			if (rc==RC_SERVFAIL && cached && (flags&CF_NOPURGE)) {
				/* We could not get a new record, but we have a timed-out cached one
				   with the nopurge flag set. This means that we shall use it even
				   if timed out when no new one is available*/
				DEBUG_MSG("Falling back to cached record.\n");
			} else {
				goto cleanup_return;
			}
		} else {
			if (cached) {
				free_cent(cached  DBG1);
				pdnsd_free(cached);
			}
			cached=ent;
		}
	} else {
		DEBUG_MSG("Using cached record.\n");
	}
	*cachedp=cached;
	return RC_OK;

 cleanup_return:
	if(cached) {
		free_cent(cached  DBG1);
		pdnsd_free(cached);
	}
	return rc;
}


/* r_dns_cached_resolve() is like p_dns_cached_resolve(), except that r_dns_cached_resolve()
   will not returned negatively cached entries, but return RC_NAMEERR instead.
*/
int r_dns_cached_resolve(unsigned char *name, dns_cent_t **cachedp,
			 int hops, qhintnode_t *qhlist, int thint, time_t queryts,
			 unsigned char *c_soa)
{
	int rc=p_dns_cached_resolve(NULL,name,cachedp,hops,NULL,qhlist,thint,queryts,c_soa);
	if(rc==RC_OK) {
		dns_cent_t *cached=*cachedp;
		if(cached->flags&DF_NEGATIVE) {
			if(c_soa)
				*c_soa=cached->c_soa;
			free_cent(cached  DBG1);
			pdnsd_free(cached);
			rc=RC_NAMEERR;
		}
	}
	return rc;
}


/* Check whether a server is responsive by sending it an empty query.
   rep is the number of times this is tried in case of no reply.
 */
int query_uptest(pdnsd_a *addr, int port, time_t timeout, int rep)
{
	query_stat_t qs;
	int iter=0,rv;
#ifdef NO_POLL
#else
#endif

#ifdef ENABLE_IPV4
	if (run_ipv4) {
		memset(&qs.a.sin4,0,sizeof(qs.a.sin4));
		qs.a.sin4.sin_family=AF_INET;
		qs.a.sin4.sin_port=htons(port);
		qs.a.sin4.sin_addr=addr->ipv4;
		SET_SOCKA_LEN4(qs.a.sin4);
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		memset(&qs.a.sin6,0,sizeof(qs.a.sin6));
		qs.a.sin6.sin6_family=AF_INET6;
		qs.a.sin6.sin6_port=htons(port);
		qs.a.sin6.sin6_flowinfo=IPV6_FLOWINFO;
		qs.a.sin6.sin6_addr=addr->ipv6;
		SET_SOCKA_LEN6(qs.a.sin6);
	}
#endif
	qs.timeout=timeout;
	qs.flags=0;
	qs.nocache=0;
	qs.qt=T_A;
	qs.lean_query=1;
	qs.auth_serv=0;
	qs.needs_testing=0;
	qs.nsdomain=NULL;

 try_again:
	qs.state=QS_INITIAL;
	qs.qm=global.query_method;
	qs.s_errno=0;
	rv=p_exec_query(NULL, NULL, NULL, &qs, NULL, NULL);
	if(rv==-1) {
		time_t ts, tpassed;
		for(ts=time(NULL), tpassed=0;; tpassed=time(NULL)-ts) {
			int event;
#ifdef NO_POLL
			fd_set reads;
			fd_set writes;
			struct timeval tv;
			FD_ZERO(&reads);
			FD_ZERO(&writes);
			switch (qs.state) {
			QS_READ_CASES:
				FD_SET(qs.sock,&reads);
				break;
			QS_WRITE_CASES:
				FD_SET(qs.sock,&writes);
				break;
			}
			tv.tv_sec=timeout>tpassed?timeout-tpassed:0;
			tv.tv_usec=0;
			event=select(qs.sock+1,&reads,&writes,NULL,&tv);
#else
			struct pollfd pfd;
			pfd.fd=qs.sock;
			switch (qs.state) {
			QS_READ_CASES:
				pfd.events=POLLIN;
				break;
			QS_WRITE_CASES:
				pfd.events=POLLOUT;
				break;
			default:
				pfd.events=0;
			}
			event=poll(&pfd,1,timeout>tpassed?(timeout-tpassed)*1000:0);
#endif
			if (event<0) {
				log_warn("poll/select failed: %s",strerror(errno));
				p_cancel_query(&qs);
				return 0;
			}
			if(event==0) {
				/* timed out */
				p_cancel_query(&qs);
				if(++iter<rep) goto try_again;
				return 0;
			}
			event=0;
#ifdef NO_POLL
			switch (qs.state) {
			QS_READ_CASES:
				event=FD_ISSET(qs.sock,&reads);
				break;
			QS_WRITE_CASES:
				event=FD_ISSET(qs.sock,&writes);
				break;
			}
#else
			switch (qs.state) {
			QS_READ_CASES:
				event=pfd.revents&(POLLIN|POLLERR|POLLHUP|POLLNVAL);
				break;
			QS_WRITE_CASES:
				event=pfd.revents&(POLLOUT|POLLERR|POLLHUP|POLLNVAL);
				break;
			}
#endif
			if(event) {
				rv=p_exec_query(NULL, NULL, NULL, &qs, NULL, NULL);
				if(rv!=-1) break;
			}
			else {
				if(++poll_errs<=MAXPOLLERRS)
					log_error("Unhandled poll/select event in query_uptest() at %s, line %d.",__FILE__,__LINE__);
				p_cancel_query(&qs);
				return 0;
			}
		}
	}
	return rv!=RC_SERVFAIL;
}
