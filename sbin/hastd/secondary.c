/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/time.h>
#include <sys/bio.h>
#include <sys/disk.h>
#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgeom.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <activemap.h>
#include <nv.h>
#include <pjdlog.h>

#include "control.h"
#include "hast.h"
#include "hast_proto.h"
#include "hastd.h"
#include "metadata.h"
#include "proto.h"
#include "subr.h"
#include "synch.h"

struct hio {
	uint64_t 	 hio_seq;
	int	 	 hio_error;
	struct nv	*hio_nv;
	void		*hio_data;
	uint8_t		 hio_cmd;
	uint64_t	 hio_offset;
	uint64_t	 hio_length;
	TAILQ_ENTRY(hio) hio_next;
};

/*
 * Free list holds unused structures. When free list is empty, we have to wait
 * until some in-progress requests are freed.
 */
static TAILQ_HEAD(, hio) hio_free_list;
static pthread_mutex_t hio_free_list_lock;
static pthread_cond_t hio_free_list_cond;
/*
 * Disk thread (the one that do I/O requests) takes requests from this list.
 */
static TAILQ_HEAD(, hio) hio_disk_list;
static pthread_mutex_t hio_disk_list_lock;
static pthread_cond_t hio_disk_list_cond;
/*
 * There is one recv list for every component, although local components don't
 * use recv lists as local requests are done synchronously.
 */
static TAILQ_HEAD(, hio) hio_send_list;
static pthread_mutex_t hio_send_list_lock;
static pthread_cond_t hio_send_list_cond;

/*
 * Maximum number of outstanding I/O requests.
 */
#define	HAST_HIO_MAX	256

static void *recv_thread(void *arg);
static void *disk_thread(void *arg);
static void *send_thread(void *arg);

static void
init_environment(void)
{
	struct hio *hio;
	unsigned int ii;

	/*
	 * Initialize lists, their locks and theirs condition variables.
	 */
	TAILQ_INIT(&hio_free_list);
	mtx_init(&hio_free_list_lock);
	cv_init(&hio_free_list_cond);
	TAILQ_INIT(&hio_disk_list);
	mtx_init(&hio_disk_list_lock);
	cv_init(&hio_disk_list_cond);
	TAILQ_INIT(&hio_send_list);
	mtx_init(&hio_send_list_lock);
	cv_init(&hio_send_list_cond);

	/*
	 * Allocate requests pool and initialize requests.
	 */
	for (ii = 0; ii < HAST_HIO_MAX; ii++) {
		hio = malloc(sizeof(*hio));
		if (hio == NULL) {
			pjdlog_exitx(EX_TEMPFAIL,
			    "Unable to allocate memory (%zu bytes) for hio request.",
			    sizeof(*hio));
		}
		hio->hio_error = 0;
		hio->hio_data = malloc(MAXPHYS);
		if (hio->hio_data == NULL) {
			pjdlog_exitx(EX_TEMPFAIL,
			    "Unable to allocate memory (%zu bytes) for gctl_data.",
			    (size_t)MAXPHYS);
		}
		TAILQ_INSERT_HEAD(&hio_free_list, hio, hio_next);
	}
}

static void
init_local(struct hast_resource *res)
{

	if (metadata_read(res, true) < 0)
		exit(EX_NOINPUT);
}

static void
init_remote(struct hast_resource *res, struct nv *nvin)
{
	uint64_t resuid;
	struct nv *nvout;
	unsigned char *map;
	size_t mapsize;

	map = NULL;
	mapsize = 0;
	nvout = nv_alloc();
	nv_add_int64(nvout, (int64_t)res->hr_datasize, "datasize");
	nv_add_int32(nvout, (int32_t)res->hr_extentsize, "extentsize");
	resuid = nv_get_uint64(nvin, "resuid");
	res->hr_primary_localcnt = nv_get_uint64(nvin, "localcnt");
	res->hr_primary_remotecnt = nv_get_uint64(nvin, "remotecnt");
	nv_add_uint64(nvout, res->hr_secondary_localcnt, "localcnt");
	nv_add_uint64(nvout, res->hr_secondary_remotecnt, "remotecnt");
	mapsize = activemap_calc_ondisk_size(res->hr_local_mediasize -
	    METADATA_SIZE, res->hr_extentsize, res->hr_local_sectorsize);
	map = malloc(mapsize);
	if (map == NULL) {
		pjdlog_exitx(EX_TEMPFAIL,
		    "Unable to allocate memory (%zu bytes) for activemap.",
		    mapsize);
	}
	nv_add_uint32(nvout, (uint32_t)mapsize, "mapsize");
	/*
	 * When we work as primary and secondary is missing we will increase
	 * localcnt in our metadata. When secondary is connected and synced
	 * we make localcnt be equal to remotecnt, which means nodes are more
	 * or less in sync.
	 * Split-brain condition is when both nodes are not able to communicate
	 * and are both configured as primary nodes. In turn, they can both
	 * make incompatible changes to the data and we have to detect that.
	 * Under split-brain condition we will increase our localcnt on first
	 * write and remote node will increase its localcnt on first write.
	 * When we connect we can see that primary's localcnt is greater than
	 * our remotecnt (primary was modified while we weren't watching) and
	 * our localcnt is greater than primary's remotecnt (we were modified
	 * while primary wasn't watching).
	 * There are many possible combinations which are all gathered below.
	 * Don't pay too much attention to exact numbers, the more important
	 * is to compare them. We compare secondary's local with primary's
	 * remote and secondary's remote with primary's local.
	 * Note that every case where primary's localcnt is smaller than
	 * secondary's remotecnt and where secondary's localcnt is smaller than
	 * primary's remotecnt should be impossible in practise. We will perform
	 * full synchronization then. Those cases are marked with an asterisk.
	 * Regular synchronization means that only extents marked as dirty are
	 * synchronized (regular synchronization).
	 *
	 * SECONDARY METADATA PRIMARY METADATA
	 * local=3 remote=3   local=2 remote=2*  ?! Full sync from secondary.
	 * local=3 remote=3   local=2 remote=3*  ?! Full sync from primary.
	 * local=3 remote=3   local=2 remote=4*  ?! Full sync from primary.
	 * local=3 remote=3   local=3 remote=2   Primary is out-of-date,
	 *                                       regular sync from secondary.
	 * local=3 remote=3   local=3 remote=3   Regular sync just in case.
	 * local=3 remote=3   local=3 remote=4*  ?! Full sync from primary.
	 * local=3 remote=3   local=4 remote=2   Split-brain condition.
	 * local=3 remote=3   local=4 remote=3   Secondary out-of-date,
	 *                                       regular sync from primary.
	 * local=3 remote=3   local=4 remote=4*  ?! Full sync from primary.
	 */
	if (res->hr_resuid == 0) {
		/*
		 * Provider is used for the first time. Initialize everything.
		 */
		assert(res->hr_secondary_localcnt == 0);
		res->hr_resuid = resuid;
		if (metadata_write(res) < 0)
			exit(EX_NOINPUT);
		memset(map, 0xff, mapsize);
		nv_add_uint8(nvout, HAST_SYNCSRC_PRIMARY, "syncsrc");
	} else if (
	    /* Is primary is out-of-date? */
	    (res->hr_secondary_localcnt > res->hr_primary_remotecnt &&
	     res->hr_secondary_remotecnt == res->hr_primary_localcnt) ||
	    /* Node are more or less in sync? */
	    (res->hr_secondary_localcnt == res->hr_primary_remotecnt &&
	     res->hr_secondary_remotecnt == res->hr_primary_localcnt) ||
	    /* Is secondary is out-of-date? */
	    (res->hr_secondary_localcnt == res->hr_primary_remotecnt &&
	     res->hr_secondary_remotecnt < res->hr_primary_localcnt)) {
		/*
		 * Nodes are more or less in sync or one of the nodes is
		 * out-of-date.
		 * It doesn't matter at this point which one, we just have to
		 * send out local bitmap to the remote node.
		 */
		if (pread(res->hr_localfd, map, mapsize, METADATA_SIZE) !=
		    (ssize_t)mapsize) {
			pjdlog_exit(LOG_ERR, "Unable to read activemap");
		}
		if (res->hr_secondary_localcnt > res->hr_primary_remotecnt &&
		     res->hr_secondary_remotecnt == res->hr_primary_localcnt) {
			/* Primary is out-of-date, sync from secondary. */
			nv_add_uint8(nvout, HAST_SYNCSRC_SECONDARY, "syncsrc");
		} else {
			/*
			 * Secondary is out-of-date or counts match.
			 * Sync from primary.
			 */
			nv_add_uint8(nvout, HAST_SYNCSRC_PRIMARY, "syncsrc");
		}
	} else if (res->hr_secondary_localcnt > res->hr_primary_remotecnt &&
	     res->hr_primary_localcnt > res->hr_secondary_remotecnt) {
		/*
		 * Not good, we have split-brain condition.
		 */
		pjdlog_error("Split-brain detected, exiting.");
		nv_add_string(nvout, "Split-brain condition!", "errmsg");
		free(map);
		map = NULL;
		mapsize = 0;
	} else /* if (res->hr_secondary_localcnt < res->hr_primary_remotecnt ||
	    res->hr_primary_localcnt < res->hr_secondary_remotecnt) */ {
		/*
		 * This should never happen in practise, but we will perform
		 * full synchronization.
		 */
		assert(res->hr_secondary_localcnt < res->hr_primary_remotecnt ||
		    res->hr_primary_localcnt < res->hr_secondary_remotecnt);
		mapsize = activemap_calc_ondisk_size(res->hr_local_mediasize -
		    METADATA_SIZE, res->hr_extentsize,
		    res->hr_local_sectorsize);
		memset(map, 0xff, mapsize);
		if (res->hr_secondary_localcnt > res->hr_primary_remotecnt) {
			/* In this one of five cases sync from secondary. */
			nv_add_uint8(nvout, HAST_SYNCSRC_SECONDARY, "syncsrc");
		} else {
			/* For the rest four cases sync from primary. */
			nv_add_uint8(nvout, HAST_SYNCSRC_PRIMARY, "syncsrc");
		}
		pjdlog_warning("This should never happen, asking for full synchronization (primary(local=%ju, remote=%ju), secondary(local=%ju, remote=%ju)).",
		    (uintmax_t)res->hr_primary_localcnt,
		    (uintmax_t)res->hr_primary_remotecnt,
		    (uintmax_t)res->hr_secondary_localcnt,
		    (uintmax_t)res->hr_secondary_remotecnt);
	}
	if (hast_proto_send(res, res->hr_remotein, nvout, map, mapsize) < 0) {
		pjdlog_errno(LOG_WARNING, "Unable to send activemap to %s",
		    res->hr_remoteaddr);
		nv_free(nvout);
		exit(EX_TEMPFAIL);
	}
	nv_free(nvout);
	if (res->hr_secondary_localcnt > res->hr_primary_remotecnt &&
	     res->hr_primary_localcnt > res->hr_secondary_remotecnt) {
		/* Exit on split-brain. */
		exit(EX_CONFIG);
	}
}

void
hastd_secondary(struct hast_resource *res, struct nv *nvin)
{
	pthread_t td;
	pid_t pid;
	int error;

	/*
	 * Create communication channel between parent and child.
	 */
	if (proto_client("socketpair://", &res->hr_ctrl) < 0) {
		KEEP_ERRNO((void)pidfile_remove(pfh));
		pjdlog_exit(EX_OSERR,
		    "Unable to create control sockets between parent and child");
	}

	pid = fork();
	if (pid < 0) {
		KEEP_ERRNO((void)pidfile_remove(pfh));
		pjdlog_exit(EX_OSERR, "Unable to fork");
	}

	if (pid > 0) {
		/* This is parent. */
		proto_close(res->hr_remotein);
		res->hr_remotein = NULL;
		proto_close(res->hr_remoteout);
		res->hr_remoteout = NULL;
		res->hr_workerpid = pid;
		return;
	}
	(void)pidfile_close(pfh);

	setproctitle("%s (secondary)", res->hr_name);

	signal(SIGHUP, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);

	/* Error in setting timeout is not critical, but why should it fail? */
	if (proto_timeout(res->hr_remotein, 0) < 0)
		pjdlog_errno(LOG_WARNING, "Unable to set connection timeout");
	if (proto_timeout(res->hr_remoteout, res->hr_timeout) < 0)
		pjdlog_errno(LOG_WARNING, "Unable to set connection timeout");

	init_local(res);
	init_remote(res, nvin);
	init_environment();

	error = pthread_create(&td, NULL, recv_thread, res);
	assert(error == 0);
	error = pthread_create(&td, NULL, disk_thread, res);
	assert(error == 0);
	error = pthread_create(&td, NULL, send_thread, res);
	assert(error == 0);
	(void)ctrl_thread(res);
}

static void
reqlog(int loglevel, int debuglevel, int error, struct hio *hio, const char *fmt, ...)
{
	char msg[1024];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if ((size_t)len < sizeof(msg)) {
		switch (hio->hio_cmd) {
		case HIO_READ:
			(void)snprintf(msg + len, sizeof(msg) - len,
			    "READ(%ju, %ju).", (uintmax_t)hio->hio_offset,
			    (uintmax_t)hio->hio_length);
			break;
		case HIO_DELETE:
			(void)snprintf(msg + len, sizeof(msg) - len,
			    "DELETE(%ju, %ju).", (uintmax_t)hio->hio_offset,
			    (uintmax_t)hio->hio_length);
			break;
		case HIO_FLUSH:
			(void)snprintf(msg + len, sizeof(msg) - len, "FLUSH.");
			break;
		case HIO_WRITE:
			(void)snprintf(msg + len, sizeof(msg) - len,
			    "WRITE(%ju, %ju).", (uintmax_t)hio->hio_offset,
			    (uintmax_t)hio->hio_length);
			break;
		default:
			(void)snprintf(msg + len, sizeof(msg) - len,
			    "UNKNOWN(%u).", (unsigned int)hio->hio_cmd);
			break;
		}
	}
	pjdlog_common(loglevel, debuglevel, error, "%s", msg);
}

static int
requnpack(struct hast_resource *res, struct hio *hio)
{

	hio->hio_cmd = nv_get_uint8(hio->hio_nv, "cmd");
	if (hio->hio_cmd == 0) {
		pjdlog_error("Header contains no 'cmd' field.");
		hio->hio_error = EINVAL;
		goto end;
	}
	switch (hio->hio_cmd) {
	case HIO_READ:
	case HIO_WRITE:
	case HIO_DELETE:
		hio->hio_offset = nv_get_uint64(hio->hio_nv, "offset");
		if (nv_error(hio->hio_nv) != 0) {
			pjdlog_error("Header is missing 'offset' field.");
			hio->hio_error = EINVAL;
			goto end;
		}
		hio->hio_length = nv_get_uint64(hio->hio_nv, "length");
		if (nv_error(hio->hio_nv) != 0) {
			pjdlog_error("Header is missing 'length' field.");
			hio->hio_error = EINVAL;
			goto end;
		}
		if (hio->hio_length == 0) {
			pjdlog_error("Data length is zero.");
			hio->hio_error = EINVAL;
			goto end;
		}
		if (hio->hio_length > MAXPHYS) {
			pjdlog_error("Data length is too large (%ju > %ju).",
			    (uintmax_t)hio->hio_length, (uintmax_t)MAXPHYS);
			hio->hio_error = EINVAL;
			goto end;
		}
		if ((hio->hio_offset % res->hr_local_sectorsize) != 0) {
			pjdlog_error("Offset %ju is not multiple of sector size.",
			    (uintmax_t)hio->hio_offset);
			hio->hio_error = EINVAL;
			goto end;
		}
		if ((hio->hio_length % res->hr_local_sectorsize) != 0) {
			pjdlog_error("Length %ju is not multiple of sector size.",
			    (uintmax_t)hio->hio_length);
			hio->hio_error = EINVAL;
			goto end;
		}
		if (hio->hio_offset + hio->hio_length >
		    (uint64_t)res->hr_datasize) {
			pjdlog_error("Data offset is too large (%ju > %ju).",
			    (uintmax_t)(hio->hio_offset + hio->hio_length),
			    (uintmax_t)res->hr_datasize);
			hio->hio_error = EINVAL;
			goto end;
		}
		break;
	default:
		pjdlog_error("Header contains invalid 'cmd' (%hhu).",
		    hio->hio_cmd);
		hio->hio_error = EINVAL;
		goto end;
	}
	hio->hio_error = 0;
end:
	return (hio->hio_error);
}

/*
 * Thread receives requests from the primary node.
 */
static void *
recv_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hio *hio;
	bool wakeup;

	for (;;) {
		pjdlog_debug(2, "recv: Taking free request.");
		mtx_lock(&hio_free_list_lock);
		while ((hio = TAILQ_FIRST(&hio_free_list)) == NULL) {
			pjdlog_debug(2, "recv: No free requests, waiting.");
			cv_wait(&hio_free_list_cond, &hio_free_list_lock);
		}
		TAILQ_REMOVE(&hio_free_list, hio, hio_next);
		mtx_unlock(&hio_free_list_lock);
		pjdlog_debug(2, "recv: (%p) Got request.", hio);
		if (hast_proto_recv_hdr(res->hr_remotein, &hio->hio_nv) < 0) {
			pjdlog_exit(EX_TEMPFAIL,
			    "Unable to receive request header");
		}
		if (requnpack(res, hio) != 0)
			goto send_queue;
		reqlog(LOG_DEBUG, 2, -1, hio,
		    "recv: (%p) Got request header: ", hio);
		if (hio->hio_cmd == HIO_WRITE) {
			if (hast_proto_recv_data(res, res->hr_remotein,
			    hio->hio_nv, hio->hio_data, MAXPHYS) < 0) {
				pjdlog_exit(EX_TEMPFAIL,
				    "Unable to receive reply data");
			}
		}
		pjdlog_debug(2, "recv: (%p) Moving request to the disk queue.",
		    hio);
		mtx_lock(&hio_disk_list_lock);
		wakeup = TAILQ_EMPTY(&hio_disk_list);
		TAILQ_INSERT_TAIL(&hio_disk_list, hio, hio_next);
		mtx_unlock(&hio_disk_list_lock);
		if (wakeup)
			cv_signal(&hio_disk_list_cond);
		continue;
send_queue:
		pjdlog_debug(2, "recv: (%p) Moving request to the send queue.",
		    hio);
		mtx_lock(&hio_send_list_lock);
		wakeup = TAILQ_EMPTY(&hio_send_list);
		TAILQ_INSERT_TAIL(&hio_send_list, hio, hio_next);
		mtx_unlock(&hio_send_list_lock);
		if (wakeup)
			cv_signal(&hio_send_list_cond);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Thread reads from or writes to local component and also handles DELETE and
 * FLUSH requests.
 */
static void *
disk_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hio *hio;
	ssize_t ret;
	bool clear_activemap, wakeup;

	clear_activemap = true;

	for (;;) {
		pjdlog_debug(2, "disk: Taking request.");
		mtx_lock(&hio_disk_list_lock);
		while ((hio = TAILQ_FIRST(&hio_disk_list)) == NULL) {
			pjdlog_debug(2, "disk: No requests, waiting.");
			cv_wait(&hio_disk_list_cond, &hio_disk_list_lock);
		}
		TAILQ_REMOVE(&hio_disk_list, hio, hio_next);
		mtx_unlock(&hio_disk_list_lock);
		while (clear_activemap) {
			unsigned char *map;
			size_t mapsize;

			/*
			 * When first request is received, it means that primary
			 * already received our activemap, merged it and stored
			 * locally. We can now safely clear our activemap.
			 */
			mapsize =
			    activemap_calc_ondisk_size(res->hr_local_mediasize -
			    METADATA_SIZE, res->hr_extentsize,
			    res->hr_local_sectorsize);
			map = calloc(1, mapsize);
			if (map == NULL) {
				pjdlog_warning("Unable to allocate memory to clear local activemap.");
				break;
			}
			if (pwrite(res->hr_localfd, map, mapsize,
			    METADATA_SIZE) != (ssize_t)mapsize) {
				pjdlog_errno(LOG_WARNING,
				    "Unable to store cleared activemap");
				free(map);
				break;
			}
			free(map);
			clear_activemap = false;
			pjdlog_debug(1, "Local activemap cleared.");
		}
		reqlog(LOG_DEBUG, 2, -1, hio, "disk: (%p) Got request: ", hio);
		/* Handle the actual request. */
		switch (hio->hio_cmd) {
		case HIO_READ:
			ret = pread(res->hr_localfd, hio->hio_data,
			    hio->hio_length,
			    hio->hio_offset + res->hr_localoff);
			if (ret < 0)
				hio->hio_error = errno;
			else if (ret != (int64_t)hio->hio_length)
				hio->hio_error = EIO;
			else
				hio->hio_error = 0;
			break;
		case HIO_WRITE:
			ret = pwrite(res->hr_localfd, hio->hio_data,
			    hio->hio_length,
			    hio->hio_offset + res->hr_localoff);
			if (ret < 0)
				hio->hio_error = errno;
			else if (ret != (int64_t)hio->hio_length)
				hio->hio_error = EIO;
			else
				hio->hio_error = 0;
			break;
		case HIO_DELETE:
			ret = g_delete(res->hr_localfd,
			    hio->hio_offset + res->hr_localoff,
			    hio->hio_length);
			if (ret < 0)
				hio->hio_error = errno;
			else
				hio->hio_error = 0;
			break;
		case HIO_FLUSH:
			ret = g_flush(res->hr_localfd);
			if (ret < 0)
				hio->hio_error = errno;
			else
				hio->hio_error = 0;
			break;
		}
		if (hio->hio_error != 0) {
			reqlog(LOG_ERR, 0, hio->hio_error, hio,
			    "Request failed: ");
		}
		pjdlog_debug(2, "disk: (%p) Moving request to the send queue.",
		    hio);
		mtx_lock(&hio_send_list_lock);
		wakeup = TAILQ_EMPTY(&hio_send_list);
		TAILQ_INSERT_TAIL(&hio_send_list, hio, hio_next);
		mtx_unlock(&hio_send_list_lock);
		if (wakeup)
			cv_signal(&hio_send_list_cond);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Thread sends requests back to primary node.
 */
static void *
send_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct nv *nvout;
	struct hio *hio;
	void *data;
	size_t length;
	bool wakeup;

	for (;;) {
		pjdlog_debug(2, "send: Taking request.");
		mtx_lock(&hio_send_list_lock);
		while ((hio = TAILQ_FIRST(&hio_send_list)) == NULL) {
			pjdlog_debug(2, "send: No requests, waiting.");
			cv_wait(&hio_send_list_cond, &hio_send_list_lock);
		}
		TAILQ_REMOVE(&hio_send_list, hio, hio_next);
		mtx_unlock(&hio_send_list_lock);
		reqlog(LOG_DEBUG, 2, -1, hio, "send: (%p) Got request: ", hio);
		nvout = nv_alloc();
		/* Copy sequence number. */
		nv_add_uint64(nvout, nv_get_uint64(hio->hio_nv, "seq"), "seq");
		switch (hio->hio_cmd) {
		case HIO_READ:
			if (hio->hio_error == 0) {
				data = hio->hio_data;
				length = hio->hio_length;
				break;
			}
			/*
			 * We send no data in case of an error.
			 */
			/* FALLTHROUGH */
		case HIO_DELETE:
		case HIO_FLUSH:
		case HIO_WRITE:
			data = NULL;
			length = 0;
			break;
		default:
			abort();
			break;
		}
		if (hio->hio_error != 0)
			nv_add_int16(nvout, hio->hio_error, "error");
		if (hast_proto_send(res, res->hr_remoteout, nvout, data,
		    length) < 0) {
			pjdlog_exit(EX_TEMPFAIL, "Unable to send reply.");
		}
		nv_free(nvout);
		pjdlog_debug(2, "send: (%p) Moving request to the free queue.",
		    hio);
		nv_free(hio->hio_nv);
		hio->hio_error = 0;
		mtx_lock(&hio_free_list_lock);
		wakeup = TAILQ_EMPTY(&hio_free_list);
		TAILQ_INSERT_TAIL(&hio_free_list, hio, hio_next);
		mtx_unlock(&hio_free_list_lock);
		if (wakeup)
			cv_signal(&hio_free_list_cond);
	}
	/* NOTREACHED */
	return (NULL);
}