/* Socket event dispatching library - by D.C. van Moolenbroek */

#include <minix/drivers.h>
#include <minix/sockdriver.h>
#include <minix/sockevent.h>
#include <sys/ioctl.h>

#include "sockevent_proc.h"

#define US		1000000UL	/* microseconds per second */

#define SOCKHASH_SLOTS	256		/* # slots in ID-to-sock hash table */

static SLIST_HEAD(, sock) sockhash[SOCKHASH_SLOTS];

static SLIST_HEAD(, sock) socktimer;

static minix_timer_t sockevent_timer;

static SIMPLEQ_HEAD(, sock) sockevent_pending;

static sockevent_socket_cb_t sockevent_socket_cb = NULL;

static int sockevent_working;

static void socktimer_del(struct sock * sock);
static void sockevent_cancel_send(struct sock * sock,
	struct sockevent_proc * spr, int err);
static void sockevent_cancel_recv(struct sock * sock,
	struct sockevent_proc * spr, int err);

/*
 * Initialize the hash table of sock objects.
 */
static void
sockhash_init(void)
{
    const size_t slots = __arraycount(sockhash);
    for (size_t i = 0; i < slots; ++i) {
        SLIST_INIT(&sockhash[i]);
    }
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
#if !defined(SOCKHASH_SLOTS) || (SOCKHASH_SLOTS) <= 0
#error "SOCKHASH_SLOTS must be defined and greater than zero"
#endif

enum { SOCKHASH_SHIFT = 16 };

static unsigned int
sockhash_slot(sockid_t id)
{
	const unsigned long long uid = (unsigned long long)id;
	const unsigned long long sum = uid + (uid >> SOCKHASH_SHIFT);
	return (unsigned int)(sum % (unsigned long long)SOCKHASH_SLOTS);
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *
sockhash_get(sockid_t id)
{
    unsigned int slot = sockhash_slot(id);
    struct sock *entry;

    SLIST_FOREACH(entry, &sockhash[slot], sock_hash) {
        if (entry->sock_id == id) {
            return entry;
        }
    }

    return NULL;
}

/*
 * Add a sock object to the hash table.  The sock object must have a valid ID
 * in its 'sock_id' field, and must not be in the hash table already.
 */
static void
sockhash_add(struct sock *sock)
{
    if (sock == NULL) {
        return;
    }

    const unsigned int slot = sockhash_slot(sock->sock_id);
    SLIST_INSERT_HEAD(&sockhash[slot], sock, sock_hash);
}

/*
 * Remove a sock object from the hash table.  The sock object must be in the
 * hash table.
 */
static void
sockhash_del(struct sock *sock)
{
	if (sock == NULL) {
		return;
	}

	const unsigned int slot = sockhash_slot(sock->sock_id);
	struct sock **prevp = &SLIST_FIRST(&sockhash[slot]);
	struct sock *cur;

	while ((cur = *prevp) != NULL) {
		if (cur == sock) {
			*prevp = SLIST_NEXT(cur, sock_hash);
			break;
		}
		prevp = &SLIST_NEXT(cur, sock_hash);
	}
}

/*
 * Reset a socket object to a proper initial state, with a particular socket
 * identifier, a SOCK_ type, and a socket operations table.  The socket is
 * added to the ID-to-object hash table.  This function always succeeds.
 */
static void
sockevent_reset(struct sock * sock, sockid_t id, int domain, int type,
	const struct sockevent_ops * ops)
{
	struct sock tmp;

	assert(sock != NULL);
	if (sock == NULL)
		return;

	memset(&tmp, 0, sizeof(tmp));

	tmp.sock_id = id;
	tmp.sock_domain = domain;
	tmp.sock_type = type;

	tmp.sock_slowat = 1;
	tmp.sock_rlowat = 1;

	tmp.sock_ops = ops;
	tmp.sock_select.ss_endpt = NONE;

	*sock = tmp;

	sockhash_add(sock);
}

/*
 * Initialize a new socket that will serve as an accepted socket on the given
 * listening socket 'sock'.  The new socket is given as 'newsock', and its new
 * socket identifier is given as 'newid'.  This function always succeeds.
 */
void sockevent_clone(struct sock *sock, struct sock *newsock, sockid_t newid)
{
    if (sock == NULL || newsock == NULL) {
        return;
    }

    sockevent_reset(newsock, newid, (int)sock->sock_domain, sock->sock_type, sock->sock_ops);

    newsock->sock_opt = sock->sock_opt & ~SO_ACCEPTCONN;
    newsock->sock_linger = sock->sock_linger;
    newsock->sock_stimeo = sock->sock_stimeo;
    newsock->sock_rtimeo = sock->sock_rtimeo;
    newsock->sock_slowat = sock->sock_slowat;
    newsock->sock_rlowat = sock->sock_rlowat;

    newsock->sock_flags |= SFL_CLONED;
}

/*
 * A new socket has just been accepted.  The corresponding listening socket is
 * given as 'sock'.  The new socket has ID 'newid', and if it had not already
 * been added to the hash table through sockevent_clone() before, 'newsock' is
 * a non-NULL pointer which identifies the socket object to clone into.
 */
static void
sockevent_accepted(struct sock *sock, struct sock *newsock, sockid_t newid)
{
    if (newsock == NULL) {
        newsock = sockhash_get(newid);
        if (newsock == NULL) {
            panic("libsockdriver: socket driver returned unknown ID %d from accept callback", newid);
            return;
        }
    } else {
        sockevent_clone(sock, newsock, newid);
    }

    assert(newsock != NULL);
    assert((newsock->sock_flags & SFL_CLONED) != 0);
    newsock->sock_flags &= ~SFL_CLONED;
}

/*
 * Allocate a sock object, by asking the socket driver for one.  On success,
 * return OK, with a pointer to the new object stored in 'sockp'.  This new
 * object has all its fields set to initial values, in part based on the given
 * parameters.  On failure, return an error code.  Failure has two typical
 * cause: either the given domain, type, protocol combination is not supported,
 * or the socket driver is out of sockets (globally or for this combination).
 */
static int
sockevent_alloc(int domain, int type, int protocol, endpoint_t user_endpt,
	struct sock **sockp)
{
	struct sock *sock = NULL;
	const struct sockevent_ops *ops = NULL;
	sockid_t sid;

	if (domain < 0 || domain > UINT8_MAX)
		return EAFNOSUPPORT;

	if (sockevent_socket_cb == NULL)
		panic("libsockevent: not initialized");

	if (sockp == NULL)
		return EINVAL;

	sid = sockevent_socket_cb(domain, type, protocol, user_endpt, &sock, &ops);
	if (sid < 0)
		return (int)sid;

	if (sock == NULL || ops == NULL)
		return EFAULT;

	sockevent_reset(sock, sid, domain, type, ops);

	*sockp = sock;
	return OK;
}

/*
 * Free a previously allocated sock object.
 */
static void
sockevent_free(struct sock *sock)
{
	const struct sockevent_ops *ops;

	assert(sock != NULL);
	assert(sock->sock_proc == NULL);

	socktimer_del(sock);
	sockhash_del(sock);

	ops = sock->sock_ops;
	assert(ops != NULL);
	assert(ops->sop_free != NULL);

	sock->sock_ops = NULL;

	ops->sop_free(sock);
}

/*
 * Create a new socket.
 */
static sockid_t
sockevent_socket(int domain, int type, int protocol, endpoint_t user_endpt)
{
	struct sock *sock = NULL;
	int r;

	r = sockevent_alloc(domain, type, protocol, user_endpt, &sock);
	if (r != OK)
		return r;

	return sock->sock_id;
}

/*
 * Create a pair of connected sockets.
 */
static int
sockevent_socketpair(int domain, int type, int protocol, endpoint_t user_endpt,
    sockid_t id[2])
{
    struct sock *sock1 = NULL, *sock2 = NULL;
    int r = OK;

    if (id == NULL)
        return EINVAL;

    r = sockevent_alloc(domain, type, protocol, user_endpt, &sock1);
    if (r != OK)
        return r;

    if (sock1->sock_ops == NULL || sock1->sock_ops->sop_pair == NULL) {
        r = EOPNOTSUPP;
        goto cleanup;
    }

    r = sockevent_alloc(domain, type, protocol, user_endpt, &sock2);
    if (r != OK)
        goto cleanup;

    if (sock2->sock_ops != sock1->sock_ops) {
        r = EOPNOTSUPP;
        goto cleanup;
    }

    r = sock1->sock_ops->sop_pair(sock1, sock2, user_endpt);
    if (r != OK)
        goto cleanup;

    id[0] = sock1->sock_id;
    id[1] = sock2->sock_id;
    return OK;

cleanup:
    if (sock2 != NULL)
        sockevent_free(sock2);
    if (sock1 != NULL)
        sockevent_free(sock1);
    return r;
}

/*
 * A send request returned EPIPE.  If desired, send a SIGPIPE signal to the
 * user process that issued the request.
 */
static void
sockevent_sigpipe(struct sock *sock, endpoint_t user_endpt, int flags)
{
	if (sock == NULL)
		return;

	if ((flags & MSG_NOSIGNAL) != 0 ||
	    (sock->sock_opt & SO_NOSIGPIPE) != 0 ||
	    sock->sock_type != SOCK_STREAM)
		return;

	(void)sys_kill(user_endpt, SIGPIPE);
}

/*
 * Suspend a request without data, that is, a bind, connect, accept, or close
 * request.
 */
static void
sockevent_suspend(struct sock * sock, unsigned int event,
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt)
{
	struct sockevent_proc *spr;
	struct sockevent_proc **sprp;

	if (sock == NULL || call == NULL)
		panic("libsockevent: invalid argument");

	spr = sockevent_proc_alloc();
	if (spr == NULL)
		panic("libsockevent: too many suspended processes");

	spr->spr_next = NULL;
	spr->spr_event = event;
	spr->spr_timer = FALSE;
	spr->spr_call = *call;
	spr->spr_endpt = user_endpt;

	sprp = &sock->sock_proc;
	while (*sprp != NULL)
		sprp = &(*sprp)->spr_next;

	*sprp = spr;
}

/*
 * Suspend a request with data, that is, a send or receive request.
 */
static void
sockevent_suspend_data(struct sock *sock, unsigned int event, int timer,
    const struct sockdriver_call *__restrict call, endpoint_t user_endpt,
    const struct sockdriver_data *__restrict data, size_t len, size_t off,
    const struct sockdriver_data *__restrict ctl, socklen_t ctl_len,
    socklen_t ctl_off, int flags, int rflags, clock_t time)
{
    struct sockevent_proc *spr;
    struct sockevent_proc **tail;

    spr = sockevent_proc_alloc();
    if (spr == NULL)
        panic("libsockevent: too many suspended processes");

    spr->spr_next = NULL;
    spr->spr_event = event;
    spr->spr_timer = timer;
    spr->spr_call = *call;
    spr->spr_endpt = user_endpt;
    sockdriver_pack_data(&spr->spr_data, call, data, len);
    spr->spr_datalen = len;
    spr->spr_dataoff = off;
    sockdriver_pack_data(&spr->spr_ctl, call, ctl, ctl_len);
    spr->spr_ctllen = ctl_len;
    spr->spr_ctloff = ctl_off;
    spr->spr_flags = flags;
    spr->spr_rflags = rflags;
    spr->spr_time = time;

    tail = &sock->sock_proc;
    while (*tail != NULL) {
        tail = &(*tail)->spr_next;
    }
    *tail = spr;
}

/*
 * Return TRUE if there are any suspended requests on the given socket's queue
 * that match any of the events in the given event mask, or FALSE otherwise.
 */
static int
sockevent_has_suspended(struct sock *sock, unsigned int mask)
{
	const struct sockevent_proc *spr;

	if (sock == NULL || mask == 0U) {
		return FALSE;
	}

	for (spr = sock->sock_proc; spr != NULL; spr = spr->spr_next) {
		if ((spr->spr_event & mask) != 0U) {
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Check whether the given call is on the given socket's queue of suspended
 * requests.  If so, remove it from the queue and return a pointer to the
 * suspension data structure.  The caller is then responsible for freeing that
 * data structure using sockevent_proc_free().  If the call was not found, the
 * function returns NULL.
 */
static struct sockevent_proc *
sockevent_unsuspend(struct sock *sock, const struct sockdriver_call *call)
{
	struct sockevent_proc **sprp, *spr;

	if (sock == NULL || call == NULL)
		return NULL;

	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL; sprp = &spr->spr_next) {
		if (spr->spr_call.sc_endpt == call->sc_endpt &&
		    spr->spr_call.sc_req == call->sc_req) {
			*sprp = spr->spr_next;
			return spr;
		}
	}

	return NULL;
}

/*
 * Attempt to resume the given suspended request for the given socket object.
 * Return TRUE if the suspended request has been fully resumed and can be
 * removed from the queue of suspended requests, or FALSE if it has not been
 * fully resumed and should stay on the queue.  In the latter case, no
 * resumption will be attempted for other suspended requests of the same type.
 */
static int
sockevent_resume(struct sock *sock, struct sockevent_proc *spr)
{
	struct sock *newsock = NULL;
	struct sockdriver_data data, ctl;
	char addr[SOCKADDR_MAX];
	socklen_t addr_len = 0;
	size_t len = 0, min = 0;
	sockid_t r = 0;

	assert(sock != NULL);
	assert(spr != NULL);
	memset(&data, 0, sizeof(data));
	memset(&ctl, 0, sizeof(ctl));
	memset(addr, 0, sizeof(addr));

	switch (spr->spr_event) {
	case SEV_CONNECT:
		if (spr->spr_call.sc_endpt == NONE)
			return TRUE;
		r = sock->sock_err;
		if (r != OK)
			sock->sock_err = OK;
		sockdriver_reply_generic(&spr->spr_call, r);
		return TRUE;

	case SEV_BIND:
		r = sock->sock_err;
		if (r != OK)
			sock->sock_err = OK;
		sockdriver_reply_generic(&spr->spr_call, r);
		return TRUE;

	case SEV_ACCEPT:
		assert(sock->sock_opt & SO_ACCEPTCONN);
		newsock = NULL;
		r = sock->sock_ops->sop_accept(sock, (struct sockaddr *)&addr,
		    &addr_len, spr->spr_endpt, &newsock);
		if (r == SUSPEND)
			return FALSE;
		if (r >= 0) {
			assert(addr_len <= sizeof(addr));
			sockevent_accepted(sock, newsock, r);
		}
		sockdriver_reply_accept(&spr->spr_call, r,
		    (struct sockaddr *)&addr, addr_len);
		return TRUE;

	case SEV_SEND:
		assert(spr->spr_dataoff <= spr->spr_datalen);
		assert(spr->spr_ctloff <= spr->spr_ctllen);
		if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
			if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
				r = (int)spr->spr_dataoff;
			} else if ((r = sock->sock_err) != OK) {
				sock->sock_err = OK;
			} else {
				r = EPIPE;
			}
		} else {
			sockdriver_unpack_data(&data, &spr->spr_call,
			    &spr->spr_data, spr->spr_datalen);
			sockdriver_unpack_data(&ctl, &spr->spr_call,
			    &spr->spr_ctl, spr->spr_ctllen);

			len = spr->spr_datalen - spr->spr_dataoff;
			min = sock->sock_slowat;
			if (min > len)
				min = len;

			r = sock->sock_ops->sop_send(sock, &data, len,
			    &spr->spr_dataoff, &ctl,
			    spr->spr_ctllen - spr->spr_ctloff,
			    &spr->spr_ctloff, NULL, 0, spr->spr_endpt,
			    spr->spr_flags, min);

			assert(r <= 0);
			if (r == SUSPEND)
				return FALSE;

			if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
				r = spr->spr_dataoff;
		}

		if (r == EPIPE)
			sockevent_sigpipe(sock, spr->spr_endpt, spr->spr_flags);

		sockdriver_reply_generic(&spr->spr_call, r);
		return TRUE;

	case SEV_RECV:
		assert(spr->spr_dataoff <= spr->spr_datalen);
		assert(spr->spr_ctloff <= spr->spr_ctllen);
		addr_len = 0;

		if (sock->sock_flags & SFL_SHUT_RD) {
			r = SOCKEVENT_EOF;
		} else {
			len = spr->spr_datalen - spr->spr_dataoff;

			if (sock->sock_err == OK) {
				min = sock->sock_rlowat;
				if (min > len)
					min = len;
			} else {
				min = 0;
			}

			sockdriver_unpack_data(&data, &spr->spr_call,
			    &spr->spr_data, spr->spr_datalen);
			sockdriver_unpack_data(&ctl, &spr->spr_call,
			    &spr->spr_ctl, spr->spr_ctllen);

			r = sock->sock_ops->sop_recv(sock, &data, len,
			    &spr->spr_dataoff, &ctl,
			    spr->spr_ctllen - spr->spr_ctloff,
			    &spr->spr_ctloff, (struct sockaddr *)&addr,
			    &addr_len, spr->spr_endpt, spr->spr_flags, min,
			    &spr->spr_rflags);

			if (r == SUSPEND) {
				if (sock->sock_err == OK)
					return FALSE;
				r = SOCKEVENT_EOF;
			}

			assert(addr_len <= sizeof(addr));
		}

		if (r == OK || spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
			r = (int)spr->spr_dataoff;
		} else if (sock->sock_err != OK) {
			r = sock->sock_err;
			sock->sock_err = OK;
		} else if (r == SOCKEVENT_EOF) {
			r = 0;
		}

		sockdriver_reply_recv(&spr->spr_call, r, spr->spr_ctloff,
		    (struct sockaddr *)&addr, addr_len, spr->spr_rflags);
		return TRUE;

	case SEV_CLOSE:
		sockdriver_reply_generic(&spr->spr_call, OK);
		return TRUE;

	default:
		panic("libsockevent: process suspended on unknown event 0x%x",
		    spr->spr_event);
	}
}

/*
 * Return TRUE if the given socket is ready for reading for a select call, or
 * FALSE otherwise.
 */
static int
sockevent_test_readable(struct sock *sock)
{
	if (sock == NULL || sock->sock_ops == NULL)
		return TRUE;

	if ((sock->sock_flags & SFL_SHUT_RD) != 0)
		return TRUE;

	if (sock->sock_err != OK)
		return TRUE;

	if ((sock->sock_opt & SO_ACCEPTCONN) != 0) {
		if (sock->sock_ops->sop_test_accept == NULL)
			return TRUE;
		return sock->sock_ops->sop_test_accept(sock) != SUSPEND;
	}

	if (sock->sock_ops->sop_test_recv == NULL)
		return TRUE;

	return sock->sock_ops->sop_test_recv(sock, sock->sock_rlowat, NULL) != SUSPEND;
}

/*
 * Return TRUE if the given socket is ready for writing for a select call, or
 * FALSE otherwise.
 */
static int sockevent_test_writable(struct sock *sock)
{
	if (sock == NULL)
		return FALSE;

	if (sock->sock_err != OK ||
	    (sock->sock_flags & SFL_SHUT_WR) ||
	    sock->sock_ops == NULL ||
	    sock->sock_ops->sop_test_send == NULL)
		return TRUE;

	return sock->sock_ops->sop_test_send(sock, sock->sock_slowat) != SUSPEND;
}

/*
 * Test whether any of the given select operations are ready on the given
 * socket.  Return the subset of ready operations; zero if none.
 */
static unsigned int
sockevent_test_select(struct sock *sock, unsigned int ops)
{
    const unsigned int valid_ops = SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR;
    unsigned int ready_ops = 0;

    assert((ops & ~valid_ops) == 0);

    if (sock == NULL) {
        return 0;
    }

    ops &= valid_ops;

    if ((ops & SDEV_OP_RD) != 0 && sockevent_test_readable(sock)) {
        ready_ops |= SDEV_OP_RD;
    }

    if ((ops & SDEV_OP_WR) != 0 && sockevent_test_writable(sock)) {
        ready_ops |= SDEV_OP_WR;
    }

    return ready_ops;
}

/*
 * Fire the given mask of events on the given socket object now.
 */
static void
sockevent_fire(struct sock *sock, unsigned int mask)
{
	if (sock == NULL)
		return;

	if (mask & SEV_CONNECT)
		mask |= SEV_SEND;

	struct sockevent_proc *spr;
	struct sockevent_proc **sprp = &sock->sock_proc;

	while ((spr = *sprp) != NULL) {
		unsigned int eventMask = spr->spr_event;

		if ((mask & eventMask) != 0 && sockevent_resume(sock, spr)) {
			*sprp = spr->spr_next;
			sockevent_proc_free(spr);
		} else {
			mask &= ~eventMask;
			sprp = &spr->spr_next;
		}
	}

	const unsigned int selEventMask = SEV_ACCEPT | SEV_SEND | SEV_RECV;

	if ((mask & selEventMask) != 0 && sock->sock_select.ss_endpt != NONE) {
		assert(sock->sock_selops != 0);

		unsigned int testOps = sock->sock_selops;

		if ((mask & (SEV_ACCEPT | SEV_RECV)) == 0)
			testOps &= ~SDEV_OP_RD;
		if ((mask & SEV_SEND) == 0)
			testOps &= ~SDEV_OP_WR;
		testOps &= ~SDEV_OP_ERR;

		if (testOps != 0) {
			unsigned int readyOps = sockevent_test_select(sock, testOps);

			if (readyOps != 0) {
				sockdriver_reply_select(&sock->sock_select,
				    sock->sock_id, readyOps);

				sock->sock_selops &= ~readyOps;

				if (sock->sock_selops == 0)
					sock->sock_select.ss_endpt = NONE;
			}
		}
	}

	if (mask & SEV_CLOSE) {
		assert(sock->sock_flags & (SFL_CLONED | SFL_CLOSING));
		sockevent_free(sock);
	}
}

/*
 * Process all pending events.  Events must still be blocked, so that if
 * handling one event generates a new event, that event is handled from here
 * rather than immediately.
 */
static void
sockevent_pump(void)
{
	assert(sockevent_working);

	for (;;) {
		struct sock *sock = SIMPLEQ_FIRST(&sockevent_pending);
		if (sock == NULL) {
			break;
		}

		SIMPLEQ_REMOVE_HEAD(&sockevent_pending, sock_next);

		const unsigned int events = sock->sock_events;
		assert(events != 0);
		sock->sock_events = 0;

		sockevent_fire(sock, events);
	}
}

/*
 * Return TRUE if any events are pending on any sockets, or FALSE otherwise.
 */
static int
sockevent_has_events(void)
{
    return SIMPLEQ_EMPTY(&sockevent_pending) ? 0 : 1;
}

/*
 * Raise the given bitwise-OR'ed set of events on the given socket object.
 * Depending on the context of the call, they events may or may not be
 * processed immediately.
 */
void
sockevent_raise(struct sock *sock, unsigned int mask)
{
	assert(sock != NULL);
	assert(sock->sock_ops != NULL);

	if (mask & SEV_CLOSE) {
		assert(mask == SEV_CLOSE);
		sockevent_fire(sock, SEV_CLOSE);
		return;
	}

	if (!sockevent_working) {
		sockevent_working = TRUE;

		sockevent_fire(sock, mask);

		if (sockevent_has_events())
			sockevent_pump();

		sockevent_working = FALSE;
		return;
	}

	assert(mask != 0);
	assert(mask <= UCHAR_MAX);

	if (sock->sock_events == 0)
		SIMPLEQ_INSERT_TAIL(&sockevent_pending, sock, sock_next);

	sock->sock_events |= mask;
}

/*
 * Set a pending error on the socket object, and wake up any suspended
 * operations that are affected by this.
 */
void
sockevent_set_error(struct sock *sock, int err)
{
	const unsigned int events = SEV_BIND | SEV_CONNECT | SEV_SEND | SEV_RECV;

	assert(sock != NULL);
	assert(err < 0);
	assert(sock->sock_ops != NULL);

	if (sock == NULL || err >= 0 || sock->sock_ops == NULL)
		return;

	sock->sock_err = err;
	sockevent_raise(sock, events);
}

/*
 * Initialize timer-related data structures.
 */
static void socktimer_init(void)
{
    SLIST_INIT(&socktimer);
    init_timer(&sockevent_timer);
}

/*
 * Check whether the given socket object has any suspended requests that have
 * now expired.  If so, cancel them.  Also, if the socket object has any
 * suspended requests with a timeout that has not yet expired, return the
 * earliest (relative) timeout of all of them, or TMR_NEVER if no such requests
 * are present.
 */
static clock_t
sockevent_expire(struct sock *sock, clock_t now)
{
	struct sockevent_proc *proc, **procp;
	clock_t lowest = TMR_NEVER;
	clock_t left;

	if (sock->sock_flags & SFL_CLOSING) {
		if ((sock->sock_opt & SO_LINGER) && tmr_is_first(sock->sock_linger, now)) {
			int r;

			assert(sock->sock_ops->sop_close != NULL);

			proc = sock->sock_proc;
			if (proc != NULL) {
				assert(proc->spr_event == SEV_CLOSE);
				assert(proc->spr_next == NULL);

				sock->sock_proc = NULL;

				sockdriver_reply_generic(&proc->spr_call, OK);

				sockevent_proc_free(proc);
			}

			r = sock->sock_ops->sop_close(sock, TRUE);

			assert(r == OK || r == SUSPEND);

			if (r == SUSPEND)
				sock->sock_opt &= ~SO_LINGER;
			else
				sockevent_free(sock);
		}

		return TMR_NEVER;
	}

	for (procp = &sock->sock_proc; *procp != NULL; ) {
		proc = *procp;

		if (proc->spr_timer == 0) {
			procp = &proc->spr_next;
			continue;
		}

		assert(proc->spr_event == SEV_SEND || proc->spr_event == SEV_RECV);

		if (tmr_is_first(proc->spr_time, now)) {
			*procp = proc->spr_next;

			if (proc->spr_event == SEV_SEND)
				sockevent_cancel_send(sock, proc, EWOULDBLOCK);
			else
				sockevent_cancel_recv(sock, proc, EWOULDBLOCK);

			sockevent_proc_free(proc);
			continue;
		}

		left = proc->spr_time - now;

		if (lowest == TMR_NEVER || lowest > left)
			lowest = left;

		procp = &proc->spr_next;
	}

	return lowest;
}

/*
 * The socket event alarm went off.  Go through the set of socket objects with
 * timers, and see if any of their requests have now expired.  Set a new alarm
 * as necessary.
 */
static void
socktimer_expire(int arg __unused)
{
	SLIST_HEAD(, sock) oldtimer;
	struct sock *sock, *tsock;
	clock_t now, lowest, left;
	int was_working;

	was_working = sockevent_working;
	if (!was_working)
		sockevent_working = TRUE;

	oldtimer = socktimer;
	SLIST_INIT(&socktimer);

	now = getticks();
	lowest = TMR_NEVER;

	SLIST_FOREACH_SAFE(sock, &oldtimer, sock_timer, tsock) {
		assert(sock->sock_flags & SFL_TIMER);
		sock->sock_flags &= ~SFL_TIMER;

		left = sockevent_expire(sock, now);

		if (left != TMR_NEVER) {
			if (lowest == TMR_NEVER || left < lowest)
				lowest = left;

			SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
			sock->sock_flags |= SFL_TIMER;
		}
	}

	if (lowest != TMR_NEVER)
		set_timer(&sockevent_timer, lowest, socktimer_expire, 0);

	if (!was_working) {
		if (sockevent_has_events())
			sockevent_pump();

		sockevent_working = FALSE;
	}
}

/*
 * Set a timer for the given (relative) number of clock ticks, adding the
 * associated socket object to the set of socket objects with timers, if it was
 * not already in that set.  Set a new alarm if necessary, and return the
 * absolute timeout for the timer.  Since the timers list is maintained lazily,
 * the caller need not take the object off the set if the call was canceled
 * later; see also socktimer_del().
 */
static clock_t
socktimer_add(struct sock *sock, clock_t ticks)
{
	clock_t now;
	clock_t expiry;

	assert(sock != NULL);
	assert(ticks <= TMRDIFF_MAX);

	if ((sock->sock_flags & SFL_TIMER) == 0) {
		SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
		sock->sock_flags |= SFL_TIMER;
	}

	now = getticks();
	expiry = now + ticks;

	if (!tmr_is_set(&sockevent_timer) ||
	    tmr_is_first(expiry, tmr_exp_time(&sockevent_timer))) {
		set_timer(&sockevent_timer, ticks, socktimer_expire, 0);
	}

	return expiry;
}

/*
 * Remove a socket object from the set of socket objects with timers.  Since
 * the timer list is maintained lazily, this needs to be done only right before
 * the socket object is freed.
 */
static void
socktimer_del(struct sock *sock)
{
    if (sock == NULL) {
        return;
    }
    if ((sock->sock_flags & SFL_TIMER) == 0) {
        return;
    }

    SLIST_REMOVE(&socktimer, sock, sock, sock_timer);
    sock->sock_flags &= ~SFL_TIMER;
}

/*
 * Bind a socket to a local address.
 */
static int
sockevent_bind(sockid_t id, const struct sockaddr *__restrict addr,
    socklen_t addr_len, endpoint_t user_endpt,
    const struct sockdriver_call *__restrict call)
{
    struct sock *sock;
    int r;

    sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    if (sock->sock_ops == NULL || sock->sock_ops->sop_bind == NULL)
        return EOPNOTSUPP;

    if (sock->sock_opt & SO_ACCEPTCONN)
        return EINVAL;

    r = sock->sock_ops->sop_bind(sock, addr, addr_len, user_endpt);
    if (r != SUSPEND)
        return r;

    if (call == NULL)
        return EINPROGRESS;

    sockevent_suspend(sock, SEV_BIND, call, user_endpt);
    return r;
}

/*
 * Connect a socket to a remote address.
 */
static int
sockevent_connect(sockid_t id, const struct sockaddr *__restrict addr,
    socklen_t addr_len, endpoint_t user_endpt,
    const struct sockdriver_call *call)
{
    struct sockdriver_call fakecall;
    struct sockevent_proc *spr;
    struct sock *sock;
    int r;
    int have_ctx;

    sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    if (sock->sock_ops->sop_connect == NULL)
        return EOPNOTSUPP;

    if (sock->sock_opt & SO_ACCEPTCONN)
        return EOPNOTSUPP;

    r = sock->sock_ops->sop_connect(sock, addr, addr_len, user_endpt);
    if (r != SUSPEND) {
        if (r == OK)
            sockevent_raise(sock, SEV_SEND);
        return r;
    }

    have_ctx = (call != NULL || sockevent_has_events());
    if (!have_ctx)
        return EINPROGRESS;

    if (call == NULL) {
        fakecall.sc_endpt = NONE;
        call = &fakecall;
    }

    assert(!sockevent_has_suspended(sock, SEV_SEND | SEV_RECV));

    sockevent_suspend(sock, SEV_CONNECT, call, user_endpt);

    if (call == &fakecall) {
        sockevent_pump();

        spr = sockevent_unsuspend(sock, call);
        if (spr != NULL) {
            sockevent_proc_free(spr);
            r = EINPROGRESS;
        } else if ((r = sock->sock_err) != OK) {
            sock->sock_err = OK;
        }
    }

    if (r == OK)
        sockevent_raise(sock, SEV_SEND);

    return r;
}

/*
 * Put a socket in listening mode.
 */
static int adjust_backlog(int backlog)
{
	if (backlog < 0)
		backlog = 0;

	if (backlog < SOMAXCONN) {
		unsigned int ub = (unsigned int)backlog;
		unsigned int tmp = ub + 1U + (ub >> 1);
		backlog = (tmp > (unsigned int)SOMAXCONN) ? SOMAXCONN : (int)tmp;
	} else if (backlog > SOMAXCONN) {
		backlog = SOMAXCONN;
	}

	return backlog;
}

static int
sockevent_listen(sockid_t id, int backlog)
{
	struct sock *sock;
	int result;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops == NULL || sock->sock_ops->sop_listen == NULL)
		return EOPNOTSUPP;

	backlog = adjust_backlog(backlog);

	result = sock->sock_ops->sop_listen(sock, backlog);

	if (result == OK) {
		sock->sock_opt |= SO_ACCEPTCONN;
		sockevent_raise(sock, SEV_ACCEPT);
	}

	return result;
}

/*
 * Accept a connection on a listening socket, creating a new socket.
 */
static sockid_t
sockevent_accept(sockid_t id, struct sockaddr *__restrict addr,
    socklen_t *__restrict addr_len, endpoint_t user_endpt,
    const struct sockdriver_call *__restrict call)
{
	struct sock *sock = sockhash_get(id);
	struct sock *newsock = NULL;
	sockid_t result;

	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_accept == NULL)
		return EOPNOTSUPP;

	result = sock->sock_ops->sop_accept(sock, addr, addr_len, user_endpt,
	    &newsock);

	if (result == SUSPEND) {
		assert(sock->sock_opt & SO_ACCEPTCONN);

		if (call == NULL)
			return EWOULDBLOCK;

		sockevent_suspend(sock, SEV_ACCEPT, call, user_endpt);
		return SUSPEND;
	}

	if (result >= 0)
		sockevent_accepted(sock, newsock, result);

	return result;
}

/*
 * Send regular and/or control data.
 */
static int
sockevent_send(sockid_t id, const struct sockdriver_data * __restrict data,
	size_t len, const struct sockdriver_data * __restrict ctl_data,
	socklen_t ctl_len, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt, int flags,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock;
	clock_t tmo;
	size_t min, off = 0;
	socklen_t ctl_off = 0;
	int r;
	int timer = FALSE;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	r = sock->sock_err;
	if (r != OK) {
		sock->sock_err = OK;
		return r;
	}

	if ((sock->sock_flags & SFL_SHUT_WR) != 0) {
		sockevent_sigpipe(sock, user_endpt, flags);
		return EPIPE;
	}

	if ((sock->sock_opt & SO_DONTROUTE) != 0)
		flags |= MSG_DONTROUTE;

	if (sock->sock_ops->sop_pre_send != NULL) {
		r = sock->sock_ops->sop_pre_send(sock, len, ctl_len, addr,
		    addr_len, user_endpt,
		    flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (r != OK)
			return r;
	}

	if (sock->sock_ops->sop_send == NULL)
		return EOPNOTSUPP;

	if ((flags & MSG_OOB) != 0) {
		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, 0);
		if (r == SUSPEND)
			panic("libsockevent: MSG_OOB send calls may not be suspended");
		return (r == OK) ? (int)off : r;
	}

	if (!sockevent_has_suspended(sock, SEV_SEND)) {
		min = sock->sock_slowat;
		if (min > len)
			min = len;

		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, min);
	} else {
		r = SUSPEND;
	}

	if (r == SUSPEND) {
		if (call != NULL) {
			if (sock->sock_stimeo != 0) {
				timer = TRUE;
				tmo = socktimer_add(sock, sock->sock_stimeo);
			} else {
				tmo = 0;
			}

			sockevent_suspend_data(sock, SEV_SEND, timer, call,
			    user_endpt, data, len, off, ctl_data, ctl_len,
			    ctl_off, flags, 0, tmo);
		} else {
			r = (off > 0 || ctl_off > 0) ? OK : EWOULDBLOCK;
		}
	} else if (r == EPIPE) {
		sockevent_sigpipe(sock, user_endpt, flags);
	}

	return (r == OK) ? (int)off : r;
}

/*
 * The inner part of the receive request handler.  An error returned from here
 * may be overridden by an error pending on the socket, although data returned
 * from here trumps such pending errors.
 */
static int
sockevent_recv_inner(struct sock * sock,
	const struct sockdriver_data * __restrict data,
	size_t len, size_t * __restrict off,
	const struct sockdriver_data * __restrict ctl_data,
	socklen_t ctl_len, socklen_t * __restrict ctl_off,
	struct sockaddr * __restrict addr,
	socklen_t * __restrict addr_len, endpoint_t user_endpt,
	int * __restrict flags, const struct sockdriver_call * __restrict call)
{
	clock_t time;
	size_t min;
	int r, oob, inflags, timer;

	inflags = *flags;
	*flags = 0;

	if (sock->sock_ops->sop_pre_recv != NULL &&
	    (r = sock->sock_ops->sop_pre_recv(sock, user_endpt,
	    inflags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))) != OK)
		return r;

	if (sock->sock_flags & SFL_SHUT_RD)
		return SOCKEVENT_EOF;

	if (sock->sock_ops->sop_recv == NULL)
		return EOPNOTSUPP;

	oob = ((inflags & MSG_OOB) != 0);

	if (oob && (sock->sock_opt & SO_OOBINLINE))
		return EINVAL;

	if (oob || !sockevent_has_suspended(sock, SEV_RECV)) {
		min = 0;
		if (!oob && sock->sock_err == OK) {
			min = sock->sock_rlowat;
			if (min > len)
				min = len;
		}

		r = sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
		    ctl_len, ctl_off, addr, addr_len, user_endpt, inflags, min,
		    flags);
	} else {
		r = SUSPEND;
	}

	assert(r <= 0 || r == SOCKEVENT_EOF);

	if (r == SUSPEND) {
		if (oob)
			panic("libsockevent: MSG_OOB receive calls may not be suspended");

		if (call != NULL && sock->sock_err == OK) {
			timer = (sock->sock_rtimeo != 0);
			time = timer ? socktimer_add(sock, sock->sock_rtimeo) : 0;

			sockevent_suspend_data(sock, SEV_RECV, timer, call,
			    user_endpt, data, len, *off, ctl_data,
			    ctl_len, *ctl_off, inflags, *flags, time);
		} else {
			r = EWOULDBLOCK;
		}
	}

	return r;
}

/*
 * Receive regular and/or control data.
 */
static int
sockevent_recv(sockid_t id, const struct sockdriver_data * __restrict data,
	size_t len, const struct sockdriver_data * __restrict ctl_data,
	socklen_t * __restrict ctl_len, struct sockaddr * __restrict addr,
	socklen_t * __restrict addr_len, endpoint_t user_endpt,
	int * __restrict flags, const struct sockdriver_call * __restrict call)
{
	struct sock *sock;
	size_t off = 0;
	socklen_t ctl_inlen;
	int r;

	if (ctl_len == NULL)
		return EINVAL;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	ctl_inlen = *ctl_len;
	*ctl_len = 0;

	r = sockevent_recv_inner(sock, data, len, &off, ctl_data, ctl_inlen,
	    ctl_len, addr, addr_len, user_endpt, flags, call);

	if (r == OK || (r != SUSPEND && (off > 0 || *ctl_len > 0))) {
		int ret = (int)off;
		return ret;
	}

	if (sock->sock_err != OK) {
		int err;
		assert(r != SUSPEND);
		err = sock->sock_err;
		sock->sock_err = OK;
		return err;
	}

	if (r == SOCKEVENT_EOF)
		return 0;

	return r;
}

/*
 * Process an I/O control call.
 */
static int
sockevent_ioctl(sockid_t id, unsigned long request,
	const struct sockdriver_data * __restrict data, endpoint_t user_endpt,
	const struct sockdriver_call * __restrict call __unused)
{
	struct sock *sock;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	switch (request) {
	case FIONREAD: {
		size_t size = 0;
		if (sock->sock_ops != NULL &&
		    !(sock->sock_flags & SFL_SHUT_RD) &&
		    sock->sock_ops->sop_test_recv != NULL)
			(void)sock->sock_ops->sop_test_recv(sock, 0, &size);

		{
			int val = (int)size;
			return sockdriver_copyout(data, 0, &val, sizeof(val));
		}
	}
	default:
		break;
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_ioctl == NULL)
		return ENOTTY;

	{
		int r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

		if (r == SUSPEND)
			panic("libsockevent: socket driver suspended IOCTL 0x%lx",
			    request);

		return r;
	}
}

/*
 * Set socket options.
 */
static int
sockevent_setsockopt(sockid_t id, int level, int name,
    const struct sockdriver_data *data, socklen_t len)
{
	struct sock *sock;
	struct linger linger;
	struct timeval tv;
	clock_t secs, ticks, hz;
	int r, val;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (level == SOL_SOCKET) {
		switch (name) {
		case SO_DEBUG:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_OOBINLINE:
		case SO_REUSEPORT:
		case SO_NOSIGPIPE:
		case SO_TIMESTAMP:
			if ((r = sockdriver_copyin_opt(data, &val, sizeof(val), len)) != OK)
				return r;

			if (val)
				sock->sock_opt |= (unsigned int)name;
			else
				sock->sock_opt &= ~(unsigned int)name;

			if (sock->sock_ops->sop_setsockmask != NULL)
				sock->sock_ops->sop_setsockmask(sock, sock->sock_opt);

			if (name == SO_OOBINLINE && val)
				sockevent_raise(sock, SEV_RECV);

			return OK;

		case SO_LINGER:
			if ((r = sockdriver_copyin_opt(data, &linger, sizeof(linger), len)) != OK)
				return r;

			if (linger.l_onoff) {
				if (linger.l_linger < 0)
					return EINVAL;

				hz = sys_hz();
				secs = (clock_t)linger.l_linger;
				if (secs >= TMRDIFF_MAX / hz)
					return EDOM;

				sock->sock_opt |= SO_LINGER;
				sock->sock_linger = secs * hz;
			} else {
				sock->sock_opt &= ~SO_LINGER;
				sock->sock_linger = 0;
			}

			return OK;

		case SO_SNDLOWAT:
		case SO_RCVLOWAT: {
			size_t *lowat;
			int sev;

			if ((r = sockdriver_copyin_opt(data, &val, sizeof(val), len)) != OK)
				return r;

			if (val <= 0)
				return EINVAL;

			if (name == SO_SNDLOWAT) {
				lowat = &sock->sock_slowat;
				sev = SEV_SEND;
			} else {
				lowat = &sock->sock_rlowat;
				sev = SEV_RECV;
			}

			*lowat = (size_t)val;
			sockevent_raise(sock, sev);

			return OK;
		}

		case SO_SNDTIMEO:
		case SO_RCVTIMEO: {
			clock_t *ptimeo;

			if ((r = sockdriver_copyin_opt(data, &tv, sizeof(tv), len)) != OK)
				return r;

			if (tv.tv_sec < 0 || tv.tv_usec < 0 ||
			    (unsigned long)tv.tv_usec >= US)
				return EINVAL;

			hz = sys_hz();
			if ((clock_t)tv.tv_sec >= TMRDIFF_MAX / hz)
				return EDOM;

			ticks = (clock_t)tv.tv_sec * hz +
			    (clock_t)((tv.tv_usec * hz + US - 1) / US);

			ptimeo = (name == SO_SNDTIMEO) ? &sock->sock_stimeo : &sock->sock_rtimeo;
			*ptimeo = ticks;

			return OK;
		}

		case SO_ACCEPTCONN:
		case SO_ERROR:
		case SO_TYPE:
			return ENOPROTOOPT;

		default:
			break;
		}
	}

	if (sock->sock_ops->sop_setsockopt == NULL)
		return ENOPROTOOPT;

	return sock->sock_ops->sop_setsockopt(sock, level, name, data, len);
}

/*
 * Retrieve socket options.
 */
static int copyout_int_opt(const struct sockdriver_data *data, socklen_t *len, int val)
{
	return sockdriver_copyout_opt(data, &val, sizeof(val), len);
}

static void ticks_to_timeval(clock_t ticks, int hz, struct timeval *tv)
{
	if (hz > 0) {
		tv->tv_sec = ticks / hz;
		tv->tv_usec = (ticks % hz) * US / hz;
	} else {
		tv->tv_sec = 0;
		tv->tv_usec = 0;
	}
}

static int
sockevent_getsockopt(sockid_t id, int level, int name,
	const struct sockdriver_data * __restrict data,
	socklen_t * __restrict len)
{
	struct sock *sock;
	struct linger linger;
	struct timeval tv;
	clock_t ticks;
	int val;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (level == SOL_SOCKET) {
		int hz = sys_hz();

		switch (name) {
		case SO_DEBUG:
		case SO_ACCEPTCONN:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_OOBINLINE:
		case SO_REUSEPORT:
		case SO_NOSIGPIPE:
		case SO_TIMESTAMP:
			val = !!(sock->sock_opt & (unsigned int)name);
			return copyout_int_opt(data, len, val);

		case SO_LINGER:
			linger.l_onoff = !!(sock->sock_opt & SO_LINGER);
			linger.l_linger = (hz > 0) ? (sock->sock_linger / hz) : 0;
			return sockdriver_copyout_opt(data, &linger, sizeof(linger), len);

		case SO_ERROR:
			val = -sock->sock_err;
			if (val != OK)
				sock->sock_err = OK;
			return copyout_int_opt(data, len, val);

		case SO_TYPE:
			val = sock->sock_type;
			return copyout_int_opt(data, len, val);

		case SO_SNDLOWAT:
			val = (int)sock->sock_slowat;
			return copyout_int_opt(data, len, val);

		case SO_RCVLOWAT:
			val = (int)sock->sock_rlowat;
			return copyout_int_opt(data, len, val);

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			ticks = (name == SO_SNDTIMEO) ? sock->sock_stimeo : sock->sock_rtimeo;
			ticks_to_timeval(ticks, hz, &tv);
			return sockdriver_copyout_opt(data, &tv, sizeof(tv), len);

		default:
			break;
		}
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_getsockopt == NULL)
		return ENOPROTOOPT;

	return sock->sock_ops->sop_getsockopt(sock, level, name, data, len);
}

/*
 * Retrieve a socket's local address.
 */
static int
sockevent_getsockname(sockid_t id, struct sockaddr * __restrict addr,
    socklen_t * __restrict addr_len)
{
    struct sock *sock;

    sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    if (sock->sock_ops == NULL || sock->sock_ops->sop_getsockname == NULL)
        return EOPNOTSUPP;

    return sock->sock_ops->sop_getsockname(sock, addr, addr_len);
}

/*
 * Retrieve a socket's remote address.
 */
static int
sockevent_getpeername(sockid_t id, struct sockaddr * __restrict addr,
    socklen_t * __restrict addr_len)
{
	struct sock *sock = sockhash_get(id);
	int (*getpeername_fn)(struct sock *, struct sockaddr *, socklen_t *);

	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_opt & SO_ACCEPTCONN) {
		return ENOTCONN;
	}

	if (sock->sock_ops == NULL) {
		return EOPNOTSUPP;
	}

	getpeername_fn = sock->sock_ops->sop_getpeername;
	if (getpeername_fn == NULL) {
		return EOPNOTSUPP;
	}

	return getpeername_fn(sock, addr, addr_len);
}

/*
 * Mark the socket object as shut down for sending and/or receiving.  The flags
 * parameter may be a bitwise-OR'ed combination of SFL_SHUT_RD and SFL_SHUT_WR.
 * This function will wake up any suspended requests affected by this change,
 * but it will not invoke the sop_shutdown() callback function on the socket.
 * The function may in fact be called from sop_shutdown() before completion to
 * mark the socket as shut down as reflected by sockevent_is_shutdown().
 */
void sockevent_set_shutdown(struct sock *sock, unsigned int flags)
{
    unsigned int new_flags;
    unsigned int mask;

    if (sock == NULL || sock->sock_ops == NULL)
        return;

    if ((flags & ~(SFL_SHUT_RD | SFL_SHUT_WR)) != 0U)
        return;

    new_flags = flags & ~(unsigned int)sock->sock_flags;
    if (new_flags == 0U)
        return;

    sock->sock_flags |= new_flags;

    mask = 0U;
    if ((new_flags & SFL_SHUT_RD) != 0U)
        mask |= SEV_RECV;
    if ((new_flags & SFL_SHUT_WR) != 0U)
        mask |= SEV_SEND;
    if ((sock->sock_opt & SO_ACCEPTCONN) != 0U)
        mask |= SEV_ACCEPT;

    if (mask != 0U)
        sockevent_raise(sock, mask);
}

/*
 * Shut down socket send and receive operations.
 */
static int
sockevent_shutdown(sockid_t id, int how)
{
	struct sock *sock;
	unsigned int flags;
	int result;

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	switch (how) {
	case SHUT_RD:
		flags = SFL_SHUT_RD;
		break;
	case SHUT_WR:
		flags = SFL_SHUT_WR;
		break;
	case SHUT_RDWR:
		flags = SFL_SHUT_RD | SFL_SHUT_WR;
		break;
	default:
		flags = 0;
		break;
	}

	if (sock->sock_ops == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_shutdown != NULL) {
		result = sock->sock_ops->sop_shutdown(sock, flags);
	} else {
		result = OK;
	}

	if (result == OK) {
		sockevent_set_shutdown(sock, flags);
	}

	return result;
}

/*
 * Close a socket.
 */
static int
sockevent_close(sockid_t id, const struct sockdriver_call *call)
{
	struct sock *sock = sockhash_get(id);
	int r;

	if (sock == NULL)
		return EINVAL;

	assert(sock->sock_proc == NULL);
	sock->sock_select.ss_endpt = NONE;

	{
		int linger_enabled = (sock->sock_opt & SO_LINGER) != 0;
		int force = (linger_enabled && sock->sock_linger == 0);

		if (sock->sock_ops != NULL && sock->sock_ops->sop_close != NULL)
			r = sock->sock_ops->sop_close(sock, force);
		else
			r = OK;

		assert(r == OK || r == SUSPEND);

		if (r == OK) {
			sockevent_free(sock);
			return OK;
		}

		sock->sock_flags |= SFL_CLOSING;

		if (force)
			return OK;

		if (linger_enabled) {
			int should_suspend;

			sock->sock_linger = socktimer_add(sock, sock->sock_linger);
			should_suspend = (call != NULL);

			if (should_suspend) {
				sockevent_suspend(sock, SEV_CLOSE, call, NONE);
				return r;
			}

			return OK;
		}

		return OK;
	}
}

/*
 * Cancel a suspended send request.
 */
static void
sockevent_cancel_send(struct sock *sock, struct sockevent_proc *spr, int err)
{
	int result;

	if (spr == NULL) {
		if (sock != NULL)
			sockevent_raise(sock, SEV_SEND);
		return;
	}

	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
		result = (int)spr->spr_dataoff;
	else
		result = err;

	sockdriver_reply_generic(&spr->spr_call, result);

	if (sock != NULL)
		sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static void
sockevent_cancel_recv(struct sock *sock, struct sockevent_proc *spr, int err)
{
	const size_t dataoff = spr->spr_dataoff;
	const size_t ctloff = spr->spr_ctloff;
	const int r = (dataoff > 0 || ctloff > 0) ? (int)dataoff : err;

	sockdriver_reply_recv(&spr->spr_call, r, ctloff, NULL, 0, spr->spr_rflags);
	sockevent_raise(sock, SEV_RECV);
}

/*
 * Cancel a previous request that may currently be suspended.  The cancel
 * operation itself does not have a reply.  Instead, if the given request was
 * found to be suspended, that request must be aborted and an appropriate reply
 * must be sent for the request.  If no matching request was found, no reply
 * must be sent at all.
 */
static void
sockevent_cancel(sockid_t id, const struct sockdriver_call *call)
{
	struct sock *sock = sockhash_get(id);
	if (sock == NULL)
		return;

	struct sockevent_proc *spr = sockevent_unsuspend(sock, call);
	if (spr == NULL)
		return;

	uint32_t event = spr->spr_event;
	struct sockdriver_call *sc = &spr->spr_call;

	switch (event) {
	case SEV_BIND:
	case SEV_CONNECT:
		assert(sc->sc_endpt != NONE);
		sockdriver_reply_generic(sc, EINTR);
		break;

	case SEV_ACCEPT:
		sockdriver_reply_accept(sc, EINTR, NULL, 0);
		break;

	case SEV_SEND:
		sockevent_cancel_send(sock, spr, EINTR);
		break;

	case SEV_RECV:
		sockevent_cancel_recv(sock, spr, EINTR);
		break;

	case SEV_CLOSE:
		sockdriver_reply_generic(sc, EINPROGRESS);
		break;

	default:
		panic("libsockevent: process suspended on unknown event 0x%x",
		    event);
	}

	sockevent_proc_free(spr);
}

/*
 * Process a select request.
 */
static int
sockevent_select(sockid_t id, unsigned int ops, const struct sockdriver_select *sel)
{
	struct sock *sock;
	unsigned int requested_ops, ready_ops, pending_ops;
	int notify_requested;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	notify_requested = ((ops & SDEV_NOTIFY) != 0);
	requested_ops = ops & (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR);

	ready_ops = sockevent_test_select(sock, requested_ops);

	assert(!(sock->sock_selops & ready_ops));

	pending_ops = requested_ops & ~ready_ops;

	if (notify_requested && pending_ops != 0) {
		if (sel == NULL)
			return EINVAL;

		if (sock->sock_select.ss_endpt != NONE &&
		    sock->sock_select.ss_endpt != sel->ss_endpt) {
			printf("libsockevent: no support for multiple select callers yet\n");
			return EIO;
		}

		if (sock->sock_select.ss_endpt == NONE) {
			assert(sel->ss_endpt != NONE);
			sock->sock_select = *sel;
			sock->sock_selops = pending_ops;
		} else {
			sock->sock_selops |= pending_ops;
		}
	}

	return (int)ready_ops;
}

/*
 * An alarm has triggered.  Expire any timers.  Socket drivers that do not pass
 * clock notification messages to libsockevent must call expire_timers(3)
 * themselves instead.
 */
static void sockevent_alarm(clock_t now) { expire_timers(now); }

static const struct sockdriver sockevent_tab = {
	.sdr_socket		= sockevent_socket,
	.sdr_socketpair		= sockevent_socketpair,
	.sdr_bind		= sockevent_bind,
	.sdr_connect		= sockevent_connect,
	.sdr_listen		= sockevent_listen,
	.sdr_accept		= sockevent_accept,
	.sdr_send		= sockevent_send,
	.sdr_recv		= sockevent_recv,
	.sdr_ioctl		= sockevent_ioctl,
	.sdr_setsockopt		= sockevent_setsockopt,
	.sdr_getsockopt		= sockevent_getsockopt,
	.sdr_getsockname	= sockevent_getsockname,
	.sdr_getpeername	= sockevent_getpeername,
	.sdr_shutdown		= sockevent_shutdown,
	.sdr_close		= sockevent_close,
	.sdr_cancel		= sockevent_cancel,
	.sdr_select		= sockevent_select,
	.sdr_alarm		= sockevent_alarm
};

/*
 * Initialize the socket event library.
 */
void
sockevent_init(sockevent_socket_cb_t socket_cb)
{
	assert(socket_cb != NULL);
	sockevent_socket_cb = socket_cb;

	SIMPLEQ_INIT(&sockevent_pending);

	sockhash_init();
	socktimer_init();
	sockevent_proc_init();

	sockdriver_announce();

	sockevent_working = FALSE;
}

/*
 * Process a socket driver request message.
 */
void sockevent_process(const message *m_ptr, int ipc_status)
{
	int prev_working = sockevent_working;

	assert(!prev_working);
	sockevent_working = TRUE;

	sockdriver_process(&sockevent_tab, m_ptr, ipc_status);

	if (sockevent_has_events()) {
		sockevent_pump();
	}

	sockevent_working = prev_working;
}
