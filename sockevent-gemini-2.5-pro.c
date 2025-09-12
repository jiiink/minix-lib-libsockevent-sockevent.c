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
	for (size_t i = 0; i < (sizeof(sockhash) / sizeof(sockhash[0])); i++) {
		SLIST_INIT(&sockhash[i]);
	}
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
static unsigned int
sockhash_slot(sockid_t id)
{
	const unsigned int mix_shift = 16;
	const sockid_t mixed_id = id + (id >> mix_shift);

	return mixed_id % SOCKHASH_SLOTS;
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *
sockhash_get(sockid_t id)
{
	const unsigned int slot = sockhash_slot(id);
	const unsigned int sockhash_size = sizeof(sockhash) / sizeof(sockhash[0]);

	if (slot >= sockhash_size) {
		return NULL;
	}

	struct sock *sock;
	SLIST_FOREACH(sock, &sockhash[slot], sock_hash) {
		if (sock->sock_id == id) {
			return sock;
		}
	}

	return NULL;
}

/*
 * Add a sock object to the hash table.  The sock object must have a valid ID
 * in its 'sock_id' field, and must not be in the hash table already.
 */
static void sockhash_add(struct sock *sock)
{
	if (sock == NULL) {
		return;
	}

	unsigned int slot = sockhash_slot(sock->sock_id);
	SLIST_INSERT_HEAD(&sockhash[slot], sock, sock_hash);
}

/*
 * Remove a sock object from the hash table.  The sock object must be in the
 * hash table.
 */
static void
sockhash_del(struct sock *sock)
{
	if (!sock) {
		return;
	}

	unsigned int slot = sockhash_slot(sock->sock_id);
	SLIST_REMOVE(&sockhash[slot], sock, sock, sock_hash);
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
	assert(sock != NULL);

	*sock = (struct sock){
		.sock_id = id,
		.sock_domain = domain,
		.sock_type = type,
		.sock_ops = ops,
		.sock_slowat = 1,
		.sock_rlowat = 1,
		.sock_select.ss_endpt = NONE,
	};

	sockhash_add(sock);
}

/*
 * Initialize a new socket that will serve as an accepted socket on the given
 * listening socket 'sock'.  The new socket is given as 'newsock', and its new
 * socket identifier is given as 'newid'.  This function always succeeds.
 */
void
sockevent_clone(const struct sock *sock, struct sock *newsock, sockid_t newid)
{
	if (sock == NULL || newsock == NULL) {
		return;
	}

	sockevent_reset(newsock, newid, (int)sock->sock_domain,
	    sock->sock_type, sock->sock_ops);

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
	if (newsock != NULL) {
		sockevent_clone(sock, newsock, newid);
	} else {
		newsock = sockhash_get(newid);
	}

	if (newsock == NULL) {
		panic("libsockdriver: socket driver returned unknown "
		      "ID %d from accept callback", newid);
	}

	assert(newsock->sock_flags & SFL_CLONED);
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
	struct sock *sock;
	const struct sockevent_ops *ops;
	sockid_t r;

	if (domain < 0 || domain > UINT8_MAX)
		return EAFNOSUPPORT;

	if (sockevent_socket_cb == NULL)
		return EPROTONOSUPPORT;

	r = sockevent_socket_cb(domain, type, protocol, user_endpt, &sock,
	    &ops);
	if (r < 0)
		return r;

	if (sock == NULL || ops == NULL)
		return EPROTO; /* Callback contract violation */

	sockevent_reset(sock, r, domain, type, ops);

	*sockp = sock;
	return OK;
}

/*
 * Free a previously allocated sock object.
 */
static void
sockevent_free(struct sock *sock)
{
	if (sock == NULL) {
		return;
	}

	assert(sock->sock_proc == NULL);

	socktimer_del(sock);
	sockhash_del(sock);

	const struct sockevent_ops *ops = sock->sock_ops;
	sock->sock_ops = NULL;

	if (ops && ops->sop_free) {
		ops->sop_free(sock);
	}
}

/*
 * Create a new socket.
 */
static sockid_t
sockevent_socket(int domain, int type, int protocol, endpoint_t user_endpt)
{
	struct sock *sock;
	int result;

	result = sockevent_alloc(domain, type, protocol, user_endpt, &sock);
	if (result != OK) {
		return result;
	}

	return sock->sock_id;
}

/*
 * Create a pair of connected sockets.
 */
static int
sockevent_socketpair(int domain, int type, int protocol, endpoint_t user_endpt,
	sockid_t id[2])
{
	struct sock *sock1 = NULL;
	struct sock *sock2 = NULL;
	int r;

	if ((r = sockevent_alloc(domain, type, protocol, user_endpt,
	    &sock1)) != OK)
		goto fail;

	if (sock1->sock_ops->sop_pair == NULL) {
		r = EOPNOTSUPP;
		goto fail;
	}

	if ((r = sockevent_alloc(domain, type, protocol, user_endpt,
	    &sock2)) != OK)
		goto fail;

	assert(sock1->sock_ops == sock2->sock_ops);

	if ((r = sock1->sock_ops->sop_pair(sock1, sock2, user_endpt)) != OK)
		goto fail;

	id[0] = sock1->sock_id;
	id[1] = sock2->sock_id;
	return OK;

fail:
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
	if (!sock || sock->sock_type != SOCK_STREAM || (flags & MSG_NOSIGNAL) ||
	    (sock->sock_opt & SO_NOSIGPIPE)) {
		return;
	}

	sys_kill(user_endpt, SIGPIPE);
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

	spr = sockevent_proc_alloc();
	if (spr == NULL) {
		return;
	}

	spr->spr_next = NULL;
	spr->spr_event = event;
	spr->spr_timer = FALSE;
	spr->spr_call = *call;
	spr->spr_endpt = user_endpt;

	sprp = &sock->sock_proc;
	while (*sprp != NULL) {
		sprp = &(*sprp)->spr_next;
	}
	*sprp = spr;
}

/*
 * Suspend a request with data, that is, a send or receive request.
 */
static void
sockevent_suspend_data(struct sock *sock, unsigned int event, int timer,
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt,
	const struct sockdriver_data * __restrict data, size_t len, size_t off,
	const struct sockdriver_data * __restrict ctl, socklen_t ctl_len,
	socklen_t ctl_off, int flags, int rflags, clock_t time)
{
	if (sock == NULL || call == NULL)
		panic("libsockevent: NULL pointer argument");

	struct sockevent_proc *spr = sockevent_proc_alloc();
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

	struct sockevent_proc **sprp = &sock->sock_proc;
	while (*sprp != NULL) {
		sprp = &(*sprp)->spr_next;
	}
	*sprp = spr;
}

/*
 * Return TRUE if there are any suspended requests on the given socket's queue
 * that match any of the events in the given event mask, or FALSE otherwise.
 */
static int
sockevent_has_suspended(const struct sock *sock, unsigned int mask)
{
	if (!sock) {
		return FALSE;
	}

	for (const struct sockevent_proc *spr = sock->sock_proc; spr != NULL; spr = spr->spr_next) {
		if (spr->spr_event & mask) {
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
sockevent_unsuspend(struct sock * sock, const struct sockdriver_call * call)
{
	if (sock == NULL || call == NULL) {
		return NULL;
	}

	struct sockevent_proc **linkp = &sock->sock_proc;
	while (*linkp != NULL) {
		struct sockevent_proc *spr = *linkp;

		if (spr->spr_call.sc_endpt == call->sc_endpt &&
		    spr->spr_call.sc_req == call->sc_req) {
			*linkp = spr->spr_next;
			return spr;
		}
		linkp = &spr->spr_next;
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
handle_connect_bind(struct sock * sock, struct sockevent_proc * spr)
{
	sockid_t r;

	r = sock->sock_err;
	if (r != OK) {
		sock->sock_err = OK;
	}

	sockdriver_reply_generic(&spr->spr_call, r);

	return TRUE;
}

static int
sockevent_resume_accept(struct sock * sock, struct sockevent_proc * spr)
{
	struct sock *newsock = NULL;
	char addr[SOCKADDR_MAX];
	socklen_t addr_len = 0;
	sockid_t r;

	assert(sock->sock_opt & SO_ACCEPTCONN);

	r = sock->sock_ops->sop_accept(sock, (struct sockaddr *)&addr,
	    &addr_len, spr->spr_endpt, &newsock);

	if (r == SUSPEND) {
		return FALSE;
	}

	if (r >= 0) {
		assert(addr_len <= sizeof(addr));
		sockevent_accepted(sock, newsock, r);
	}

	sockdriver_reply_accept(&spr->spr_call, r, (struct sockaddr *)&addr,
	    addr_len);

	return TRUE;
}

static int
sockevent_resume_send(struct sock * sock, struct sockevent_proc * spr)
{
	struct sockdriver_data data, ctl;
	size_t len, min;
	sockid_t r;

	if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
		if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
			r = (sockid_t)spr->spr_dataoff;
		} else if (sock->sock_err != OK) {
			r = sock->sock_err;
			sock->sock_err = OK;
		} else {
			r = EPIPE;
		}
	} else {
		sockdriver_unpack_data(&data, &spr->spr_call, &spr->spr_data,
		    spr->spr_datalen);
		sockdriver_unpack_data(&ctl, &spr->spr_call, &spr->spr_ctl,
		    spr->spr_ctllen);

		len = spr->spr_datalen - spr->spr_dataoff;
		min = sock->sock_slowat;
		if (min > len) {
			min = len;
		}

		r = sock->sock_ops->sop_send(sock, &data, len,
		    &spr->spr_dataoff, &ctl,
		    spr->spr_ctllen - spr->spr_ctloff, &spr->spr_ctloff,
		    NULL, 0, spr->spr_endpt, spr->spr_flags, min);

		assert(r <= 0);

		if (r == SUSPEND) {
			return FALSE;
		}

		if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
			r = (sockid_t)spr->spr_dataoff;
		}
	}

	if (r == EPIPE) {
		sockevent_sigpipe(sock, spr->spr_endpt, spr->spr_flags);
	}

	sockdriver_reply_generic(&spr->spr_call, r);

	return TRUE;
}

static int
sockevent_resume_recv(struct sock * sock, struct sockevent_proc * spr)
{
	struct sockdriver_data data, ctl;
	char addr[SOCKADDR_MAX];
	socklen_t addr_len = 0;
	size_t len, min;
	sockid_t r;

	if (sock->sock_flags & SFL_SHUT_RD) {
		r = SOCKEVENT_EOF;
	} else {
		len = spr->spr_datalen - spr->spr_dataoff;

		if (sock->sock_err == OK) {
			min = sock->sock_rlowat;
			if (min > len) {
				min = len;
			}
		} else {
			min = 0;
		}

		sockdriver_unpack_data(&data, &spr->spr_call, &spr->spr_data,
		    spr->spr_datalen);
		sockdriver_unpack_data(&ctl, &spr->spr_call, &spr->spr_ctl,
		    spr->spr_ctllen);

		r = sock->sock_ops->sop_recv(sock, &data, len,
		    &spr->spr_dataoff, &ctl,
		    spr->spr_ctllen - spr->spr_ctloff, &spr->spr_ctloff,
		    (struct sockaddr *)&addr, &addr_len, spr->spr_endpt,
		    spr->spr_flags, min, &spr->spr_rflags);

		assert(addr_len <= sizeof(addr));

		if (r == SUSPEND) {
			if (sock->sock_err == OK) {
				return FALSE;
			}
			r = SOCKEVENT_EOF;
		}
	}

	if (r == OK || spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
		r = (sockid_t)spr->spr_dataoff;
	} else if (sock->sock_err != OK) {
		r = sock->sock_err;
		sock->sock_err = OK;
	} else if (r == SOCKEVENT_EOF) {
		r = 0; /* EOF */
	}

	sockdriver_reply_recv(&spr->spr_call, r, spr->spr_ctloff,
	    (struct sockaddr *)&addr, addr_len, spr->spr_rflags);

	return TRUE;
}

static int
sockevent_resume(struct sock * sock, struct sockevent_proc * spr)
{
	switch (spr->spr_event) {
	case SEV_CONNECT:
		if (spr->spr_call.sc_endpt == NONE) {
			return TRUE;
		}
		/* FALLTHROUGH */
	case SEV_BIND:
		return handle_connect_bind(sock, spr);
	case SEV_ACCEPT:
		return sockevent_resume_accept(sock, spr);
	case SEV_SEND:
		return sockevent_resume_send(sock, spr);
	case SEV_RECV:
		return sockevent_resume_recv(sock, spr);
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
sockevent_test_readable(struct sock * sock)
{
	if ((sock->sock_flags & SFL_SHUT_RD) || (sock->sock_err != OK)) {
		return TRUE;
	}

	if (sock->sock_opt & SO_ACCEPTCONN) {
		if (sock->sock_ops->sop_test_accept) {
			return sock->sock_ops->sop_test_accept(sock) != SUSPEND;
		}
	} else {
		if (sock->sock_ops->sop_test_recv) {
			return sock->sock_ops->sop_test_recv(sock,
			    sock->sock_rlowat, NULL) != SUSPEND;
		}
	}

	return TRUE;
}

/*
 * Return TRUE if the given socket is ready for writing for a select call, or
 * FALSE otherwise.
 */
static int
sockevent_test_writable(struct sock * sock)
{
	if (sock == NULL) {
		return FALSE;
	}

	if (sock->sock_err != OK ||
	    (sock->sock_flags & SFL_SHUT_WR) ||
	    sock->sock_ops == NULL ||
	    sock->sock_ops->sop_test_send == NULL) {
		return TRUE;
	}

	/*
	 * Test whether sends would block.  The low send watermark is relevant
	 * for stream-type sockets only.
	 */
	int r = sock->sock_ops->sop_test_send(sock, sock->sock_slowat);

	return (r != SUSPEND);
}

/*
 * Test whether any of the given select operations are ready on the given
 * socket.  Return the subset of ready operations; zero if none.
 */
static unsigned int
sockevent_test_select(struct sock *sock, unsigned int ops)
{
	assert(!(ops & ~(SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR)));

	/*
	 * We do not support the "bind in progress" case here.  If a blocking
	 * bind call is in progress, the file descriptor should not be ready
	 * for either reading or writing.  Currently, socket drivers will have
	 * to cover this case themselves.  Otherwise we would have to check the
	 * queue of suspended calls, or create a custom flag for this.
	 */

	unsigned int ready_ops = 0;

	if ((ops & SDEV_OP_RD) && sockevent_test_readable(sock)) {
		ready_ops |= SDEV_OP_RD;
	}

	if ((ops & SDEV_OP_WR) && sockevent_test_writable(sock)) {
		ready_ops |= SDEV_OP_WR;
	}

	/* TODO: OOB receive support. */

	return ready_ops;
}

/*
 * Fire the given mask of events on the given socket object now.
 */
static void
process_pending_syscalls(struct sock *sock, unsigned int *mask_ptr)
{
	struct sockevent_proc *spr, **sprp;
	unsigned int mask = *mask_ptr;

	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL;) {
		unsigned int flag = spr->spr_event;

		if ((mask & flag) && sockevent_resume(sock, spr)) {
			*sprp = spr->spr_next;
			sockevent_proc_free(spr);
		} else {
			mask &= ~flag;
			sprp = &spr->spr_next;
		}
	}

	*mask_ptr = mask;
}

static void
process_pending_select(struct sock *sock, unsigned int mask)
{
	unsigned int ops, satisfied_ops;

	if (!(mask & (SEV_ACCEPT | SEV_SEND | SEV_RECV)) ||
	    sock->sock_select.ss_endpt == NONE) {
		return;
	}

	assert(sock->sock_selops != 0);

	ops = 0;
	if (mask & (SEV_ACCEPT | SEV_RECV)) {
		ops |= sock->sock_selops & SDEV_OP_RD;
	}
	if (mask & SEV_SEND) {
		ops |= sock->sock_selops & SDEV_OP_WR;
	}

	if (ops == 0) {
		return;
	}

	satisfied_ops = sockevent_test_select(sock, ops);
	if (satisfied_ops == 0) {
		return;
	}

	sockdriver_reply_select(&sock->sock_select, sock->sock_id,
	    satisfied_ops);

	sock->sock_selops &= ~satisfied_ops;

	if (sock->sock_selops == 0) {
		sock->sock_select.ss_endpt = NONE;
	}
}

static void
sockevent_fire(struct sock *sock, unsigned int mask)
{
	if (mask & SEV_CONNECT) {
		mask |= SEV_SEND;
	}

	process_pending_syscalls(sock, &mask);

	process_pending_select(sock, mask);

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

	while (!SIMPLEQ_EMPTY(&sockevent_pending)) {
		struct sock * const sock = SIMPLEQ_FIRST(&sockevent_pending);
		SIMPLEQ_REMOVE_HEAD(&sockevent_pending, sock_next);

		const unsigned int mask = sock->sock_events;
		assert(mask != 0);
		sock->sock_events = 0;

		sockevent_fire(sock, mask);
	}
}

/*
 * Return TRUE if any events are pending on any sockets, or FALSE otherwise.
 */
static int
sockevent_has_events(void)
{
	return !SIMPLEQ_EMPTY(&sockevent_pending);
}

/*
 * Raise the given bitwise-OR'ed set of events on the given socket object.
 * Depending on the context of the call, they events may or may not be
 * processed immediately.
 */
void
sockevent_raise(struct sock * sock, unsigned int mask)
{
	assert(sock->sock_ops != NULL);

	if (mask & SEV_CLOSE) {
		assert(mask == SEV_CLOSE);
		sockevent_fire(sock, mask);
		return;
	}

	if (sockevent_working) {
		assert(mask != 0);
		assert(mask <= UCHAR_MAX);

		if (sock->sock_events == 0) {
			SIMPLEQ_INSERT_TAIL(&sockevent_pending, sock,
			    sock_next);
		}
		sock->sock_events |= mask;
		return;
	}

	sockevent_working = TRUE;
	sockevent_fire(sock, mask);

	if (sockevent_has_events()) {
		sockevent_pump();
	}

	sockevent_working = FALSE;
}

/*
 * Set a pending error on the socket object, and wake up any suspended
 * operations that are affected by this.
 */
void
sockevent_set_error(struct sock *sock, int err)
{
	if (!sock || !sock->sock_ops || err >= 0) {
		return;
	}

	sock->sock_err = err;

	const unsigned int error_events = SEV_BIND | SEV_CONNECT | SEV_SEND | SEV_RECV;
	sockevent_raise(sock, error_events);
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
static void
handle_expired_request(struct sock * sock, struct sockevent_proc * spr)
{
	assert(spr->spr_event == SEV_SEND || spr->spr_event == SEV_RECV);

	if (spr->spr_event == SEV_SEND) {
		sockevent_cancel_send(sock, spr, EWOULDBLOCK);
	} else {
		sockevent_cancel_recv(sock, spr, EWOULDBLOCK);
	}
	sockevent_proc_free(spr);
}

static clock_t
process_socket_requests(struct sock * sock, clock_t now)
{
	struct sockevent_proc **sprp = &sock->sock_proc;
	clock_t lowest = TMR_NEVER;

	while (*sprp != NULL) {
		struct sockevent_proc *spr = *sprp;

		if (spr->spr_timer == 0) {
			sprp = &spr->spr_next;
			continue;
		}

		if (tmr_is_first(spr->spr_time, now)) {
			*sprp = spr->spr_next;
			handle_expired_request(sock, spr);
		} else {
			clock_t left = spr->spr_time - now;
			if (lowest == TMR_NEVER || lowest > left) {
				lowest = left;
			}
			sprp = &spr->spr_next;
		}
	}

	return lowest;
}

static void
handle_closing_socket_timeout(struct sock * sock, clock_t now)
{
	if (!(sock->sock_opt & SO_LINGER) ||
	    !tmr_is_first(sock->sock_linger, now)) {
		return;
	}

	assert(sock->sock_ops->sop_close != NULL);

	struct sockevent_proc *spr = sock->sock_proc;
	if (spr != NULL) {
		assert(spr->spr_event == SEV_CLOSE);
		assert(spr->spr_next == NULL);

		sock->sock_proc = NULL;
		sockdriver_reply_generic(&spr->spr_call, OK);
		sockevent_proc_free(spr);
	}

	int r = sock->sock_ops->sop_close(sock, TRUE /*force*/);
	assert(r == OK || r == SUSPEND);

	if (r == SUSPEND) {
		sock->sock_opt &= ~SO_LINGER;
	} else {
		sockevent_free(sock);
	}
}

static clock_t
sockevent_expire(struct sock * sock, clock_t now)
{
	if (sock->sock_flags & SFL_CLOSING) {
		handle_closing_socket_timeout(sock, now);
		return TMR_NEVER;
	}

	return process_socket_requests(sock, now);
}

/*
 * The socket event alarm went off.  Go through the set of socket objects with
 * timers, and see if any of their requests have now expired.  Set a new alarm
 * as necessary.
 */
static void
socktimer_expire(int arg __unused)
{
	SLIST_HEAD(, sock) expiring_timers;
	struct sock *sock, *tsock;
	clock_t lowest;
	const int was_working = sockevent_working;

	if (!was_working) {
		sockevent_working = TRUE;
	}

	memcpy(&expiring_timers, &socktimer, sizeof(expiring_timers));
	SLIST_INIT(&socktimer);

	const clock_t now = getticks();
	lowest = TMR_NEVER;

	SLIST_FOREACH_SAFE(sock, &expiring_timers, sock_timer, tsock) {
		assert(sock->sock_flags & SFL_TIMER);
		sock->sock_flags &= ~SFL_TIMER;

		const clock_t left = sockevent_expire(sock, now);
		if (left != TMR_NEVER) {
			if (lowest == TMR_NEVER || left < lowest) {
				lowest = left;
			}
			SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
			sock->sock_flags |= SFL_TIMER;
		}
	}

	if (lowest != TMR_NEVER) {
		set_timer(&sockevent_timer, lowest, socktimer_expire, 0);
	}

	if (!was_working) {
		if (sockevent_has_events()) {
			sockevent_pump();
		}
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
	assert(sock != NULL);
	assert(ticks <= TMRDIFF_MAX);

	if (!(sock->sock_flags & SFL_TIMER)) {
		SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
		sock->sock_flags |= SFL_TIMER;
	}

	const clock_t now = getticks();
	const clock_t new_exp_time = now + ticks;

	if (!tmr_is_set(&sockevent_timer) ||
	    tmr_is_first(new_exp_time, tmr_exp_time(&sockevent_timer))) {
		set_timer(&sockevent_timer, ticks, socktimer_expire, 0);
	}

	return new_exp_time;
}

/*
 * Remove a socket object from the set of socket objects with timers.  Since
 * the timer list is maintained lazily, this needs to be done only right before
 * the socket object is freed.
 */
static void
socktimer_del(struct sock *sock)
{
	if (!sock || !(sock->sock_flags & SFL_TIMER)) {
		return;
	}

	SLIST_REMOVE(&socktimer, sock, sock, sock_timer);
	sock->sock_flags &= ~SFL_TIMER;
}

/*
 * Bind a socket to a local address.
 */
static int
sockevent_bind(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock = sockhash_get(id);
	int r;

	if (sock == NULL) {
		return EINVAL;
	}

	if ((sock->sock_opt & SO_ACCEPTCONN) != 0) {
		return EINVAL;
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_bind == NULL) {
		return EOPNOTSUPP;
	}

	r = sock->sock_ops->sop_bind(sock, addr, addr_len, user_endpt);

	if (r != SUSPEND) {
		return r;
	}

	if (call == NULL) {
		return EINPROGRESS;
	}

	sockevent_suspend(sock, SEV_BIND, call, user_endpt);
	return SUSPEND;
}

/*
 * Connect a socket to a remote address.
 */
static int
process_connect_events(struct sock *sock, endpoint_t user_endpt)
{
	struct sockdriver_call fakecall;
	struct sockevent_proc *spr;
	int r;

	fakecall.sc_endpt = NONE;

	assert(!sockevent_has_suspended(sock, SEV_SEND | SEV_RECV));
	sockevent_suspend(sock, SEV_CONNECT, &fakecall, user_endpt);

	sockevent_pump();

	spr = sockevent_unsuspend(sock, &fakecall);
	if (spr != NULL) {
		sockevent_proc_free(spr);
		return EINPROGRESS;
	}

	r = sock->sock_err;
	if (r != OK) {
		sock->sock_err = OK;
	}
	return r;
}

static int
sockevent_connect(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * call)
{
	struct sock *sock;
	int r;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_connect == NULL)
		return EOPNOTSUPP;

	if ((sock->sock_opt & SO_ACCEPTCONN) != 0)
		return EOPNOTSUPP;

	r = sock->sock_ops->sop_connect(sock, addr, addr_len, user_endpt);

	if (r == SUSPEND) {
		if (call != NULL) {
			assert(!sockevent_has_suspended(sock,
			    SEV_SEND | SEV_RECV));
			sockevent_suspend(sock, SEV_CONNECT, call, user_endpt);
		} else if (sockevent_has_events()) {
			r = process_connect_events(sock, user_endpt);
		} else {
			r = EINPROGRESS;
		}
	}

	if (r == OK) {
		sockevent_raise(sock, SEV_SEND);
	}

	return r;
}

/*
 * Put a socket in listening mode.
 */
static int
adjust_backlog(int backlog)
{
	int adjusted = (backlog < 0) ? 0 : backlog;

	if (adjusted < SOMAXCONN) {
		adjusted = adjusted * 3 / 2 + 1;
	}

	if (adjusted > SOMAXCONN) {
		adjusted = SOMAXCONN;
	}

	return adjusted;
}

static int
sockevent_listen(sockid_t id, int backlog)
{
	struct sock * const sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_listen == NULL) {
		return EOPNOTSUPP;
	}

	const int final_backlog = adjust_backlog(backlog);
	const int r = sock->sock_ops->sop_listen(sock, final_backlog);

	if (r == OK) {
		sock->sock_opt |= SO_ACCEPTCONN;
		sockevent_raise(sock, SEV_ACCEPT);
	}

	return r;
}

/*
 * Accept a connection on a listening socket, creating a new socket.
 */
static sockid_t
sockevent_accept(sockid_t id, struct sockaddr * __restrict addr,
	socklen_t * __restrict addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_accept == NULL) {
		return EOPNOTSUPP;
	}

	struct sock *newsock = NULL;
	const sockid_t r = sock->sock_ops->sop_accept(sock, addr, addr_len,
	    user_endpt, &newsock);

	if (r == SUSPEND) {
		assert(sock->sock_opt & SO_ACCEPTCONN);
		if (call == NULL) {
			return EWOULDBLOCK;
		}
		sockevent_suspend(sock, SEV_ACCEPT, call, user_endpt);
		return SUSPEND;
	}

	if (r >= 0) {
		sockevent_accepted(sock, newsock, r);
	}

	return r;
}

/*
 * Send regular and/or control data.
 */
static int
send_oob_data(struct sock * __restrict sock,
	const struct sockdriver_data * __restrict data, size_t len,
	const struct sockdriver_data * __restrict ctl_data, socklen_t ctl_len,
	const struct sockaddr * __restrict addr, socklen_t addr_len,
	endpoint_t user_endpt, int flags)
{
	size_t off = 0;
	socklen_t ctl_off = 0;
	int r;

	r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
	    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, 0);

	if (r == SUSPEND) {
		panic("libsockevent: MSG_OOB send calls may not be "
		    "suspended");
	}

	return (r == OK) ? (int)off : r;
}

static int
send_normal_data(struct sock * __restrict sock,
	const struct sockdriver_data * __restrict data, size_t len,
	const struct sockdriver_data * __restrict ctl_data, socklen_t ctl_len,
	const struct sockaddr * __restrict addr, socklen_t addr_len,
	endpoint_t user_endpt, int flags,
	const struct sockdriver_call * __restrict call)
{
	size_t off = 0;
	socklen_t ctl_off = 0;
	int r;

	if (!sockevent_has_suspended(sock, SEV_SEND)) {
		size_t min = sock->sock_slowat;
		if (min > len) {
			min = len;
		}
		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags,
		    min);
	} else {
		r = SUSPEND;
	}

	if (r == SUSPEND) {
		if (call != NULL) {
			clock_t time = 0;
			int timer = FALSE;
			if (sock->sock_stimeo != 0) {
				timer = TRUE;
				time = socktimer_add(sock, sock->sock_stimeo);
			}
			sockevent_suspend_data(sock, SEV_SEND, timer, call,
			    user_endpt, data, len, off, ctl_data, ctl_len,
			    ctl_off, flags, 0, time);
		}
		r = (off > 0 || ctl_off > 0) ? OK : EWOULDBLOCK;
	} else if (r == EPIPE) {
		sockevent_sigpipe(sock, user_endpt, flags);
	}

	return (r == OK) ? (int)off : r;
}

static int
sockevent_send(sockid_t id, const struct sockdriver_data * __restrict data,
	size_t len, const struct sockdriver_data * __restrict ctl_data,
	socklen_t ctl_len, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt, int flags,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock;
	int r;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if ((r = sock->sock_err) != OK) {
		sock->sock_err = OK;
		return r;
	}

	if (sock->sock_flags & SFL_SHUT_WR) {
		sockevent_sigpipe(sock, user_endpt, flags);
		return EPIPE;
	}

	if (sock->sock_opt & SO_DONTROUTE)
		flags |= MSG_DONTROUTE;

	if (sock->sock_ops->sop_pre_send != NULL) {
		r = sock->sock_ops->sop_pre_send(sock, len, ctl_len, addr,
		    addr_len, user_endpt,
		    flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (r != OK) {
			return r;
		}
	}

	if (sock->sock_ops->sop_send == NULL)
		return EOPNOTSUPP;

	if (flags & MSG_OOB) {
		return send_oob_data(sock, data, len, ctl_data, ctl_len, addr,
		    addr_len, user_endpt, flags);
	}

	return send_normal_data(sock, data, len, ctl_data, ctl_len, addr,
	    addr_len, user_endpt, flags, call);
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
	const int inflags = *flags;
	int r;

	*flags = 0;

	if (sock->sock_ops->sop_pre_recv != NULL) {
		r = sock->sock_ops->sop_pre_recv(sock, user_endpt,
		    inflags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (r != OK) {
			return r;
		}
	}

	if (sock->sock_flags & SFL_SHUT_RD) {
		return SOCKEVENT_EOF;
	}

	if (sock->sock_ops->sop_recv == NULL) {
		return EOPNOTSUPP;
	}

	const int oob = (inflags & MSG_OOB);
	if (oob && (sock->sock_opt & SO_OOBINLINE)) {
		return EINVAL;
	}

	if (!oob && sockevent_has_suspended(sock, SEV_RECV)) {
		r = SUSPEND;
	} else {
		size_t min = 0;
		if (!oob && sock->sock_err == OK) {
			min = sock->sock_rlowat;
			if (min > len) {
				min = len;
			}
		}

		r = sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
		    ctl_len, ctl_off, addr, addr_len, user_endpt, inflags,
		    min, flags);
	}

	assert(r <= 0 || r == SOCKEVENT_EOF);

	if (r != SUSPEND) {
		return r;
	}

	if (oob) {
		panic("libsockevent: MSG_OOB receive calls may not be "
		    "suspended");
	}

	if (call == NULL || sock->sock_err != OK) {
		return EWOULDBLOCK;
	}

	clock_t time = 0;
	int timer = FALSE;

	if (sock->sock_rtimeo != 0) {
		timer = TRUE;
		time = socktimer_add(sock, sock->sock_rtimeo);
	}

	sockevent_suspend_data(sock, SEV_RECV, timer, call, user_endpt, data,
	    len, *off, ctl_data, ctl_len, *ctl_off, inflags, *flags, time);

	return SUSPEND;
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
	size_t off;
	socklen_t ctl_inlen;
	int r;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	off = 0;
	ctl_inlen = *ctl_len;
	*ctl_len = 0;

	r = sockevent_recv_inner(sock, data, len, &off, ctl_data, ctl_inlen,
	    ctl_len, addr, addr_len, user_endpt, flags, call);

	if (r == OK || (r != SUSPEND && (off > 0 || *ctl_len > 0))) {
		return (int)off;
	}

	if (sock->sock_err != OK) {
		assert(r != SUSPEND);
		int err = sock->sock_err;
		sock->sock_err = OK;
		return err;
	}

	if (r == SOCKEVENT_EOF) {
		return 0;
	}

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
	struct sock *sock = sockhash_get(id);

	if (sock == NULL) {
		return EINVAL;
	}

	switch (request) {
	case FIONREAD: {
		size_t size = 0;
		int val;

		if (!(sock->sock_flags & SFL_SHUT_RD) &&
		    sock->sock_ops->sop_test_recv != NULL) {
			(void)sock->sock_ops->sop_test_recv(sock, 0, &size);
		}

		val = (size > (size_t)INT_MAX) ? INT_MAX : (int)size;

		return sockdriver_copyout(data, 0, &val, sizeof(val));
	}
	default:
		break;
	}

	if (sock->sock_ops->sop_ioctl == NULL) {
		return ENOTTY;
	}

	const int r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

	if (r == SUSPEND) {
		return EOPNOTSUPP;
	}

	return r;
}

/*
 * Set socket options.
 */
static int
handle_on_off_option(struct sock *sock, int name,
	const struct sockdriver_data *data, socklen_t len)
{
	int r, val;

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
}

static int
handle_linger_option(struct sock *sock, const struct sockdriver_data *data,
	socklen_t len)
{
	struct linger linger;
	clock_t secs;
	int r;

	if ((r = sockdriver_copyin_opt(data, &linger, sizeof(linger),
	    len)) != OK)
		return r;

	if (linger.l_onoff) {
		if (linger.l_linger < 0)
			return EINVAL;

		secs = (clock_t)linger.l_linger;
		if (secs >= TMRDIFF_MAX / sys_hz())
			return EDOM;

		sock->sock_opt |= SO_LINGER;
		sock->sock_linger = secs * sys_hz();
	} else {
		sock->sock_opt &= ~SO_LINGER;
		sock->sock_linger = 0;
	}

	return OK;
}

static int
handle_lowat_option(struct sock *sock, int name,
	const struct sockdriver_data *data, socklen_t len)
{
	int r, val;

	if ((r = sockdriver_copyin_opt(data, &val, sizeof(val), len)) != OK)
		return r;

	if (val <= 0)
		return EINVAL;

	if (name == SO_SNDLOWAT) {
		sock->sock_slowat = (size_t)val;
		sockevent_raise(sock, SEV_SEND);
	} else {
		sock->sock_rlowat = (size_t)val;
		sockevent_raise(sock, SEV_RECV);
	}

	return OK;
}

static int
handle_timeout_option(struct sock *sock, int name,
	const struct sockdriver_data *data, socklen_t len)
{
	struct timeval tv;
	clock_t ticks;
	int r;

	if ((r = sockdriver_copyin_opt(data, &tv, sizeof(tv), len)) != OK)
		return r;

	if (tv.tv_sec < 0 || tv.tv_usec < 0 ||
	    (unsigned long)tv.tv_usec >= US)
		return EINVAL;
	if (tv.tv_sec >= TMRDIFF_MAX / sys_hz())
		return EDOM;

	ticks = tv.tv_sec * sys_hz() +
	    (tv.tv_usec * sys_hz() + US - 1) / US;

	if (name == SO_SNDTIMEO)
		sock->sock_stimeo = ticks;
	else
		sock->sock_rtimeo = ticks;

	return OK;
}

static int
sockevent_setsockopt(sockid_t id, int level, int name,
	const struct sockdriver_data * data, socklen_t len)
{
	struct sock *sock;

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
			return handle_on_off_option(sock, name, data, len);
		case SO_LINGER:
			return handle_linger_option(sock, data, len);
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
			return handle_lowat_option(sock, name, data, len);
		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			return handle_timeout_option(sock, name, data, len);
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
static int
sockevent_getsockopt(sockid_t id, int level, int name,
	const struct sockdriver_data * __restrict data,
	socklen_t * __restrict len)
{
	struct sock *sock;
	int val;

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (level == SOL_SOCKET) {
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
			val = (sock->sock_opt & (unsigned int)name) != 0;
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);

		case SO_LINGER: {
			struct linger linger;
			linger.l_onoff = (sock->sock_opt & SO_LINGER) != 0;
			linger.l_linger = sock->sock_linger / sys_hz();
			return sockdriver_copyout_opt(data, &linger,
			    sizeof(linger), len);
		}

		case SO_ERROR:
			val = -sock->sock_err;
			if (sock->sock_err != OK) {
				sock->sock_err = OK;
			}
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);

		case SO_TYPE:
			val = sock->sock_type;
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);

		case SO_SNDLOWAT:
			val = (int)sock->sock_slowat;
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);

		case SO_RCVLOWAT:
			val = (int)sock->sock_rlowat;
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);

		case SO_SNDTIMEO:
		case SO_RCVTIMEO: {
			struct timeval tv;
			clock_t ticks;
			ticks = (name == SO_SNDTIMEO) ? sock->sock_stimeo :
			    sock->sock_rtimeo;
			tv.tv_sec = ticks / sys_hz();
			tv.tv_usec = (ticks % sys_hz()) * US / sys_hz();
			return sockdriver_copyout_opt(data, &tv, sizeof(tv),
			    len);
		}

		default:
			break;
		}
	}

	if (sock->sock_ops->sop_getsockopt == NULL) {
		return ENOPROTOOPT;
	}

	return sock->sock_ops->sop_getsockopt(sock, level, name, data, len);
}

/*
 * Retrieve a socket's local address.
 */
static int
sockevent_getsockname(sockid_t id, struct sockaddr * __restrict addr,
	socklen_t * __restrict addr_len)
{
	struct sock * const sock = sockhash_get(id);

	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_getsockname == NULL) {
		return EOPNOTSUPP;
	}

	return sock->sock_ops->sop_getsockname(sock, addr, addr_len);
}

/*
 * Retrieve a socket's remote address.
 */
static int
sockevent_getpeername(sockid_t id, struct sockaddr * __restrict addr,
	socklen_t * __restrict addr_len)
{
	if (addr == NULL || addr_len == NULL) {
		return EINVAL;
	}

	struct sock * const sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if ((sock->sock_opt & SO_ACCEPTCONN) != 0) {
		return ENOTCONN;
	}

	if (sock->sock_ops->sop_getpeername == NULL) {
		return EOPNOTSUPP;
	}

	return sock->sock_ops->sop_getpeername(sock, addr, addr_len);
}

/*
 * Mark the socket object as shut down for sending and/or receiving.  The flags
 * parameter may be a bitwise-OR'ed combination of SFL_SHUT_RD and SFL_SHUT_WR.
 * This function will wake up any suspended requests affected by this change,
 * but it will not invoke the sop_shutdown() callback function on the socket.
 * The function may in fact be called from sop_shutdown() before completion to
 * mark the socket as shut down as reflected by sockevent_is_shutdown().
 */
void
sockevent_set_shutdown(struct sock * sock, unsigned int flags)
{
	assert(sock->sock_ops != NULL);
	assert((flags & ~(SFL_SHUT_RD | SFL_SHUT_WR)) == 0);

	const unsigned int new_flags = flags & ~(unsigned int)sock->sock_flags;
	if (new_flags == 0) {
		return;
	}

	sock->sock_flags |= new_flags;

	unsigned int mask = 0;
	if (new_flags & SFL_SHUT_RD) {
		mask |= SEV_RECV;
	}
	if (new_flags & SFL_SHUT_WR) {
		mask |= SEV_SEND;
	}
	if (sock->sock_opt & SO_ACCEPTCONN) {
		mask |= SEV_ACCEPT;
	}

	sockevent_raise(sock, mask);
}

/*
 * Shut down socket send and receive operations.
 */
static int
sockevent_shutdown(sockid_t id, int how)
{
	struct sock *sock = sockhash_get(id);
	if (!sock) {
		return EINVAL;
	}

	unsigned int flags;
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
		return EINVAL;
	}

	int r = OK;
	if (sock->sock_ops && sock->sock_ops->sop_shutdown) {
		r = sock->sock_ops->sop_shutdown(sock, flags);
	}

	if (r == OK) {
		sockevent_set_shutdown(sock, flags);
	}

	return r;
}

/*
 * Close a socket.
 */
static int
sockevent_close(sockid_t id, const struct sockdriver_call * call)
{
	struct sock *sock;
	int r;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	assert(sock->sock_proc == NULL);
	sock->sock_select.ss_endpt = NONE;

	const int force = (sock->sock_opt & SO_LINGER) && sock->sock_linger == 0;

	r = (sock->sock_ops->sop_close != NULL) ?
		sock->sock_ops->sop_close(sock, force) : OK;

	assert(r == OK || r == SUSPEND);

	if (r == OK) {
		sockevent_free(sock);
		return OK;
	}

	/* If we reach here, r must be SUSPEND. */
	sock->sock_flags |= SFL_CLOSING;

	/* If force-closing, caller is not suspended even if driver needs time. */
	if (force) {
		return OK;
	}

	const int has_linger_timeout = (sock->sock_opt & SO_LINGER);
	const int is_blocking_call = (call != NULL);

	if (has_linger_timeout) {
		sock->sock_linger = socktimer_add(sock, sock->sock_linger);
	}

	/* Suspend the caller only for a blocking call with a linger timeout. */
	if (is_blocking_call && has_linger_timeout) {
		sockevent_suspend(sock, SEV_CLOSE, call, NONE);
		return SUSPEND;
	}

	/* For non-blocking calls or when linger is off, the close proceeds
	 * in the background, but the caller is not suspended. */
	return OK;
}

/*
 * Cancel a suspended send request.
 */
static void
sockevent_cancel_send(struct sock *sock, struct sockevent_proc *spr, int err)
{
	const int r = (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
	    ? (int)spr->spr_dataoff
	    : err;

	sockdriver_reply_generic(&spr->spr_call, r);
	sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static void
sockevent_cancel_recv(struct sock *sock, struct sockevent_proc *spr, int err)
{
	const int r = (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
	    ? (int)spr->spr_dataoff
	    : err;

	sockdriver_reply_recv(&spr->spr_call, r, spr->spr_ctloff, NULL, 0,
	    spr->spr_rflags);

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
handle_cancel_bind_connect(struct sock *sock __attribute__((unused)),
    struct sockevent_proc *spr)
{
	assert(spr->spr_call.sc_endpt != NONE);
	sockdriver_reply_generic(&spr->spr_call, EINTR);
}

static void
handle_cancel_accept(struct sock *sock __attribute__((unused)),
    struct sockevent_proc *spr)
{
	sockdriver_reply_accept(&spr->spr_call, EINTR, NULL, 0);
}

static void
handle_cancel_send(struct sock *sock, struct sockevent_proc *spr)
{
	sockevent_cancel_send(sock, spr, EINTR);
}

static void
handle_cancel_recv(struct sock *sock, struct sockevent_proc *spr)
{
	sockevent_cancel_recv(sock, spr, EINTR);
}

static void
handle_cancel_close(struct sock *sock __attribute__((unused)),
    struct sockevent_proc *spr)
{
	sockdriver_reply_generic(&spr->spr_call, EINPROGRESS);
}

static void
sockevent_cancel(sockid_t id, const struct sockdriver_call * call)
{
	typedef void (*cancel_handler_t)(struct sock *, struct sockevent_proc *);

	static const cancel_handler_t cancel_handlers[] = {
		[SEV_BIND] = handle_cancel_bind_connect,
		[SEV_CONNECT] = handle_cancel_bind_connect,
		[SEV_ACCEPT] = handle_cancel_accept,
		[SEV_SEND] = handle_cancel_send,
		[SEV_RECV] = handle_cancel_recv,
		[SEV_CLOSE] = handle_cancel_close
	};

	struct sock *sock = sockhash_get(id);
	if (sock == NULL) {
		return;
	}

	struct sockevent_proc *spr = sockevent_unsuspend(sock, call);
	if (spr == NULL) {
		return;
	}

	int event = spr->spr_event;
	size_t num_handlers = sizeof(cancel_handlers) / sizeof(cancel_handlers[0]);

	if ((unsigned int)event < num_handlers &&
	    cancel_handlers[event] != NULL) {
		cancel_handlers[event](sock, spr);
	} else {
		panic("libsockevent: process suspended on unknown event 0x%x",
		    event);
	}

	sockevent_proc_free(spr);
}

/*
 * Process a select request.
 */
static int
sockevent_select(sockid_t id, unsigned int ops,
	const struct sockdriver_select * sel)
{
	struct sock *sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	const unsigned int notify = (ops & SDEV_NOTIFY);
	unsigned int pending_ops = ops & (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR);

	unsigned int satisfied_ops = sockevent_test_select(sock, pending_ops);

	assert(!(sock->sock_selops & satisfied_ops));

	pending_ops &= ~satisfied_ops;

	if (notify && pending_ops != 0) {
		if (sock->sock_select.ss_endpt == NONE) {
			assert(sel->ss_endpt != NONE);
			sock->sock_select = *sel;
			sock->sock_selops = pending_ops;
		} else if (sock->sock_select.ss_endpt != sel->ss_endpt) {
			printf("libsockevent: no support for multiple "
			    "select callers yet\n");
			return EIO;
		} else {
			sock->sock_selops |= pending_ops;
		}
	}

	return satisfied_ops;
}

/*
 * An alarm has triggered.  Expire any timers.  Socket drivers that do not pass
 * clock notification messages to libsockevent must call expire_timers(3)
 * themselves instead.
 */
static void
sockevent_alarm(const clock_t now)
{
	(void)expire_timers(now);
}

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
int
sockevent_init(sockevent_socket_cb_t socket_cb)
{
	if (socket_cb == NULL) {
		return -1;
	}

	if (sockhash_init() != 0) {
		return -1;
	}
	if (socktimer_init() != 0) {
		return -1;
	}
	if (sockevent_proc_init() != 0) {
		return -1;
	}

	SIMPLEQ_INIT(&sockevent_pending);

	sockevent_socket_cb = socket_cb;

	/* Announce we are up. */
	sockdriver_announce();

	sockevent_working = false;

	return 0;
}

/*
 * Process a socket driver request message.
 */
void
sockevent_process(const message * m_ptr, int ipc_status)
{
	assert(!sockevent_working);
	if (sockevent_working) {
		return;
	}

	sockevent_working = TRUE;

	sockdriver_process(&sockevent_tab, m_ptr, ipc_status);

	if (sockevent_has_events()) {
		sockevent_pump();
	}

	sockevent_working = FALSE;
}
