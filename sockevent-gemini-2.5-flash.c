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
	size_t slot;

	for (slot = 0; slot < __arraycount(sockhash); slot++)
		SLIST_INIT(&sockhash[slot]);
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
static unsigned int
sockhash_slot(sockid_t id)
{
    const unsigned int id_class_shift = 16U;
    return (id + (id >> id_class_shift)) % SOCKHASH_SLOTS;
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *
sockhash_get(sockid_t id)
{
	struct sock *sock;
	unsigned int slot;

	slot = sockhash_slot(id);

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
static void
sockhash_add(struct sock * sock)
{
	if (sock == NULL) {
		return;
	}

	SLIST_INSERT_HEAD(&sockhash[sockhash_slot(sock->sock_id)], sock, sock_hash);
}

/*
 * Remove a sock object from the hash table.  The sock object must be in the
 * hash table.
 */
static void
sockhash_del(struct sock * sock)
{
	if (sock == NULL) {
		return;
	}

	unsigned int slot;

	slot = sockhash_slot(sock->sock_id);

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

	memset(sock, 0, sizeof(*sock));

	sock->sock_id = id;
	sock->sock_domain = domain;
	sock->sock_type = type;

	sock->sock_slowat = 1;
	sock->sock_rlowat = 1;

	sock->sock_ops = ops;
	sock->sock_proc = NULL;
	sock->sock_select.ss_endpt = NONE;

	sockhash_add(sock);
}

/*
 * Initialize a new socket that will serve as an accepted socket on the given
 * listening socket 'sock'.  The new socket is given as 'newsock', and its new
 * socket identifier is given as 'newid'.  This function always succeeds.
 */
void
sockevent_clone(struct sock * sock, struct sock * newsock, sockid_t newid)
{
	if (sock == ((void *)0) || newsock == ((void *)0)) {
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
sockevent_accepted(struct sock * sock, struct sock * newsock, sockid_t newid)
{
	// If the accepted socket object is not provided directly, retrieve it from the hash.
	// This ensures `newsock` is a valid pointer for subsequent operations.
	if (newsock == NULL) {
		newsock = sockhash_get(newid);
		if (newsock == NULL) {
			// Critical error: The driver reported a new ID but the socket
			// object cannot be found. This indicates an inconsistent state.
			panic("libsockdriver: socket driver returned unknown "
			    "ID %d from accept callback", newid);
		}
	} else {
		// If the accepted socket object was provided, perform the cloning operation.
		// This branch maintains the original behavior where sockevent_clone
		// is only called when `newsock` is initially non-NULL.
		sockevent_clone(sock, newsock, newid);
	}

	// Reliability Improvement:
	// Verify that the SFL_CLONED flag is set. This flag is expected to be
	// set either by the driver (if retrieved via sockhash_get) or by sockevent_clone.
	// Its absence indicates a critical internal state error or a protocol violation.
	// Replacing `assert` with `panic` ensures this critical check is active
	// in all builds, improving reliability and robustness.
	if (!(newsock->sock_flags & SFL_CLONED)) {
		panic("libsockdriver: accepted socket ID %d (addr %p) "
		    "does not have SFL_CLONED flag set. "
		    "Possible driver or internal state error.", newid, (void*)newsock);
	}

	// Clear the SFL_CLONED flag, as its purpose is fulfilled after this processing.
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
	struct sock ** sockp)
{
	struct sock *sock;
	const struct sockevent_ops *ops;
	sockid_t r;

	if (domain < 0 || (unsigned int)domain > UINT8_MAX) {
		return EAFNOSUPPORT;
	}

	if (sockevent_socket_cb == NULL) {
		panic("libsockevent: not initialized");
	}

	r = sockevent_socket_cb(domain, type, protocol, user_endpt, &sock, &ops);
	if (r < 0) {
		return (int)r;
	}

	assert(sock != NULL);
	assert(ops != NULL);

	sockevent_reset(sock, r, domain, type, ops);

	*sockp = sock;
	return OK;
}

/*
 * Free a previously allocated sock object.
 */
static void
sockevent_free(struct sock * sock)
{
	if (sock == NULL) {
		return;
	}

	assert(sock->sock_proc == NULL);

	socktimer_del(sock);

	sockhash_del(sock);

	const struct sockevent_ops *ops = sock->sock_ops;
	sock->sock_ops = NULL;

	if (ops != NULL && ops->sop_free != NULL) {
		ops->sop_free(sock);
	}
}

/*
 * Create a new socket.
 */
static sockid_t
sockevent_socket(int domain, int type, int protocol, endpoint_t user_endpt)
{
	struct sock *sock = NULL;

	int allocation_status = sockevent_alloc(domain, type, protocol, user_endpt, &sock);

	if (allocation_status != OK) {
		return (sockid_t)allocation_status;
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
	int r = OK;

	if ((r = sockevent_alloc(domain, type, protocol, user_endpt, &sock1)) != OK) {
		goto cleanup;
	}

	if (sock1->sock_ops == NULL || sock1->sock_ops->sop_pair == NULL) {
		r = EOPNOTSUPP;
		goto cleanup;
	}

	if ((r = sockevent_alloc(domain, type, protocol, user_endpt, &sock2)) != OK) {
		goto cleanup;
	}

	assert(sock1->sock_ops == sock2->sock_ops);

	if ((r = sock1->sock_ops->sop_pair(sock1, sock2, user_endpt)) != OK) {
		goto cleanup;
	}

	id[0] = sock1->sock_id;
	id[1] = sock2->sock_id;

cleanup:
	if (r != OK) {
		if (sock2 != NULL) {
			sockevent_free(sock2);
		}
		if (sock1 != NULL) {
			sockevent_free(sock1);
		}
	}
	return r;
}

/*
 * A send request returned EPIPE.  If desired, send a SIGPIPE signal to the
 * user process that issued the request.
 */
static void
sockevent_sigpipe(struct sock * sock, endpoint_t user_endpt, int flags)
{
	if (sock->sock_type == SOCK_STREAM &&
	    !(flags & MSG_NOSIGNAL) &&
	    !(sock->sock_opt & SO_NOSIGPIPE))
	{
		sys_kill(user_endpt, SIGPIPE);
	}
}

/*
 * Suspend a request without data, that is, a bind, connect, accept, or close
 * request.
 */
static void
sockevent_suspend(struct sock * sock, unsigned int event,
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt)
{
	struct sockevent_proc *spr, **sprp;

	if ((spr = sockevent_proc_alloc()) == NULL)
		panic("libsockevent: too many suspended processes");

	*spr = (struct sockevent_proc) {
		.spr_next = NULL,
		.spr_event = event,
		.spr_timer = FALSE,
		.spr_call = *call,
		.spr_endpt = user_endpt
	};

	for (sprp = &sock->sock_proc; *sprp != NULL;
	     sprp = &(*sprp)->spr_next);
	*sprp = spr;
}

/*
 * Suspend a request with data, that is, a send or receive request.
 */
static void
sockevent_suspend_data(struct sock * sock, unsigned int event, int timer,
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt,
	const struct sockdriver_data * __restrict data, size_t len, size_t off,
	const struct sockdriver_data * __restrict ctl, socklen_t ctl_len,
	socklen_t ctl_off, int flags, int rflags, clock_t time)
{
	struct sockevent_proc *spr;

	if ((spr = sockevent_proc_alloc()) == NULL) {
		panic("libsockevent: too many suspended processes");
	}

	spr->spr_next = NULL;
	spr->spr_event = event;
	spr->spr_timer = timer;
	spr->spr_call = *call;
	spr->spr_endpt = user_endpt;
	spr->spr_datalen = len;
	spr->spr_dataoff = off;
	spr->spr_ctllen = ctl_len;
	spr->spr_ctloff = ctl_off;
	spr->spr_flags = flags;
	spr->spr_rflags = rflags;
	spr->spr_time = time;

	sockdriver_pack_data(&spr->spr_data, call, data, len);
	sockdriver_pack_data(&spr->spr_ctl, call, ctl, ctl_len);

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
static bool
sockevent_has_suspended(struct sock * sock, unsigned int mask)
{
	struct sockevent_proc *spr;

	for (spr = sock->sock_proc; spr != NULL; spr = spr->spr_next) {
		if (spr->spr_event & mask) {
			return true;
		}
	}

	return false;
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
	struct sockevent_proc *current_proc;
	struct sockevent_proc **pointer_to_next_proc;

	for (pointer_to_next_proc = &sock->sock_proc;
	     (current_proc = *pointer_to_next_proc) != NULL;
	     pointer_to_next_proc = &current_proc->spr_next) {
		if (current_proc->spr_call.sc_endpt == call->sc_endpt &&
		    current_proc->spr_call.sc_req == call->sc_req) {
			*pointer_to_next_proc = current_proc->spr_next;

			return current_proc;
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
sockevent_resume(struct sock * sock, struct sockevent_proc * spr)
{
	switch (spr->spr_event) {
	case SEV_CONNECT:
		if (spr->spr_call.sc_endpt == NONE) {
			return TRUE;
		}
		/* FALLTHROUGH */
	case SEV_BIND: {
		sockid_t reply_code = sock->sock_err;
		if (reply_code != OK) {
			sock->sock_err = OK;
		}
		sockdriver_reply_generic(&spr->spr_call, reply_code);
		return TRUE;
	}

	case SEV_ACCEPT: {
		assert(sock->sock_opt & SO_ACCEPTCONN);

		char client_addr_buffer[SOCKADDR_MAX];
		socklen_t client_addr_len = 0;
		struct sock *new_connection_sock = NULL;
		sockid_t accept_result;

		accept_result = sock->sock_ops->sop_accept(
		    sock,
		    (struct sockaddr *)&client_addr_buffer,
		    &client_addr_len,
		    spr->spr_endpt,
		    &new_connection_sock);

		if (accept_result == SUSPEND) {
			return FALSE;
		}

		if (accept_result >= 0) {
			assert(client_addr_len <= sizeof(client_addr_buffer));
			sockevent_accepted(sock, new_connection_sock, accept_result);
		}

		sockdriver_reply_accept(
		    &spr->spr_call,
		    accept_result,
		    (struct sockaddr *)&client_addr_buffer,
		    client_addr_len);
		return TRUE;
	}

	case SEV_SEND: {
		sockid_t send_status;
		size_t bytes_to_send;
		size_t min_send_len;
		struct sockdriver_data data_to_send;
		struct sockdriver_data control_data_to_send;

		if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
			if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
				send_status = (sockid_t)spr->spr_dataoff;
			} else {
				send_status = sock->sock_err;
				if (send_status == OK) {
					send_status = EPIPE;
				} else {
					sock->sock_err = OK;
				}
			}
		} else {
			sockdriver_unpack_data(&data_to_send, &spr->spr_call,
			    &spr->spr_data, spr->spr_datalen);
			sockdriver_unpack_data(&control_data_to_send, &spr->spr_call,
			    &spr->spr_ctl, spr->spr_ctllen);

			bytes_to_send = spr->spr_datalen - spr->spr_dataoff;

			min_send_len = sock->sock_slowat;
			if (min_send_len > bytes_to_send) {
				min_send_len = bytes_to_send;
			}

			sockid_t sop_send_ret = sock->sock_ops->sop_send(
			    sock,
			    &data_to_send,
			    bytes_to_send,
			    &spr->spr_dataoff,
			    &control_data_to_send,
			    spr->spr_ctllen - spr->spr_ctloff,
			    &spr->spr_ctloff,
			    NULL, 0,
			    spr->spr_endpt,
			    spr->spr_flags,
			    min_send_len);

			assert(sop_send_ret <= 0);

			if (sop_send_ret == SUSPEND) {
				return FALSE;
			}

			if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
				send_status = (sockid_t)spr->spr_dataoff;
			} else {
				send_status = sop_send_ret;
			}
		}

		if (send_status == EPIPE) {
			sockevent_sigpipe(sock, spr->spr_endpt, spr->spr_flags);
		}

		sockdriver_reply_generic(&spr->spr_call, send_status);
		return TRUE;
	}

	case SEV_RECV: {
		char client_addr_buffer[SOCKADDR_MAX];
		socklen_t client_addr_len = 0;
		sockid_t recv_reply_code;

		if (sock->sock_flags & SFL_SHUT_RD) {
			recv_reply_code = SOCKEVENT_EOF;
		} else {
			size_t bytes_to_recv = spr->spr_datalen - spr->spr_dataoff;
			size_t min_recv_len;

			if (sock->sock_err == OK) {
				min_recv_len = sock->sock_rlowat;
				if (min_recv_len > bytes_to_recv) {
					min_recv_len = bytes_to_recv;
				}
			} else {
				min_recv_len = 0;
			}

			struct sockdriver_data data_buffer;
			struct sockdriver_data control_buffer;

			sockdriver_unpack_data(&data_buffer, &spr->spr_call,
			    &spr->spr_data, spr->spr_datalen);
			sockdriver_unpack_data(&control_buffer, &spr->spr_call,
			    &spr->spr_ctl, spr->spr_ctllen);

			sockid_t sop_recv_ret = sock->sock_ops->sop_recv(
			    sock,
			    &data_buffer,
			    bytes_to_recv,
			    &spr->spr_dataoff,
			    &control_buffer,
			    spr->spr_ctllen - spr->spr_ctloff,
			    &spr->spr_ctloff,
			    (struct sockaddr *)&client_addr_buffer,
			    &client_addr_len,
			    spr->spr_endpt,
			    spr->spr_flags,
			    min_recv_len,
			    &spr->spr_rflags);

			if (sop_recv_ret == SUSPEND) {
				if (sock->sock_err == OK) {
					return FALSE;
				}
				sop_recv_ret = SOCKEVENT_EOF;
			}

			assert(client_addr_len <= sizeof(client_addr_buffer));

			if (sop_recv_ret == OK || spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
				recv_reply_code = (sockid_t)spr->spr_dataoff;
			} else if (sock->sock_err != OK) {
				recv_reply_code = sock->sock_err;
				sock->sock_err = OK;
			} else if (sop_recv_ret == SOCKEVENT_EOF) {
				recv_reply_code = 0;
			} else {
				recv_reply_code = sop_recv_ret;
			}
		}

		sockdriver_reply_recv(
		    &spr->spr_call,
		    recv_reply_code,
		    spr->spr_ctloff,
		    (struct sockaddr *)&client_addr_buffer,
		    client_addr_len,
		    spr->spr_rflags);
		return TRUE;
	}

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
    if (sock->sock_flags & SFL_SHUT_RD) {
        return TRUE;
    }

    if (sock->sock_err != OK) {
        return TRUE;
    }

    int test_result;

    if (sock->sock_opt & SO_ACCEPTCONN) {
        if (sock->sock_ops->sop_test_accept == NULL) {
            return TRUE;
        }
        test_result = sock->sock_ops->sop_test_accept(sock);
    } else {
        if (sock->sock_ops->sop_test_recv == NULL) {
            return TRUE;
        }
        test_result = sock->sock_ops->sop_test_recv(sock, sock->sock_rlowat, NULL);
    }

    return (test_result != SUSPEND);
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

	if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
		return TRUE;
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_test_send == NULL) {
		return TRUE;
	}

	return (sock->sock_ops->sop_test_send(sock, sock->sock_slowat) != SUSPEND);
}

/*
 * Test whether any of the given select operations are ready on the given
 * socket.  Return the subset of ready operations; zero if none.
 */
static unsigned int
sockevent_test_select(struct sock * sock, unsigned int ops)
{
	unsigned int ready_ops;

	assert(!(ops & ~(SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR)));

	ready_ops = 0;

	if ((ops & SDEV_OP_RD) && sockevent_test_readable(sock))
		ready_ops |= SDEV_OP_RD;

	if ((ops & SDEV_OP_WR) && sockevent_test_writable(sock))
		ready_ops |= SDEV_OP_WR;

	return ready_ops;
}

/*
 * Fire the given mask of events on the given socket object now.
 */
static void
sockevent_fire(struct sock * sock, unsigned int mask)
{
	struct sockevent_proc *spr, **sprp;
	unsigned int r;

	if (mask & SEV_CONNECT)
		mask |= SEV_SEND;

	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL; ) {
		unsigned int spr_event_flags = spr->spr_event;

		if ((mask & spr_event_flags) && sockevent_resume(sock, spr)) {
			*sprp = spr->spr_next;
			sockevent_proc_free(spr);
		} else {
			mask &= ~spr_event_flags;
			sprp = &spr->spr_next;
		}
	}

	if ((mask & (SEV_ACCEPT | SEV_SEND | SEV_RECV)) &&
	    sock->sock_select.ss_endpt != NONE) {
		assert(sock->sock_selops != 0);

		unsigned int relevant_select_ops = 0;

		if ((mask & (SEV_ACCEPT | SEV_RECV)) && (sock->sock_selops & SDEV_OP_RD)) {
			relevant_select_ops |= SDEV_OP_RD;
		}
		if ((mask & SEV_SEND) && (sock->sock_selops & SDEV_OP_WR)) {
			relevant_select_ops |= SDEV_OP_WR;
		}
		/* SDEV_OP_ERR (OOB receive support) is not yet implemented. */

		if (relevant_select_ops != 0) {
			r = sockevent_test_select(sock, relevant_select_ops);

			if (r != 0) {
				sockdriver_reply_select(&sock->sock_select, sock->sock_id, r);
				sock->sock_selops &= ~r;

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
	struct sock *sock;
	unsigned int processed_event_flags;

	assert(sockevent_working);

	while (!SIMPLEQ_EMPTY(&sockevent_pending)) {
		sock = SIMPLEQ_FIRST(&sockevent_pending);
		SIMPLEQ_REMOVE_HEAD(&sockevent_pending, sock_next);

		processed_event_flags = sock->sock_events;
		assert(processed_event_flags != 0);
		sock->sock_events = 0;

		sockevent_fire(sock, processed_event_flags);
	}
}

/*
 * Return TRUE if any events are pending on any sockets, or FALSE otherwise.
 */
static bool
sockevent_has_events(void)
{
	return (!SIMPLEQ_EMPTY(&sockevent_pending));
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

	if (mask == SEV_CLOSE) {
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

		sock->sock_events |= (unsigned char)mask;
	} else {
		sockevent_working = TRUE;

		sockevent_fire(sock, mask);

		if (sockevent_has_events()) {
			sockevent_pump();
		}

		sockevent_working = FALSE;
	}
}

/*
 * Set a pending error on the socket object, and wake up any suspended
 * operations that are affected by this.
 */
#include <stdio.h> // Required for fprintf

void
sockevent_set_error(struct sock * sock, int err)
{
    if (sock == NULL) {
        fprintf(stderr, "ERROR: sockevent_set_error called with NULL sock pointer.\n");
        return;
    }

    if (sock->sock_ops == NULL) {
        fprintf(stderr, "WARNING: sockevent_set_error called with sock->sock_ops being NULL for sock %p. Object might be in an invalid state.\n", (void *)sock);
        return;
    }

    sock->sock_err = err;

    sockevent_raise(sock, SEV_BIND | SEV_CONNECT | SEV_SEND | SEV_RECV);
}

/*
 * Initialize timer-related data structures.
 */
static void
socktimer_init(void)
{
	SLIST_INIT(&socktimer);
	(void)init_timer(&sockevent_timer);
}

/*
 * Check whether the given socket object has any suspended requests that have
 * now expired.  If so, cancel them.  Also, if the socket object has any
 * suspended requests with a timeout that has not yet expired, return the
 * earliest (relative) timeout of all of them, or TMR_NEVER if no such requests
 * are present.
 */
static clock_t
handle_closing_socket_expiration(struct sock *sock, clock_t now)
{
	struct sockevent_proc *spr;
	int r;

	if ((sock->sock_opt & SO_LINGER) && tmr_is_first(sock->sock_linger, now)) {
		assert(sock->sock_ops->sop_close != NULL);

		spr = sock->sock_proc;
		if (spr != NULL) {
			assert(spr->spr_event == SEV_CLOSE);
			assert(spr->spr_next == NULL);

			sock->sock_proc = NULL;

			sockdriver_reply_generic(&spr->spr_call, OK);

			sockevent_proc_free(spr);
		}

		r = sock->sock_ops->sop_close(sock, TRUE);

		assert(r == OK || r == SUSPEND);

		if (r == SUSPEND) {
			sock->sock_opt &= ~SO_LINGER;
		} else {
			sockevent_free(sock);
		}
	}

	return TMR_NEVER;
}

static clock_t
handle_event_timeouts(struct sock *sock, clock_t now)
{
	struct sockevent_proc *spr;
	struct sockevent_proc **prev_spr_next_ptr;
	clock_t lowest_remaining_time = TMR_NEVER;
	clock_t time_left;

	prev_spr_next_ptr = &sock->sock_proc;

	while ((spr = *prev_spr_next_ptr) != NULL) {
		if (spr->spr_timer == 0) {
			prev_spr_next_ptr = &spr->spr_next;
			continue;
		}

		assert(spr->spr_event == SEV_SEND || spr->spr_event == SEV_RECV);

		if (tmr_is_first(spr->spr_time, now)) {
			*prev_spr_next_ptr = spr->spr_next;

			if (spr->spr_event == SEV_SEND) {
				sockevent_cancel_send(sock, spr, EWOULDBLOCK);
			} else {
				sockevent_cancel_recv(sock, spr, EWOULDBLOCK);
			}
			sockevent_proc_free(spr);
		} else {
			time_left = spr->spr_time - now;

			if (lowest_remaining_time == TMR_NEVER || lowest_remaining_time > time_left) {
				lowest_remaining_time = time_left;
			}
			prev_spr_next_ptr = &spr->spr_next;
		}
	}

	return lowest_remaining_time;
}

static clock_t
sockevent_expire(struct sock *sock, clock_t now)
{
	if (sock->sock_flags & SFL_CLOSING) {
		return handle_closing_socket_expiration(sock, now);
	}

	return handle_event_timeouts(sock, now);
}

/*
 * The socket event alarm went off.  Go through the set of socket objects with
 * timers, and see if any of their requests have now expired.  Set a new alarm
 * as necessary.
 */
static void
socktimer_expire(int arg __unused)
{
	int was_already_working = sockevent_working;
	if (was_already_working == FALSE) {
		sockevent_working = TRUE;
	}

	SLIST_HEAD(, sock) old_timers_head;
	memcpy(&old_timers_head, &socktimer, sizeof(old_timers_head));
	SLIST_INIT(&socktimer);

	clock_t now = getticks();
	clock_t lowest_next_timeout = TMR_NEVER;

	struct sock *current_sock, *next_sock;

	SLIST_FOREACH_SAFE(current_sock, &old_timers_head, sock_timer, next_sock) {
		assert(current_sock->sock_flags & SFL_TIMER);
		current_sock->sock_flags &= ~SFL_TIMER;

		clock_t remaining_time = sockevent_expire(current_sock, now);

		if (remaining_time != TMR_NEVER) {
			if (lowest_next_timeout == TMR_NEVER || remaining_time < lowest_next_timeout)
				lowest_next_timeout = remaining_time;

			SLIST_INSERT_HEAD(&socktimer, current_sock, sock_timer);

			current_sock->sock_flags |= SFL_TIMER;
		}
	}

	if (lowest_next_timeout != TMR_NEVER)
		set_timer(&sockevent_timer, lowest_next_timeout, socktimer_expire, 0);

	if (was_already_working == FALSE) {
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
socktimer_add(struct sock * sock, clock_t ticks)
{
	clock_t now;

	assert(ticks <= TMRDIFF_MAX);

	if (!(sock->sock_flags & SFL_TIMER)) {
		SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);

		sock->sock_flags |= SFL_TIMER;
	}

	now = getticks();

	if (!tmr_is_set(&sockevent_timer) ||
	    tmr_is_first(now + ticks, tmr_exp_time(&sockevent_timer)))
		set_timer(&sockevent_timer, ticks, socktimer_expire, 0);

	return now + ticks;
}

/*
 * Remove a socket object from the set of socket objects with timers.  Since
 * the timer list is maintained lazily, this needs to be done only right before
 * the socket object is freed.
 */
static void
socktimer_del(struct sock * sock)
{
	if (sock == NULL) {
		return;
	}

	if (sock->sock_flags & SFL_TIMER) {
		SLIST_REMOVE(&socktimer, sock, sock, sock_timer);
		sock->sock_flags &= ~SFL_TIMER;
	}
}

/*
 * Bind a socket to a local address.
 */
static int
sockevent_bind(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock;
	int r;

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_bind == NULL) {
		return EOPNOTSUPP;
	}

	/* Binding a socket in listening mode is never supported. */
	if (sock->sock_opt & SO_ACCEPTCONN) {
		return EINVAL;
	}

	r = sock->sock_ops->sop_bind(sock, addr, addr_len, user_endpt);

	if (r == SUSPEND) {
		if (call == NULL) {
			return EINPROGRESS;
		}
		sockevent_suspend(sock, SEV_BIND, call, user_endpt);
	}

	return r;
}

/*
 * Connect a socket to a remote address.
 */
static int
sockevent_connect(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * call)
{
	struct sock *sock;
	int r;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_connect == NULL) {
		return EOPNOTSUPP;
	}

	if (sock->sock_opt & SO_ACCEPTCONN) {
		return EOPNOTSUPP;
	}

	r = sock->sock_ops->sop_connect(sock, addr, addr_len, user_endpt);

	if (r == SUSPEND) {
		assert(!sockevent_has_suspended(sock, SEV_SEND | SEV_RECV));

		if (call != NULL) {
			sockevent_suspend(sock, SEV_CONNECT, call, user_endpt);
			r = EINPROGRESS;
		} else {
			if (sockevent_has_events()) {
				struct sockdriver_call temporary_call = { .sc_endpt = NONE };

				sockevent_suspend(sock, SEV_CONNECT, &temporary_call, user_endpt);
				sockevent_pump();

				struct sockevent_proc *spr = sockevent_unsuspend(sock, &temporary_call);
				if (spr != NULL) {
					sockevent_proc_free(spr);
					r = EINPROGRESS;
				} else {
					if (sock->sock_err != OK) {
						r = sock->sock_err;
						sock->sock_err = OK;
					} else {
						r = OK;
					}
				}
			} else {
				r = EINPROGRESS;
			}
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
sockevent_listen(sockid_t id, int backlog)
{
	struct sock *sock;
	int r;

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_listen == NULL) {
		return EOPNOTSUPP;
	}

	if (backlog < 0) {
		backlog = 0;
	}
	if (backlog < SOMAXCONN) {
		backlog += 1 + (backlog >> 1);
	}
	if (backlog > SOMAXCONN) {
		backlog = SOMAXCONN;
	}

	r = sock->sock_ops->sop_listen(sock, backlog);

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
	struct sock *sock, *newsock;
	sockid_t r;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_accept == NULL)
		return EOPNOTSUPP;

	newsock = NULL;

	if ((r = sock->sock_ops->sop_accept(sock, addr, addr_len, user_endpt,
	    &newsock)) == SUSPEND) {
		if (call == NULL)
			return EWOULDBLOCK;

		sockevent_suspend(sock, SEV_ACCEPT, call, user_endpt);

		return SUSPEND;
	}

	if (r >= 0)
		sockevent_accepted(sock, newsock, r);

	return r;
}

/*
 * Send regular and/or control data.
 */
static int sockevent_do_oob_send(struct sock *sock,
                                  const struct sockdriver_data *data, size_t len,
                                  const struct sockdriver_data *ctl_data, socklen_t ctl_len,
                                  const struct sockaddr *addr, socklen_t addr_len,
                                  endpoint_t user_endpt, int flags,
                                  size_t *out_off, socklen_t *out_ctl_off)
{
    int r;
    *out_off = 0;
    *out_ctl_off = 0;

    r = sock->sock_ops->sop_send(sock, data, len, out_off, ctl_data,
                                ctl_len, out_ctl_off, addr, addr_len, user_endpt, flags, 0);

    if (r == SUSPEND) {
        panic("libsockevent: MSG_OOB send calls may not be suspended");
    }
    return r;
}

static int sockevent_handle_suspension_or_nonblock(struct sock *sock,
                                                   size_t off, socklen_t ctl_off,
                                                   int flags,
                                                   const struct sockdriver_call *call,
                                                   endpoint_t user_endpt,
                                                   const struct sockdriver_data *data,
                                                   size_t len,
                                                   const struct sockdriver_data *ctl_data)
{
    if (call != NULL) {
        int timer = FALSE;
        clock_t time = 0;
        if (sock->sock_stimeo != 0) {
            timer = TRUE;
            time = socktimer_add(sock, sock->sock_stimeo);
        }
        sockevent_suspend_data(sock, SEV_SEND, timer, call,
                               user_endpt, data, len, off, ctl_data, ctl_len,
                               ctl_off, flags, 0, time);
        return SUSPEND;
    } else {
        return (off > 0 || ctl_off > 0) ? OK : EWOULDBLOCK;
    }
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
	size_t off = 0;
	socklen_t ctl_off = 0;

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

    int pre_send_flags = flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL);
	if (sock->sock_ops->sop_pre_send != NULL &&
	    (r = sock->sock_ops->sop_pre_send(sock, len, ctl_len, addr,
	    addr_len, user_endpt, pre_send_flags)) != OK)
		return r;

	if (sock->sock_ops->sop_send == NULL)
		return EOPNOTSUPP;

	if (flags & MSG_OOB) {
		r = sockevent_do_oob_send(sock, data, len, ctl_data, ctl_len,
                                      addr, addr_len, user_endpt, flags,
                                      &off, &ctl_off);
		return (r == OK) ? (int)off : r;
	}

	size_t min_send_size = 0;
	if (!sockevent_has_suspended(sock, SEV_SEND)) {
		min_send_size = sock->sock_slowat;
		if (min_send_size > len)
			min_send_size = len;

		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, min_send_size);
	} else {
		r = SUSPEND;
	}

	if (r == SUSPEND) {
		r = sockevent_handle_suspension_or_nonblock(sock, off, ctl_off,
                                                            flags, call, user_endpt,
                                                            data, len, ctl_data);
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
	int original_flags = *flags;
	*flags = 0;

	if (sock->sock_ops->sop_pre_recv != NULL) {
		int result = sock->sock_ops->sop_pre_recv(sock, user_endpt,
		    original_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (result != OK) {
			return result;
		}
	}

	if (sock->sock_flags & SFL_SHUT_RD) {
		return SOCKEVENT_EOF;
	}

	if (sock->sock_ops->sop_recv == NULL) {
		return EOPNOTSUPP;
	}

	int is_oob = (original_flags & MSG_OOB);

	if (is_oob && (sock->sock_opt & SO_OOBINLINE)) {
		return EINVAL;
	}

	int r;
	size_t min_recv_size = 0;

	if (is_oob || !sockevent_has_suspended(sock, SEV_RECV)) {
		if (!is_oob && sock->sock_err == OK) {
			min_recv_size = sock->sock_rlowat;
			if (min_recv_size > len) {
				min_recv_size = len;
			}
		}

		r = sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
		    ctl_len, ctl_off, addr, addr_len, user_endpt,
		    original_flags, min_recv_size, flags);
	} else {
		r = SUSPEND;
	}

	assert(r <= 0 || r == SOCKEVENT_EOF);

	if (r == SUSPEND) {
		if (is_oob) {
			panic("libsockevent: MSG_OOB receive calls may not be suspended");
		}

		if (call != NULL && sock->sock_err == OK) {
			clock_t suspend_time = 0;
			int use_timer = FALSE;

			if (sock->sock_rtimeo != 0) {
				use_timer = TRUE;
				suspend_time = socktimer_add(sock, sock->sock_rtimeo);
			}

			sockevent_suspend_data(sock, SEV_RECV, use_timer, call,
			    user_endpt, data, len, *off, ctl_data,
			    ctl_len, *ctl_off, original_flags, *flags, suspend_time);
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
	size_t received_bytes = 0;
	socklen_t ctl_input_len;
	int inner_result;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	// Store the original control length for the inner call, then clear it
	// to ensure it's properly set by the inner function for output.
	ctl_input_len = *ctl_len;
	*ctl_len = 0;

	// Attempt to perform the actual receive call.
	inner_result = sockevent_recv_inner(sock, data, len, &received_bytes, ctl_data, ctl_input_len,
	    ctl_len, addr, addr_len, user_endpt, flags, call);

	// Determine the final return value based on the following precedence:
	// 1. Data received (either payload or control data).
	// 2. A pending socket error.
	// 3. End-of-file (EOF).
	// 4. Other results from the inner call (e.g., SUSPEND, EAGAIN).

	// Priority 1: If any data (payload or control) was received, return the amount of payload data.
	// This takes precedence over any error codes (except SUSPEND, as per original logic's implied invariant).
	if (received_bytes > 0 || *ctl_len > 0) {
		return (int)received_bytes;
	}

	// Priority 2: If no data was received, check for a pending socket error.
	if (sock->sock_err != 0) { // Assuming OK is 0.
		int pending_error = sock->sock_err;
		sock->sock_err = 0; // Clear the pending error after returning it.
		return pending_error;
	}

	// Priority 3: If no data and no pending error, check if the inner call indicated EOF.
	if (inner_result == SOCKEVENT_EOF) {
		return 0; // Standard convention for EOF on read.
	}

	// Priority 4: Otherwise, return the direct result from the inner call.
	// This covers cases like SUSPEND, EAGAIN, EINTR, or other non-pending errors.
	return inner_result;
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
	int r;

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	switch (request) {
	case FIONREAD: {
		size_t bytes_available = 0;
		if (!(sock->sock_flags & SFL_SHUT_RD) &&
		    sock->sock_ops->sop_test_recv != NULL)
		{
			(void)sock->sock_ops->sop_test_recv(sock, 0, &bytes_available);
		}

		int val;
		if (bytes_available > INT_MAX) {
			val = INT_MAX;
		} else {
			val = (int)bytes_available;
		}

		return sockdriver_copyout(data, 0, &val, sizeof(val));
	}
	}

	if (sock->sock_ops->sop_ioctl == NULL) {
		return ENOTTY;
	}

	r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

	if (r == SUSPEND) {
		panic("libsockevent: socket driver suspended IOCTL 0x%lx for sock ID %d",
		    request, id);
	}

	return r;
}

/*
 * Set socket options.
 */
static int
sockevent_setsockopt(sockid_t id, int level, int name,
	const struct sockdriver_data * data, socklen_t len)
{
	struct sock *sock;
	int r;

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
		case SO_TIMESTAMP: {
			int val;
			unsigned int option_mask = (unsigned int)name;

			if ((r = sockdriver_copyin_opt(data, &val, sizeof(val), len)) != OK)
				return r;

			if (val)
				sock->sock_opt |= option_mask;
			else
				sock->sock_opt &= ~option_mask;

			if (sock->sock_ops->sop_setsockmask != NULL)
				sock->sock_ops->sop_setsockmask(sock, sock->sock_opt);

			if (name == SO_OOBINLINE && val)
				sockevent_raise(sock, SEV_RECV);

			return OK;
		}

		case SO_LINGER: {
			struct linger linger_opt;

			if ((r = sockdriver_copyin_opt(data, &linger_opt, sizeof(linger_opt), len)) != OK)
				return r;

			if (linger_opt.l_onoff) {
				if (linger_opt.l_linger < 0)
					return EINVAL;
				
				clock_t secs = (clock_t)linger_opt.l_linger;
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

		case SO_SNDLOWAT:
		case SO_RCVLOWAT: {
			int val;

			if ((r = sockdriver_copyin_opt(data, &val, sizeof(val), len)) != OK)
				return r;

			if (val <= 0)
				return EINVAL;

			if (name == SO_SNDLOWAT) {
				sock->sock_slowat = (size_t)val;
				sockevent_raise(sock, SEV_SEND);
			} else { /* SO_RCVLOWAT */
				sock->sock_rlowat = (size_t)val;
				sockevent_raise(sock, SEV_RECV);
			}

			return OK;
		}

		case SO_SNDTIMEO:
		case SO_RCVTIMEO: {
			struct timeval tv_opt;
			clock_t total_ticks, micro_ticks;

			if ((r = sockdriver_copyin_opt(data, &tv_opt, sizeof(tv_opt), len)) != OK)
				return r;

			if (tv_opt.tv_sec < 0 || tv_opt.tv_usec < 0 ||
			    (unsigned long)tv_opt.tv_usec >= US)
				return EINVAL;
			
			if (tv_opt.tv_sec >= TMRDIFF_MAX / sys_hz())
				return EDOM;

			total_ticks = (clock_t)tv_opt.tv_sec * sys_hz();
			
			micro_ticks = (clock_t)(((long long)tv_opt.tv_usec * sys_hz() + US - 1) / US);

			if (TMRDIFF_MAX - micro_ticks < total_ticks)
				return EDOM; /* Check for overflow of total_ticks + micro_ticks */
			
			total_ticks += micro_ticks;

			if (name == SO_SNDTIMEO)
				sock->sock_stimeo = total_ticks;
			else /* SO_RCVTIMEO */
				sock->sock_rtimeo = total_ticks;

			return OK;
		}

		case SO_ACCEPTCONN:
		case SO_ERROR:
		case SO_TYPE:
			return ENOPROTOOPT;

		default:
			/* Unrecognized SOL_SOCKET options fall through to driver handler */
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
	struct linger linger;
	struct timeval tv;
	clock_t ticks;
	int val;
	long hertz;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	if (level == SOL_SOCKET) {
		hertz = sys_hz();

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

		case SO_LINGER:
			linger.l_onoff = (sock->sock_opt & SO_LINGER) != 0;
			linger.l_linger = (hertz > 0) ? (sock->sock_linger / hertz) : 0;

			return sockdriver_copyout_opt(data, &linger,
			   sizeof(linger), len);

		case SO_ERROR:
			val = -sock->sock_err;
			if (val != OK) {
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
		case SO_RCVTIMEO:
			if (name == SO_SNDTIMEO) {
				ticks = sock->sock_stimeo;
			} else {
				ticks = sock->sock_rtimeo;
			}

			if (hertz > 0) {
				tv.tv_sec = ticks / hertz;
				tv.tv_usec = (ticks % hertz) * 1000000L / hertz;
			} else {
				tv.tv_sec = 0;
				tv.tv_usec = 0;
			}

			return sockdriver_copyout_opt(data, &tv, sizeof(tv),
			    len);

		default:
			break;
		}
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_getsockopt == NULL) {
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
	struct sock *sock;

	if (addr == NULL || addr_len == NULL) {
		return EINVAL;
	}

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_getsockname == NULL) {
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
	struct sock *sock;

	if (addr == NULL || addr_len == NULL)
		return EINVAL;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (sock->sock_opt & SO_ACCEPTCONN)
		return ENOTCONN;

	if (sock->sock_ops->sop_getpeername == NULL)
		return EOPNOTSUPP;

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
	unsigned int mask;

	assert(sock->sock_ops != NULL);

	/* Ensure only valid shutdown flags are processed. */
	flags &= (SFL_SHUT_RD | SFL_SHUT_WR);

	/* Look at the newly set flags only. */
	flags &= ~sock->sock_flags;

	if (flags != 0) {
		sock->sock_flags |= flags;

		/*
		 * Wake up any blocked calls that are affected by the shutdown.
		 * Shutting down listening sockets causes ongoing accept calls
		 * to be rechecked.
		 */
		mask = 0;
		if (flags & SFL_SHUT_RD) {
			mask |= SEV_RECV;
		}
		if (flags & SFL_SHUT_WR) {
			mask |= SEV_SEND;
		}
		if (sock->sock_opt & SO_ACCEPTCONN) {
			mask |= SEV_ACCEPT;
		}

		assert(mask != 0);
		sockevent_raise(sock, mask);
	}
}

/*
 * Shut down socket send and receive operations.
 */
static int
sockevent_shutdown(sockid_t id, int how)
{
	struct sock *sock;
	unsigned int flags = 0;
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
sockevent_close(sockid_t id, const struct sockdriver_call * call)
{
	struct sock *sock;
	int driver_status;
	int return_value = OK;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	assert(sock->sock_proc == NULL);
	sock->sock_select.ss_endpt = NONE;

	const int force_close_immediately = ((sock->sock_opt & SO_LINGER) && sock->sock_linger == 0);

	if (sock->sock_ops->sop_close != NULL) {
		driver_status = sock->sock_ops->sop_close(sock, force_close_immediately);
	} else {
		driver_status = OK;
	}

	assert(driver_status == OK || driver_status == SUSPEND);

	if (driver_status == SUSPEND) {
		sock->sock_flags |= SFL_CLOSING;

		if (force_close_immediately) {
			// If force-closing immediately, the caller's close(2) returns OK
			// even if the driver needs more time. The actual cleanup is asynchronous.
			return_value = OK;
		} else {
			// Handle graceful or SO_LINGER with timeout close.
			// Set a timer if SO_LINGER is active to ensure eventual forceful close.
			if (sock->sock_opt & SO_LINGER) {
				sock->sock_linger = socktimer_add(sock, sock->sock_linger);
				// If a callback is provided and SO_LINGER is set,
				// the close operation can be suspended for asynchronous completion.
				if (call != NULL) {
					sockevent_suspend(sock, SEV_CLOSE, call, NONE);
				}
			}
			// If SO_LINGER is not set, the call is never suspended (per original logic and comments).
			// In either case, for the caller of `close(2)`, the file descriptor is freed.
			return_value = OK;
		}
	} else { // driver_status == OK
		// Driver completed the close immediately; free socket resources.
		sockevent_free(sock);
		return_value = OK;
	}

	return return_value;
}

/*
 * Cancel a suspended send request.
 */
static void
sockevent_cancel_send(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int r;

	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
		r = (int)spr->spr_dataoff;
	else
		r = err;

	sockdriver_reply_generic(&spr->spr_call, r);

	sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static void
sockevent_cancel_recv(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int reply_code = (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
	               ? (int)spr->spr_dataoff
	               : err;

	sockdriver_reply_recv(&spr->spr_call, reply_code, spr->spr_ctloff, NULL, 0,
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
sockevent_cancel(sockid_t id, const struct sockdriver_call * call)
{
	struct sockevent_proc *spr;
	struct sock *sock;
	int reply_error_code = EINTR;

	if ((sock = sockhash_get(id)) == NULL)
		return;

	if ((spr = sockevent_unsuspend(sock, call)) == NULL)
		return;

	switch (spr->spr_event) {
	case SEV_BIND:
	case SEV_CONNECT:
		assert(spr->spr_call.sc_endpt != NONE);
		sockdriver_reply_generic(&spr->spr_call, reply_error_code);
		break;

	case SEV_ACCEPT:
		sockdriver_reply_accept(&spr->spr_call, reply_error_code, NULL, 0);
		break;

	case SEV_SEND:
		sockevent_cancel_send(sock, spr, reply_error_code);
		break;

	case SEV_RECV:
		sockevent_cancel_recv(sock, spr, reply_error_code);
		break;

	case SEV_CLOSE:
		sockdriver_reply_generic(&spr->spr_call, EINPROGRESS);
		break;

	default:
		panic("libsockevent: process suspended on unknown event 0x%x",
		    spr->spr_event);
	}

	sockevent_proc_free(spr);
}

/*
 * Process a select request.
 */
static int
sockevent_select(sockid_t id, unsigned int ops_param,
	const struct sockdriver_select * sel)
{
	struct sock *sock;
	unsigned int notified_ops;
	unsigned int requested_ops;
	unsigned int ops_to_monitor;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	const unsigned int notify_flag = (ops_param & SDEV_NOTIFY);
	requested_ops = (ops_param & (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR));

	notified_ops = sockevent_test_select(sock, requested_ops);

	assert(!(sock->sock_selops & notified_ops));

	ops_to_monitor = requested_ops & ~notified_ops;

	if (notify_flag && ops_to_monitor != 0) {
		if (sock->sock_select.ss_endpt != NONE) {
			if (sock->sock_select.ss_endpt != sel->ss_endpt) {
				return EIO;
			}
			sock->sock_selops |= ops_to_monitor;
		} else {
			assert(sel->ss_endpt != NONE);
			sock->sock_select = *sel;
			sock->sock_selops = ops_to_monitor;
		}
	}

	return notified_ops;
}

/*
 * An alarm has triggered.  Expire any timers.  Socket drivers that do not pass
 * clock notification messages to libsockevent must call expire_timers(3)
 * themselves instead.
 */
static void
sockevent_alarm(const clock_t now)
{
	expire_timers(now);
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
void
sockevent_init(sockevent_socket_cb_t socket_cb)
{
	if (socket_cb == ((void *)0)) {
		(void)fprintf(stderr, "Error: sockevent_init: socket_cb cannot be NULL. Terminating.\n");
		exit(EXIT_FAILURE);
	}

	sockhash_init();

	socktimer_init();

	sockevent_proc_init();

	SIMPLEQ_INIT(&sockevent_pending);

	sockevent_socket_cb = socket_cb;

	sockdriver_announce();

	sockevent_working = 0;
}

/*
 * Process a socket driver request message.
 */
void
sockevent_process(const message * m_ptr, int ipc_status)
{
	assert(!sockevent_working);
	sockevent_working = TRUE;

	sockdriver_process(&sockevent_tab, m_ptr, ipc_status);

	if (sockevent_has_events()) {
		sockevent_pump();
	}

	goto cleanup;

cleanup:
	sockevent_working = FALSE;
}
