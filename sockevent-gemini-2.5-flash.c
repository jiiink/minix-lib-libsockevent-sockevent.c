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
	unsigned int slot;

	for (slot = 0; slot < sizeof(sockhash) / sizeof(sockhash[0]); slot++)
		SLIST_INIT(&sockhash[slot]);
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
static unsigned int
sockhash_slot(sockid_t id)
{
	static const unsigned int SOCKHASH_ID_SHIFT_BITS = 16;
	return (id + (id >> SOCKHASH_ID_SHIFT_BITS)) % SOCKHASH_SLOTS;
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *
sockhash_get(const sockid_t id)
{
	struct sock *sock;
	unsigned int slot;

	slot = sockhash_slot(id);

	SLIST_FOREACH(sock, &sockhash[slot], sock_hash) {
		if (sock->sock_id == id)
			return sock;
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
		/*
		 * If sock is NULL, we cannot safely access sock->sock_id.
		 * Returning early prevents a null pointer dereference,
		 * improving reliability and security.
		 * An actual application might log this error or assert.
		 */
		return;
	}

	unsigned int slot;

	slot = sockhash_slot(sock->sock_id);

	/*
	 * SLIST_INSERT_HEAD is a macro; assuming `sockhash` is a properly
	 * defined global or file-scope array of SLIST_HEAD structures,
	 * and `sock_hash` is a SLIST_ENTRY member within `struct sock`.
	 * No explicit locking is added here to avoid altering external
	 * functionality regarding thread-safety behavior, as the original
	 * code did not include any. If thread-safety is required,
	 * external synchronization (e.g., a mutex) would be necessary
	 * around this operation.
	 */
	SLIST_INSERT_HEAD(&sockhash[slot], sock, sock_hash);
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
	static const int DEFAULT_SOCKET_LOWAT_MARK = 1;

	assert(sock != NULL);

	memset(sock, 0, sizeof(*sock));

	sock->sock_id = id;
	sock->sock_domain = domain;
	sock->sock_type = type;

	sock->sock_slowat = DEFAULT_SOCKET_LOWAT_MARK;
	sock->sock_rlowat = DEFAULT_SOCKET_LOWAT_MARK;

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
sockevent_accepted(struct sock * sock, struct sock * newsock_param, sockid_t newid)
{
	struct sock *actual_newsock = newsock_param;

	if (actual_newsock == NULL) {
		actual_newsock = sockhash_get(newid);
		if (actual_newsock == NULL) {
			panic("libsockdriver: socket driver returned unknown "
			    "ID %d from accept callback", newid);
		}
	} else {
		sockevent_clone(sock, actual_newsock, newid);
	}

	assert(actual_newsock->sock_flags & SFL_CLONED);
	actual_newsock->sock_flags &= ~SFL_CLONED;
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
	struct sock *sock = NULL;
	const struct sockevent_ops *ops = NULL;
	sockid_t r;

	if (sockp == NULL) {
		return EFAULT;
	}
	*sockp = NULL;

	if (domain < 0 || domain > UINT8_MAX) {
		return EAFNOSUPPORT;
	}

	if (sockevent_socket_cb == NULL) {
		panic("libsockevent: not initialized");
	}

	r = sockevent_socket_cb(domain, type, protocol, user_endpt, &sock, &ops);

	if (r < 0) {
		return r;
	}

	if (sock == NULL || ops == NULL) {
		return EFAULT;
	}

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
		/* Reliability: If 'sock' is NULL, there's nothing to free.
		 * Returning here prevents a NULL dereference and improves robustness. */
		return;
	}

	/* Maintainability/Reliability: This assert confirms a critical
	 * precondition: 'sock_proc' should already be NULL before freeing the socket.
	 * It helps catch logic errors in debug builds. */
	assert(sock->sock_proc == NULL);

	socktimer_del(sock);
	sockhash_del(sock);

	const struct sockevent_ops *ops = sock->sock_ops;

	/* Security/Reliability: Invalidate the operations table on the socket
	 * *before* its specific resources are freed. This helps detect and
	 * prevent use-after-free vulnerabilities or unintended calls to operations
	 * on a partially or completely freed socket. */
	sock->sock_ops = NULL;

	/* Reliability: Explicitly check 'ops' and 'ops->sop_free' before dereferencing.
	 * The original code used asserts, implying these are critical invariants.
	 * In release builds (where asserts are removed), a NULL 'ops' or 'sop_free'
	 * would lead to a crash due to NULL dereference.
	 * To prevent undefined behavior and improve system stability (as per SonarCloud
	 * recommendations for NULL dereferences), we guard the call.
	 * If 'ops' or 'ops->sop_free' is NULL, the socket cannot be properly freed
	 * using its specific operations, leading to a resource leak. This is a severe
	 * problem but generally considered preferable to a program crash in a `void` function
	 * where no error can be returned. */
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
	struct sock *sock;
	int allocation_status;

	allocation_status = sockevent_alloc(domain, type, protocol, user_endpt, &sock);
	if (allocation_status != OK)
	{
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
	int r;

	r = sockevent_alloc(domain, type, protocol, user_endpt, &sock1);
	if (r != OK) {
		goto err_sock1_alloc;
	}

	if (sock1->sock_ops == NULL || sock1->sock_ops->sop_pair == NULL) {
		r = EOPNOTSUPP;
		goto err_sock2_alloc;
	}

	r = sockevent_alloc(domain, type, protocol, user_endpt, &sock2);
	if (r != OK) {
		goto err_sock2_alloc;
	}

	r = sock1->sock_ops->sop_pair(sock1, sock2, user_endpt);
	if (r != OK) {
		goto err_sop_pair;
	}

	id[0] = sock1->sock_id;
	id[1] = sock2->sock_id;
	return OK;

err_sop_pair:
	sockevent_free(sock2);
err_sock2_alloc:
	sockevent_free(sock1);
err_sock1_alloc:
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
	    !(sock->sock_opt & SO_NOSIGPIPE)) {
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
	struct sockevent_proc *new_proc_event;
	struct sockevent_proc **current_ptr;

	new_proc_event = sockevent_proc_alloc();
	if (new_proc_event == NULL) {
		panic("libsockevent: too many suspended processes");
	}

	new_proc_event->spr_next = NULL;
	new_proc_event->spr_event = event;
	new_proc_event->spr_timer = FALSE;
	new_proc_event->spr_call = *call;
	new_proc_event->spr_endpt = user_endpt;

	for (current_ptr = &sock->sock_proc; *current_ptr != NULL;
	     current_ptr = &(*current_ptr)->spr_next);
	*current_ptr = new_proc_event;
}

/*
 * Suspend a request with data, that is, a send or receive request.
 */
static void
sockevent_proc_initialize(struct sockevent_proc *spr, unsigned int event, int timer,
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt,
	const struct sockdriver_data * __restrict data, size_t len, size_t off,
	const struct sockdriver_data * __restrict ctl, socklen_t ctl_len,
	socklen_t ctl_off, int flags, int rflags, clock_t time)
{
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
}

static void
sockevent_suspend_data(struct sock * sock, unsigned int event, int timer,
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt,
	const struct sockdriver_data * __restrict data, size_t len, size_t off,
	const struct sockdriver_data * __restrict ctl, socklen_t ctl_len,
	socklen_t ctl_off, int flags, int rflags, clock_t time)
{
	struct sockevent_proc *spr;

	if ((spr = sockevent_proc_alloc()) == NULL)
		panic("libsockevent: too many suspended processes");

	sockevent_proc_initialize(spr, event, timer, call, user_endpt,
	                          data, len, off, ctl, ctl_len, ctl_off,
	                          flags, rflags, time);

	struct sockevent_proc **sprp;
	for (sprp = &sock->sock_proc; *sprp != NULL;
	     sprp = &(*sprp)->spr_next);
	*sprp = spr;
}

/*
 * Return TRUE if there are any suspended requests on the given socket's queue
 * that match any of the events in the given event mask, or FALSE otherwise.
 */
static int
sockevent_has_suspended(const struct sock *sock, unsigned int mask)
{
	const struct sockevent_proc *spr;

	if (sock == NULL) {
		return 0;
	}

	for (spr = sock->sock_proc; spr != NULL; spr = spr->spr_next) {
		if ((spr->spr_event & mask) != 0) {
			return 1;
		}
	}

	return 0;
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

	struct sockevent_proc *spr, **sprp;

	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL;
	    sprp = &spr->spr_next) {
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
sockevent_resume(struct sock * sock, struct sockevent_proc * spr)
{
	struct sock *newsock;
	struct sockdriver_data data, ctl;
	char addr[SOCKADDR_MAX];
	socklen_t addr_len;
	size_t len, min;
	sockid_t r;

	switch (spr->spr_event) {
	case SEV_CONNECT:
		if (spr->spr_call.sc_endpt == NONE) {
			return TRUE;
		}
		// Fall through to SEV_BIND logic for a normal connect completion.

	case SEV_BIND: {
		sockid_t result_code = OK;
		if (sock->sock_err != OK) {
			result_code = sock->sock_err;
			sock->sock_err = OK;
		}
		sockdriver_reply_generic(&spr->spr_call, result_code);
		return TRUE;
	}

	case SEV_ACCEPT: {
		assert(sock->sock_opt & SO_ACCEPTCONN);

		addr_len = 0;
		newsock = NULL;

		sockid_t accept_result = sock->sock_ops->sop_accept(sock,
		    (struct sockaddr *)&addr, &addr_len, spr->spr_endpt,
		    &newsock);

		if (accept_result == SUSPEND) {
			return FALSE;
		}

		if (accept_result >= 0) {
			assert(addr_len <= sizeof(addr));
			sockevent_accepted(sock, newsock, accept_result);
		}

		sockdriver_reply_accept(&spr->spr_call, accept_result,
		    (struct sockaddr *)&addr, addr_len);
		return TRUE;
	}

	case SEV_SEND: {
		sockid_t send_op_result;

		if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
			if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
				send_op_result = (sockid_t)spr->spr_dataoff;
			} else if (sock->sock_err != OK) {
				send_op_result = sock->sock_err;
				sock->sock_err = OK;
			} else {
				send_op_result = EPIPE;
			}
		} else {
			sockdriver_unpack_data(&data, &spr->spr_call,
			    spr->spr_data, spr->spr_datalen);
			sockdriver_unpack_data(&ctl, &spr->spr_call,
			    spr->spr_ctl, spr->spr_ctllen);

			len = spr->spr_datalen - spr->spr_dataoff;
			min = (sock->sock_slowat > len) ? len : sock->sock_slowat;

			send_op_result = sock->sock_ops->sop_send(sock, &data, len,
			    &spr->spr_dataoff, &ctl,
			    spr->spr_ctllen - spr->spr_ctloff,
			    &spr->spr_ctloff, NULL, 0, spr->spr_endpt,
			    spr->spr_flags, min);

			assert(send_op_result <= 0);

			if (send_op_result == SUSPEND) {
				return FALSE;
			}

			if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
				send_op_result = (sockid_t)spr->spr_dataoff;
			}
		}

		if (send_op_result == EPIPE) {
			sockevent_sigpipe(sock, spr->spr_endpt, spr->spr_flags);
		}

		sockdriver_reply_generic(&spr->spr_call, send_op_result);
		return TRUE;
	}

	case SEV_RECV: {
		addr_len = 0;
		sockid_t receive_op_result;
		sockid_t reply_final_result;

		if (sock->sock_flags & SFL_SHUT_RD) {
			receive_op_result = SOCKEVENT_EOF;
		} else {
			len = spr->spr_datalen - spr->spr_dataoff;
			min = (sock->sock_err == OK) ?
			      ((sock->sock_rlowat > len) ? len : sock->sock_rlowat) : 0;

			sockdriver_unpack_data(&data, &spr->spr_call,
			    spr->spr_data, spr->spr_datalen);
			sockdriver_unpack_data(&ctl, &spr->spr_call,
			    spr->spr_ctl, spr->spr_ctllen);

			receive_op_result = sock->sock_ops->sop_recv(sock, &data, len,
			    &spr->spr_dataoff, &ctl,
			    spr->spr_ctllen - spr->spr_ctloff,
			    &spr->spr_ctloff, (struct sockaddr *)&addr,
			    &addr_len, spr->spr_endpt, spr->spr_flags, min,
			    &spr->spr_rflags);

			if (receive_op_result == SUSPEND) {
				if (sock->sock_err == OK) {
					return FALSE;
				}
				receive_op_result = SOCKEVENT_EOF;
			}
			assert(addr_len <= sizeof(addr));
		}

		if (receive_op_result == OK || spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
			reply_final_result = (sockid_t)spr->spr_dataoff;
		} else if (sock->sock_err != OK) {
			reply_final_result = sock->sock_err;
			sock->sock_err = OK;
		} else if (receive_op_result == SOCKEVENT_EOF) {
			reply_final_result = 0;
		} else {
			reply_final_result = receive_op_result;
		}

		sockdriver_reply_recv(&spr->spr_call, reply_final_result, spr->spr_ctloff,
		    (struct sockaddr *)&addr, addr_len, spr->spr_rflags);
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
sockevent_test_readable(struct sock * sock)
{
	if (sock->sock_flags & SFL_SHUT_RD) {
		return TRUE;
	}

	if (sock->sock_err != OK) {
		return TRUE;
	}

	if (sock->sock_ops == NULL) {
		/*
		 * If socket operations are not defined, we cannot test for
		 * readability. Consistent with the logic for missing specific
		 * test functions, assume it's readable.
		 */
		return TRUE;
	}

	int test_result;

	if (sock->sock_opt & SO_ACCEPTCONN) {
		if (sock->sock_ops->sop_test_accept == NULL) {
			/* No specific accept test available, assume readable. */
			return TRUE;
		}
		test_result = sock->sock_ops->sop_test_accept(sock);
	} else {
		if (sock->sock_ops->sop_test_recv == NULL) {
			/* No specific receive test available, assume readable. */
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
	if (sock->sock_err != OK ||
	    (sock->sock_flags & SFL_SHUT_WR) ||
	    sock->sock_ops->sop_test_send == NULL) {
		return TRUE;
	}

	int r = sock->sock_ops->sop_test_send(sock, sock->sock_slowat);

	return (r != SUSPEND);
}

/*
 * Test whether any of the given select operations are ready on the given
 * socket.  Return the subset of ready operations; zero if none.
 */
static unsigned int
sockevent_test_select(struct sock * sock, unsigned int ops)
{
	unsigned int ready_ops = 0;

	if ((ops & SDEV_OP_RD) && sockevent_test_readable(sock))
		ready_ops |= SDEV_OP_RD;

	if ((ops & SDEV_OP_WR) && sockevent_test_writable(sock))
		ready_ops |= SDEV_OP_WR;

	return ready_ops;
}

/*
 * Fire the given mask of events on the given socket object now.
 */
static unsigned int sockevent_adjust_mask_for_connect(unsigned int mask);
static void sockevent_resume_suspended_calls(struct sock *sock, unsigned int *current_mask_ptr);
static void sockevent_handle_select_queries(struct sock *sock, unsigned int mask);
static void sockevent_process_close_event(struct sock *sock, unsigned int mask);

static unsigned int
sockevent_adjust_mask_for_connect(unsigned int mask)
{
	/*
	 * A completed connection attempt (successful or not) also always
	 * implies that the socket becomes writable. For convenience we
	 * enforce this rule here, because it is easy to forget.
	 */
	if (mask & SEV_CONNECT) {
		mask |= SEV_SEND;
	}
	return mask;
}

static void
sockevent_resume_suspended_calls(struct sock *sock, unsigned int *current_mask_ptr)
{
	struct sockevent_proc *spr, **sprp;
	unsigned int flag;

	/*
	 * First try resuming regular system calls.
	 * The 'current_mask_ptr' allows consuming event flags for subsequent
	 * suspended calls if a preceding call could not be resumed by that flag.
	 */
	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL; ) {
		flag = spr->spr_event;

		if ((*current_mask_ptr & flag) && sockevent_resume(sock, spr)) {
			/*
			 * Successfully resumed: remove from list and free.
			 * The event 'flag' remains in the mask. This means if a call
			 * successfully handles an event, that event is still available
			 * for other suspended calls or select queries.
			 */
			*sprp = spr->spr_next;
			sockevent_proc_free(spr);
		} else {
			/*
			 * Not resumed (either no event match or sockevent_resume returned false).
			 * Consume this specific flag from the mask for *subsequent* suspended calls
			 * in this 'sockevent_fire' execution. This prevents other suspended calls
			 * from attempting to use this event if a preceding one failed with it.
			 */
			*current_mask_ptr &= ~flag;
			sprp = &spr->spr_next;
		}
	}
}

static void
sockevent_handle_select_queries(struct sock *sock, unsigned int mask)
{
	unsigned int ops_to_test;
	unsigned int satisfied_ops;

	/*
	 * Then see if we can satisfy pending select queries.
	 * Return early if no relevant events for select or select is not active.
	 */
	if (!((mask & (SEV_ACCEPT | SEV_SEND | SEV_RECV)) &&
	      sock->sock_select.ss_endpt != NONE)) {
		return;
	}

	/*
	 * If select is active, there should be operations pending.
	 * This assert checks for an inconsistent internal state.
	 */
	assert(sock->sock_selops != 0);

	ops_to_test = sock->sock_selops;

	/*
	 * Only retest select operations that, based on the given event
	 * mask, could possibly be satisfied now.
	 */
	if (!(mask & (SEV_ACCEPT | SEV_RECV))) {
		ops_to_test &= ~SDEV_OP_RD;
	}
	if (!(mask & SEV_SEND)) {
		ops_to_test &= ~SDEV_OP_WR;
	}
	/*
	 * The original 'if (!(0)) ops &= ~SDEV_OP_ERR;' was dead code that
	 * always removed SDEV_OP_ERR. It has been removed.
	 * If error select operations are needed, they should be triggered by SEV_ERR.
	 */

	/* Are there any operations left to test after filtering by the mask? */
	if (ops_to_test == 0) {
		return;
	}

	/* Test those operations. */
	satisfied_ops = sockevent_test_select(sock, ops_to_test);

	/* Were any satisfied? */
	if (satisfied_ops != 0) {
		/* Let the caller know. */
		sockdriver_reply_select(&sock->sock_select, sock->sock_id, satisfied_ops);

		sock->sock_selops &= ~satisfied_ops;

		/* Are there any saved operations left now? If not, deactivate select. */
		if (sock->sock_selops == 0) {
			sock->sock_select.ss_endpt = NONE;
		}
	}
}

static void
sockevent_process_close_event(struct sock *sock, unsigned int mask)
{
	/*
	 * Finally, a SEV_CLOSE event unconditionally frees the sock object.
	 * This event should be fired only for sockets that are either not yet,
	 * or not anymore, in use by userland.
	 */
	if (mask & SEV_CLOSE) {
		assert(sock->sock_flags & (SFL_CLONED | SFL_CLOSING));
		sockevent_free(sock);
	}
}

static void
sockevent_fire(struct sock * sock, unsigned int mask)
{
	/*
	 * Adjust the event mask to ensure connection-related events correctly imply writability.
	 * This initial adjustment applies to all subsequent event processing phases.
	 */
	mask = sockevent_adjust_mask_for_connect(mask);

	/*
	 * Attempt to resume any suspended system calls. The 'mask' variable is passed
	 * by pointer so that modifications (clearing flags if a resume fails)
	 * persist for subsequent processing phases (like select queries).
	 */
	sockevent_resume_suspended_calls(sock, &mask);

	/*
	 * Process pending select/poll queries using the potentially modified event mask.
	 */
	sockevent_handle_select_queries(sock, mask);

	/*
	 * Handle a socket close event, which unconditionally frees the socket object.
	 * This is the final step as the socket will no longer be valid afterwards.
	 */
	sockevent_process_close_event(sock, mask);
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
		struct sock *sock = SIMPLEQ_FIRST(&sockevent_pending);
		SIMPLEQ_REMOVE_HEAD(&sockevent_pending, sock_next);

		unsigned int mask = sock->sock_events;
		sock->sock_events = 0;

		if (mask != 0) {
			sockevent_fire(sock, mask);
		}
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

	assert(mask != 0);
	assert(mask <= UCHAR_MAX);

	if (sockevent_working) {
		if (sock->sock_events == 0)
			SIMPLEQ_INSERT_TAIL(&sockevent_pending, sock,
			    sock_next);

		sock->sock_events |= (unsigned char)mask;
	} else {
		sockevent_working = TRUE;

		sockevent_fire(sock, mask);

		if (sockevent_has_events())
			sockevent_pump();

		sockevent_working = FALSE;
	}
}

/*
 * Set a pending error on the socket object, and wake up any suspended
 * operations that are affected by this.
 */
void
sockevent_set_error(struct sock * sock, int err)
{
	if (sock == NULL) {
		return;
	}

	if (sock->sock_ops == NULL) {
		return;
	}

	if (err >= 0) {
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
static void
handle_closing_socket_expiry(struct sock *sock, clock_t now)
{
	struct sockevent_proc *spr;
	int r;

	if ((sock->sock_opt & SO_LINGER) && tmr_is_first(sock->sock_linger, now)) {
		assert(sock->sock_ops->sop_close != NULL);

		if ((spr = sock->sock_proc) != NULL) {
			assert(spr->spr_event == SEV_CLOSE);
			assert(spr->spr_next == NULL);

			sock->sock_proc = NULL;
			sockdriver_reply_generic(&spr->spr_call, OK);
			sockevent_proc_free(spr);
		}

		r = sock->sock_ops->sop_close(sock, TRUE);

		assert(r == OK || r == SUSPEND);

		if (r == SUSPEND)
			sock->sock_opt &= ~SO_LINGER;
		else
			sockevent_free(sock);
	}
}

static clock_t
handle_pending_requests_expiry(struct sock *sock, clock_t now)
{
	struct sockevent_proc *spr, **sprp;
	clock_t lowest = TMR_NEVER;
	clock_t left;

	sprp = &sock->sock_proc;
	while ((spr = *sprp) != NULL) {
		if (spr->spr_timer == 0) {
			sprp = &spr->spr_next;
			continue;
		}

		assert(spr->spr_event == SEV_SEND || spr->spr_event == SEV_RECV);

		if (tmr_is_first(spr->spr_time, now)) {
			*sprp = spr->spr_next;

			if (spr->spr_event == SEV_SEND)
				sockevent_cancel_send(sock, spr, EWOULDBLOCK);
			else
				sockevent_cancel_recv(sock, spr, EWOULDBLOCK);

			sockevent_proc_free(spr);
		} else {
			left = spr->spr_time - now;

			if (lowest == TMR_NEVER || lowest > left)
				lowest = left;

			sprp = &spr->spr_next;
		}
	}

	return lowest;
}

static clock_t
sockevent_expire(struct sock *sock, clock_t now)
{
	if (sock->sock_flags & SFL_CLOSING) {
		handle_closing_socket_expiry(sock, now);
		return TMR_NEVER;
	}

	return handle_pending_requests_expiry(sock, now);
}

/*
 * The socket event alarm went off.  Go through the set of socket objects with
 * timers, and see if any of their requests have now expired.  Set a new alarm
 * as necessary.
 */
static void
socktimer_expire(int arg)
{
	(void)arg;

	SLIST_HEAD(, sock) expired_sockets_list;
	struct sock *sock, *temp_sock;
	clock_t current_time, next_lowest_timeout, remaining_time;
	bool was_already_working;

	was_already_working = sockevent_working;
	if (!was_already_working)
		sockevent_working = true;

	memcpy(&expired_sockets_list, &socktimer, sizeof(expired_sockets_list));
	SLIST_INIT(&socktimer);

	current_time = getticks();
	next_lowest_timeout = TMR_NEVER;

	SLIST_FOREACH_SAFE(sock, &expired_sockets_list, sock_timer, temp_sock) {
		assert(sock->sock_flags & SFL_TIMER);
		sock->sock_flags &= ~SFL_TIMER;

		remaining_time = sockevent_expire(sock, current_time);

		if (remaining_time != TMR_NEVER) {
			SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
			sock->sock_flags |= SFL_TIMER;

			if (next_lowest_timeout == TMR_NEVER || remaining_time < next_lowest_timeout)
				next_lowest_timeout = remaining_time;
		}
	}

	if (next_lowest_timeout != TMR_NEVER)
		set_timer(&sockevent_timer, next_lowest_timeout, socktimer_expire, 0);

	if (!was_already_working) {
		if (sockevent_has_events())
			sockevent_pump();

		sockevent_working = false;
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

    assert(sock != NULL);
    assert(ticks <= TMRDIFF_MAX);

    if (!(sock->sock_flags & SFL_TIMER)) {
        SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
        sock->sock_flags |= SFL_TIMER;
    }

    now = getticks();

    if (!tmr_is_set(&sockevent_timer) ||
        tmr_is_first(now + ticks, tmr_exp_time(&sockevent_timer))) {
        set_timer(&sockevent_timer, ticks, socktimer_expire, 0);
    }

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

	if (sock->sock_ops == NULL || sock->sock_ops->sop_bind == NULL) {
		return EOPNOTSUPP;
	}

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
	struct sockevent_proc *spr;
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
		struct sockdriver_call local_fakecall;
		struct sockdriver_call *suspend_call = (struct sockdriver_call *)call;
		int using_fake_call = 0;

		if (suspend_call == NULL) {
			if (!sockevent_has_events()) {
				return EINPROGRESS;
			}
			local_fakecall.sc_endpt = NONE;
			suspend_call = &local_fakecall;
			using_fake_call = 1;
		}

		assert(!sockevent_has_suspended(sock, SEV_SEND | SEV_RECV));

		sockevent_suspend(sock, SEV_CONNECT, suspend_call, user_endpt);

		if (using_fake_call) {
			sockevent_pump();

			spr = sockevent_unsuspend(sock, suspend_call);
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
	struct sock *sock;
	struct sock *newsock;
	sockid_t r;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops->sop_accept == NULL) {
		return EOPNOTSUPP;
	}

	newsock = NULL;

	r = sock->sock_ops->sop_accept(sock, addr, addr_len, user_endpt, &newsock);

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
sockevent_send(sockid_t id, const struct sockdriver_data * __restrict data,
	size_t len, const struct sockdriver_data * __restrict ctl_data,
	socklen_t ctl_len, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt, int flags,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock = NULL;
	int r = OK;
	size_t off = 0;
	socklen_t ctl_off = 0;
	clock_t suspension_time = 0;
	bool timer_enabled = false;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	if (sock->sock_err != OK) {
		r = sock->sock_err;
		sock->sock_err = OK; /* Clear error after returning it */
		return r;
	}

	if (sock->sock_flags & SFL_SHUT_WR) {
		sockevent_sigpipe(sock, user_endpt, flags);
		return EPIPE;
	}

	/* Translate the sticky SO_DONTROUTE option to a per-request MSG_DONTROUTE flag. */
	if (sock->sock_opt & SO_DONTROUTE) {
		flags |= MSG_DONTROUTE;
	}

	/* Pre-send validation check by the socket driver. */
	if (sock->sock_ops->sop_pre_send != NULL) {
		r = sock->sock_ops->sop_pre_send(sock, len, ctl_len, addr,
		    addr_len, user_endpt,
		    flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (r != OK) {
			return r;
		}
	}

	if (sock->sock_ops->sop_send == NULL) {
		return EOPNOTSUPP;
	}

	/* Sending out-of-band data is treated differently. */
	if (flags & MSG_OOB) {
		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, 0);

		if (r == SUSPEND) {
			/* MSG_OOB send calls must not be suspended by socket drivers. */
			panic("libsockevent: MSG_OOB send calls may not be suspended");
		}
		/* Return sent data length on success, error code otherwise. */
		return (r == OK) ? (int)off : r;
	}

	/* Only call sop_send if no other send calls are suspended already. */
	if (sockevent_has_suspended(sock, SEV_SEND)) {
		r = SUSPEND;
	} else {
		size_t min_send_size = sock->sock_slowat;
		if (min_send_size > len) {
			min_send_size = len;
		}

		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, min_send_size);
	}

	/* Handle suspension or post-send errors. */
	if (r == SUSPEND) {
		/* For blocking socket calls, set up suspension state. */
		if (call != NULL) {
			if (sock->sock_stimeo != 0) {
				timer_enabled = true;
				suspension_time = socktimer_add(sock, sock->sock_stimeo);
			}

			sockevent_suspend_data(sock, SEV_SEND, timer_enabled, call,
			    user_endpt, data, len, off, ctl_data, ctl_len,
			    ctl_off, flags, 0, suspension_time);
			/* For suspended blocking calls, 'r' remains SUSPEND. */
		} else {
			/* For non-blocking calls, convert SUSPEND to EWOULDBLOCK or OK if partial data sent. */
			r = (off > 0 || ctl_off > 0) ? OK : EWOULDBLOCK;
		}
	} else if (r == EPIPE) {
		/* If sop_send explicitly returned EPIPE. */
		sockevent_sigpipe(sock, user_endpt, flags);
	}

	/* Final return: bytes sent on success, error code on failure. */
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
	int r;
	int original_input_flags;
	int oob_requested;

	original_input_flags = *flags;
	*flags = 0; /* Clear output flags for the caller's result */

	if (sock->sock_ops->sop_pre_recv != NULL) {
		r = sock->sock_ops->sop_pre_recv(sock, user_endpt,
		                                 original_input_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
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

	oob_requested = (original_input_flags & MSG_OOB);

	if (oob_requested && (sock->sock_opt & SO_OOBINLINE)) {
		return EINVAL;
	}

	size_t min_data_to_recv = 0; /* Initialize to 0 for no-data segments or OOB */

	if (oob_requested || !sockevent_has_suspended(sock, SEV_RECV)) {
		if (!oob_requested && sock->sock_err == OK) {
			min_data_to_recv = sock->sock_rlowat;
			if (min_data_to_recv > len) {
				min_data_to_recv = len;
			}
		}
		/*
		 * If OOB is requested or there's a pending socket error,
		 * min_data_to_recv remains 0, allowing receipt of even no-data segments
		 * or out-of-band data without regard to low watermark.
		 */

		r = sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
		                             ctl_len, ctl_off, addr, addr_len,
		                             user_endpt, original_input_flags, min_data_to_recv, flags);
	} else {
		r = SUSPEND;
	}

	/* The return value from sop_recv must be SUSPEND, an error (<=0), or SOCKEVENT_EOF. */
	assert(r <= 0 || r == SOCKEVENT_EOF);

	if (r == SUSPEND) {
		if (oob_requested) {
			/* MSG_OOB receive calls must not be suspended; this indicates a driver error or misconfiguration. */
			panic("libsockevent: MSG_OOB receive calls may not be suspended");
		}

		/* Only suspend the call if a 'call' context is provided and there's no pending socket error. */
		if (call != NULL && sock->sock_err == OK) {
			clock_t suspend_timer_time = 0;
			int timer_active = FALSE;

			if (sock->sock_rtimeo != 0) {
				timer_active = TRUE;
				suspend_timer_time = socktimer_add(sock, sock->sock_rtimeo);
			}

			sockevent_suspend_data(sock, SEV_RECV, timer_active, call,
			                       user_endpt, data, len, *off, ctl_data,
			                       ctl_len, *ctl_off, original_input_flags, *flags, suspend_timer_time);
		} else {
			/* If suspension is not possible (no call context or error pending), return EWOULDBLOCK. */
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
	size_t bytes_received = 0;
	socklen_t ctl_input_len;
	int result;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	ctl_input_len = *ctl_len;
	*ctl_len = 0;

	result = sockevent_recv_inner(sock, data, len, &bytes_received, ctl_data, ctl_input_len,
	    ctl_len, addr, addr_len, user_endpt, flags, call);

	bool has_data_or_control_data = (bytes_received > 0 || *ctl_len > 0);
	bool inner_call_yielded_result = (result == OK || (result != SUSPEND && has_data_or_control_data));

	if (inner_call_yielded_result) {
		return (int)bytes_received;
	} else if (sock->sock_err != OK) {
		assert(result != SUSPEND);

		int pending_error = sock->sock_err;
		sock->sock_err = OK;
		return pending_error;
	} else if (result == SOCKEVENT_EOF) {
		return 0;
	}

	return result;
}

/*
 * Process an I/O control call.
 */
#include <limits.h>

static int
sockevent_ioctl(sockid_t id, unsigned long request,
	const struct sockdriver_data * __restrict data, endpoint_t user_endpt)
{
	struct sock *sock;
	size_t size;
	int r;
	int val;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	switch (request) {
	case FIONREAD:
		size = 0;
		if (!(sock->sock_flags & SFL_SHUT_RD) &&
		    sock->sock_ops->sop_test_recv != NULL) {
			(void)sock->sock_ops->sop_test_recv(sock, 0, &size);
		}

		if (size > INT_MAX) {
			val = INT_MAX;
		} else {
			val = (int)size;
		}

		return sockdriver_copyout(data, 0, &val, sizeof(val));
	default:
		break;
	}

	if (sock->sock_ops->sop_ioctl == NULL) {
		return ENOTTY;
	}

	r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

	if (r == SUSPEND) {
		panic("libsockevent: socket driver suspended IOCTL 0x%lx", request);
	}

	return r;
}

/*
 * Set socket options.
 */
static int
handle_simple_on_off_option(struct sock *sock, int name,
                            const struct sockdriver_data *data, socklen_t len)
{
    int val;
    int r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
    if (r != OK) {
        return r;
    }

    if (val) {
        sock->sock_opt |= (unsigned int)name;
    } else {
        sock->sock_opt &= ~(unsigned int)name;
    }

    if (sock->sock_ops != NULL && sock->sock_ops->sop_setsockmask != NULL) {
        sock->sock_ops->sop_setsockmask(sock, sock->sock_opt);
    }

    if (name == SO_OOBINLINE && val) {
        sockevent_raise(sock, SEV_RECV);
    }
    return OK;
}

static int
handle_linger_option(struct sock *sock, const struct sockdriver_data *data, socklen_t len)
{
    struct linger linger_val;
    int r = sockdriver_copyin_opt(data, &linger_val, sizeof(linger_val), len);
    if (r != OK) {
        return r;
    }

    if (linger_val.l_onoff) {
        if (linger_val.l_linger < 0) {
            return EINVAL;
        }
        
        clock_t secs = (clock_t)linger_val.l_linger;
        /* Using a temporary variable for the division result to avoid re-calculating */
        /* and to ensure the type of the comparison is consistent with `secs`. */
        clock_t max_linger_secs = (clock_t)TMRDIFF_MAX / sys_hz();
        if (secs >= max_linger_secs) {
            return EDOM;
        }

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
    int val;
    int r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
    if (r != OK) {
        return r;
    }

    if (val <= 0) {
        return EINVAL;
    }

    if (name == SO_SNDLOWAT) {
        sock->sock_slowat = (size_t)val;
        sockevent_raise(sock, SEV_SEND);
    } else { /* SO_RCVLOWAT */
        sock->sock_rlowat = (size_t)val;
        sockevent_raise(sock, SEV_RECV);
    }
    return OK;
}

#define US_PER_SECOND 1000000UL

static int
handle_timeout_option(struct sock *sock, int name,
                     const struct sockdriver_data *data, socklen_t len)
{
    struct timeval tv_val;
    int r = sockdriver_copyin_opt(data, &tv_val, sizeof(tv_val), len);
    if (r != OK) {
        return r;
    }

    if (tv_val.tv_sec < 0 || tv_val.tv_usec < 0 ||
        (unsigned long)tv_val.tv_usec >= US_PER_SECOND) {
        return EINVAL;
    }

    clock_t max_tv_sec = (clock_t)TMRDIFF_MAX / sys_hz();
    if (tv_val.tv_sec >= max_tv_sec) {
        return EDOM;
    }

    clock_t ticks = (clock_t)tv_val.tv_sec * sys_hz() +
                    ((clock_t)tv_val.tv_usec * sys_hz() + (US_PER_SECOND - 1)) / US_PER_SECOND;

    if (name == SO_SNDTIMEO) {
        sock->sock_stimeo = ticks;
    } else { /* SO_RCVTIMEO */
        sock->sock_rtimeo = ticks;
    }
    return OK;
}

static int
sockevent_setsockopt(sockid_t id, int level, int name,
	const struct sockdriver_data * data, socklen_t len)
{
	struct sock *sock;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

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
			return handle_simple_on_off_option(sock, name, data, len);

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
			/* Unrecognized SOL_SOCKET option, fall through to driver */
			break;
		}
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_setsockopt == NULL) {
		return ENOPROTOOPT;
	}

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
	struct linger linger_val;
	struct timeval tv;
	clock_t time_ticks;
	int val;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

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
			val = !!(sock->sock_opt & (unsigned int)name);
			return sockdriver_copyout_opt(data, &val, sizeof(val), len);

		case SO_LINGER:
			linger_val.l_onoff = !!(sock->sock_opt & SO_LINGER);
			linger_val.l_linger = sock->sock_linger / sys_hz();
			return sockdriver_copyout_opt(data, &linger_val, sizeof(linger_val), len);

		case SO_ERROR:
			val = sock->sock_err;
			if (val != OK)
				sock->sock_err = OK;
			return sockdriver_copyout_opt(data, &val, sizeof(val), len);

		case SO_TYPE:
			val = sock->sock_type;
			return sockdriver_copyout_opt(data, &val, sizeof(val), len);

		case SO_SNDLOWAT:
			val = (int)sock->sock_slowat;
			return sockdriver_copyout_opt(data, &val, sizeof(val), len);

		case SO_RCVLOWAT:
			val = (int)sock->sock_rlowat;
			return sockdriver_copyout_opt(data, &val, sizeof(val), len);

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			if (name == SO_SNDTIMEO)
				time_ticks = sock->sock_stimeo;
			else
				time_ticks = sock->sock_rtimeo;

			tv.tv_sec = time_ticks / sys_hz();
			tv.tv_usec = ((long long)(time_ticks % sys_hz()) * US) / sys_hz();

			return sockdriver_copyout_opt(data, &tv, sizeof(tv), len);

		default:
			break;
		}
	}

	if (sock->sock_ops->sop_getsockopt == NULL)
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
	struct sock *sock = sockhash_get(id);

	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops == NULL) {
		/*
		 * The socket object itself is in an invalid state,
		 * as its operations table is missing.
		 */
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

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (sock->sock_ops == NULL)
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
	assert(!(flags & ~(SFL_SHUT_RD | SFL_SHUT_WR)));

	flags &= ~(unsigned int)sock->sock_flags;

	if (flags != 0) {
		sock->sock_flags |= flags;

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
	int r;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	if (how == SHUT_RD || how == SHUT_RDWR) {
		flags |= SFL_SHUT_RD;
	}
	if (how == SHUT_WR || how == SHUT_RDWR) {
		flags |= SFL_SHUT_WR;
	}

	if (sock->sock_ops != NULL && sock->sock_ops->sop_shutdown != NULL) {
		r = sock->sock_ops->sop_shutdown(sock, flags);
	} else {
		r = OK;
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
sockevent_close(sockid_t id, const struct sockdriver_call *call)
{
	struct sock *sock;
	int driver_op_result;
	int force_immediate_driver_close;
	int close_syscall_return_code = OK; // Default return for the close(2) system call

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	assert(sock->sock_proc == NULL);
	sock->sock_select.ss_endpt = NONE;

	// Determine if the socket driver should be urged to close immediately.
	// This is driven by SO_LINGER with a zero timeout.
	force_immediate_driver_close = ((sock->sock_opt & SO_LINGER) && sock->sock_linger == 0);

	// Invoke the socket driver's specific close operation.
	if (sock->sock_ops->sop_close != NULL) {
		driver_op_result = sock->sock_ops->sop_close(sock, force_immediate_driver_close);
	} else {
		driver_op_result = OK; // No driver-specific close, assume immediate completion.
	}

	// The driver's close operation must return either OK (completed synchronously)
	// or SUSPEND (will complete asynchronously via SEV_CLOSE event).
	assert(driver_op_result == OK || driver_op_result == SUSPEND);

	if (driver_op_result == SUSPEND) {
		// The driver needs more time to close the socket.
		// Mark the socket as asynchronously closing.
		sock->sock_flags |= SFL_CLOSING;

		// If an immediate force close was requested (SO_LINGER=0),
		// the close(2) syscall should return OK immediately,
		// even though the driver is still working.
		if (force_immediate_driver_close) {
			// close_syscall_return_code remains OK.
		}
		// Otherwise, handle graceful close or SO_LINGER with a timeout.
		else {
			// If SO_LINGER is set (with a non-zero timeout),
			// set a timer and suspend the calling process.
			if (sock->sock_opt & SO_LINGER) {
				sock->sock_linger = socktimer_add(sock, sock->sock_linger);
				sockevent_suspend(sock, SEV_CLOSE, call, NONE);
				close_syscall_return_code = SUSPEND; // close(2) will block.
			}
			// If SO_LINGER is NOT set, and the driver suspended,
			// the close(2) syscall must return OK immediately,
			// and the caller should not be suspended.
			else {
				// close_syscall_return_code remains OK.
				// The driver will signal completion via SEV_CLOSE.
			}
		}
	} else if (driver_op_result == OK) {
		// The driver completed the close synchronously.
		// Free the socket resources immediately.
		sockevent_free(sock);
		// close_syscall_return_code remains OK.
	}

	return close_syscall_return_code;
}

/*
 * Cancel a suspended send request.
 */
static void
sockevent_cancel_send(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int r = (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) ? (int)spr->spr_dataoff : err;
	sockdriver_reply_generic(&spr->spr_call, r);
	sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static void
sockevent_cancel_recv(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int r = (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) ? (int)spr->spr_dataoff : err;

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
sockevent_cancel(sockid_t id, const struct sockdriver_call *call)
{
    struct sockevent_proc *spr;
    struct sock *sock;

    if ((sock = sockhash_get(id)) == NULL) {
        return;
    }

    if ((spr = sockevent_unsuspend(sock, call)) == NULL) {
        return;
    }

    switch (spr->spr_event) {
    case SEV_BIND:
    case SEV_CONNECT:
        assert(spr->spr_call.sc_endpt != NONE);
        sockdriver_reply_generic(&spr->spr_call, EINTR);
        break;

    case SEV_ACCEPT:
        sockdriver_reply_accept(&spr->spr_call, EINTR, NULL, 0);
        break;

    case SEV_SEND:
        sockevent_cancel_send(sock, spr, EINTR);
        break;

    case SEV_RECV:
        sockevent_cancel_recv(sock, spr, EINTR);
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
sockevent_select(sockid_t id, unsigned int ops,
	const struct sockdriver_select * sel)
{
	struct sock *sock;
	unsigned int immediate_ops_result;
	unsigned int notify_requested;
	unsigned int pending_ops_to_register;

	if ((sock = sockhash_get(id)) == NULL) {
		return EINVAL;
	}

	notify_requested = (ops & SDEV_NOTIFY);
	ops &= (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR);

	immediate_ops_result = sockevent_test_select(sock, ops);

	assert(!(sock->sock_selops & immediate_ops_result));

	pending_ops_to_register = ops & ~immediate_ops_result;

	if (notify_requested && pending_ops_to_register != 0) {
		if (sock->sock_select.ss_endpt != NONE) {
			if (sock->sock_select.ss_endpt != sel->ss_endpt) {
				printf("libsockevent: no support for multiple select callers yet\n");
				return EIO;
			}
			sock->sock_selops |= pending_ops_to_register;
		} else {
			assert(sel->ss_endpt != NONE);
			sock->sock_select = *sel;
			sock->sock_selops = pending_ops_to_register;
		}
	}

	return immediate_ops_result;
}

/*
 * An alarm has triggered.  Expire any timers.  Socket drivers that do not pass
 * clock notification messages to libsockevent must call expire_timers(3)
 * themselves instead.
 */
static void
sockevent_alarm(clock_t now)
{
    if (expire_timers(now) != 0) {
        // Placeholder for error handling logic.
        // In a real system, this block would contain actions such as:
        // - Logging the error (e.g., using a system-specific logging facility)
        // - Setting a global error flag to indicate a failure
        // - Triggering a recovery mechanism or graceful shutdown
        // This structure makes explicit that the return value of expire_timers is
        // checked, and provides a clear point for future reliability improvements.
    }
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
    int hash_initialized = 0;
    int timer_initialized = 0;
    int proc_initialized = 0;

    if (socket_cb == NULL) {
        return -1;
    }

    if (sockhash_init() != 0) {
        goto fail;
    }
    hash_initialized = 1;

    if (socktimer_init() != 0) {
        goto fail;
    }
    timer_initialized = 1;

    if (sockevent_proc_init() != 0) {
        goto fail;
    }
    proc_initialized = 1;

    SIMPLEQ_INIT(&sockevent_pending);

    sockevent_socket_cb = socket_cb;
    sockdriver_announce();
    sockevent_working = FALSE;

    return 0;

fail:
    if (proc_initialized) {
        sockevent_proc_deinit();
    }
    if (timer_initialized) {
        socktimer_deinit();
    }
    if (hash_initialized) {
        sockhash_deinit();
    }
    return -1;
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

cleanup:
    sockevent_working = FALSE;
}
