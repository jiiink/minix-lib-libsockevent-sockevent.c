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
	for (unsigned int slot = 0; slot < __arraycount(sockhash); slot++) {
		SLIST_INIT(&sockhash[slot]);
	}
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
static unsigned int sockhash_slot(sockid_t id)
{
    const unsigned int CLASS_SHIFT = 16;
    unsigned int hash = id + (id >> CLASS_SHIFT);
    return hash % SOCKHASH_SLOTS;
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *sockhash_get(sockid_t id)
{
    unsigned int slot = sockhash_slot(id);
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
static void
sockhash_add(struct sock *sock)
{
	unsigned int slot;

	if (sock == NULL) {
		return;
	}

	slot = sockhash_slot(sock->sock_id);

	if (slot < SOCKHASH_SIZE) {
		SLIST_INSERT_HEAD(&sockhash[slot], sock, sock_hash);
	}
}

/*
 * Remove a sock object from the hash table.  The sock object must be in the
 * hash table.
 */
static void
sockhash_del(struct sock *sock)
{
	unsigned int slot;
	struct sock *current;
	struct sock *prev;

	if (sock == NULL) {
		return;
	}

	slot = sockhash_slot(sock->sock_id);

	current = SLIST_FIRST(&sockhash[slot]);
	prev = NULL;

	while (current != NULL) {
		if (current == sock) {
			if (prev == NULL) {
				SLIST_REMOVE_HEAD(&sockhash[slot], sock_hash);
			} else {
				SLIST_REMOVE_AFTER(prev, sock_hash);
			}
			return;
		}
		prev = current;
		current = SLIST_NEXT(current, sock_hash);
	}
}

/*
 * Reset a socket object to a proper initial state, with a particular socket
 * identifier, a SOCK_ type, and a socket operations table.  The socket is
 * added to the ID-to-object hash table.  This function always succeeds.
 */
static void sockevent_reset(struct sock *sock, sockid_t id, int domain, int type, const struct sockevent_ops *ops)
{
    if (sock == NULL) {
        return;
    }

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
void sockevent_clone(struct sock *sock, struct sock *newsock, sockid_t newid)
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
sockevent_accepted(struct sock * sock, struct sock * newsock, sockid_t newid)
{
	if (newsock == NULL) {
		newsock = sockhash_get(newid);
		if (newsock == NULL) {
			panic("libsockdriver: socket driver returned unknown "
			    "ID %d from accept callback", newid);
		}
	} else {
		sockevent_clone(sock, newsock, newid);
	}

	if ((newsock->sock_flags & SFL_CLONED) == 0) {
		panic("libsockdriver: accepted socket not marked as cloned");
	}
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

	if (domain < 0 || domain > UINT8_MAX)
		return EAFNOSUPPORT;

	if (sockevent_socket_cb == NULL)
		panic("libsockevent: not initialized");

	sock = NULL;
	ops = NULL;

	r = sockevent_socket_cb(domain, type, protocol, user_endpt, &sock, &ops);
	if (r < 0)
		return r;

	assert(sock != NULL);
	assert(ops != NULL);

	sockevent_reset(sock, r, domain, type, ops);

	*sockp = sock;
	return OK;
}

/*
 * Free a previously allocated sock object.
 */
static void sockevent_free(struct sock *sock)
{
    const struct sockevent_ops *ops;

    if (sock == NULL) {
        return;
    }

    if (sock->sock_proc != NULL) {
        return;
    }

    socktimer_del(sock);
    sockhash_del(sock);

    ops = sock->sock_ops;
    if (ops == NULL || ops->sop_free == NULL) {
        return;
    }

    sock->sock_ops = NULL;
    ops->sop_free(sock);
}

/*
 * Create a new socket.
 */
static sockid_t sockevent_socket(int domain, int type, int protocol, endpoint_t user_endpt)
{
    struct sock *sock;
    int r;

    r = sockevent_alloc(domain, type, protocol, user_endpt, &sock);
    if (r != OK) {
        return r;
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
	if (r != OK)
		return r;

	if (sock1->sock_ops->sop_pair == NULL) {
		sockevent_free(sock1);
		return EOPNOTSUPP;
	}

	r = sockevent_alloc(domain, type, protocol, user_endpt, &sock2);
	if (r != OK) {
		sockevent_free(sock1);
		return r;
	}

	assert(sock1->sock_ops == sock2->sock_ops);

	r = sock1->sock_ops->sop_pair(sock1, sock2, user_endpt);
	if (r != OK) {
		sockevent_free(sock2);
		sockevent_free(sock1);
		return r;
	}

	id[0] = sock1->sock_id;
	id[1] = sock2->sock_id;
	return OK;
}

/*
 * A send request returned EPIPE.  If desired, send a SIGPIPE signal to the
 * user process that issued the request.
 */
static void
sockevent_sigpipe(struct sock *sock, endpoint_t user_endpt, int flags)
{
    if (sock == NULL) {
        return;
    }

    if (sock->sock_type != SOCK_STREAM) {
        return;
    }

    if ((flags & MSG_NOSIGNAL) || (sock->sock_opt & SO_NOSIGPIPE)) {
        return;
    }

    sys_kill(user_endpt, SIGPIPE);
}

/*
 * Suspend a request without data, that is, a bind, connect, accept, or close
 * request.
 */
static void
sockevent_suspend(struct sock *sock, unsigned int event,
	const struct sockdriver_call *call, endpoint_t user_endpt)
{
	struct sockevent_proc *spr;
	struct sockevent_proc **tail;

	spr = sockevent_proc_alloc();
	if (spr == NULL) {
		panic("libsockevent: too many suspended processes");
	}

	spr->spr_next = NULL;
	spr->spr_event = event;
	spr->spr_timer = FALSE;
	spr->spr_call = *call;
	spr->spr_endpt = user_endpt;

	tail = &sock->sock_proc;
	while (*tail != NULL) {
		tail = &(*tail)->spr_next;
	}
	*tail = spr;
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
	struct sockevent_proc **tail;

	spr = sockevent_proc_alloc();
	if (spr == NULL) {
		panic("libsockevent: too many suspended processes");
	}

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
static int sockevent_has_suspended(struct sock *sock, unsigned int mask)
{
	struct sockevent_proc *spr;

	if (!sock)
		return FALSE;

	for (spr = sock->sock_proc; spr != NULL; spr = spr->spr_next) {
		if (spr->spr_event & mask)
			return TRUE;
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
	struct sockevent_proc *spr;
	struct sockevent_proc **sprp;

	if (sock == NULL || call == NULL) {
		return NULL;
	}

	sprp = &sock->sock_proc;

	while (*sprp != NULL) {
		spr = *sprp;

		if (spr->spr_call.sc_endpt == call->sc_endpt &&
		    spr->spr_call.sc_req == call->sc_req) {
			*sprp = spr->spr_next;
			return spr;
		}

		sprp = &spr->spr_next;
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
static int sockevent_resume(struct sock *sock, struct sockevent_proc *spr) {
    switch (spr->spr_event) {
    case SEV_CONNECT:
        if (spr->spr_call.sc_endpt == NONE) {
            return TRUE;
        }
        /* FALLTHROUGH */
    case SEV_BIND:
        return sockevent_resume_bind_connect(sock, spr);
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
        panic("libsockevent: process suspended on unknown event 0x%x", spr->spr_event);
    }
}

static int sockevent_resume_bind_connect(struct sock *sock, struct sockevent_proc *spr) {
    sockid_t r = sock->sock_err;
    if (r != OK) {
        sock->sock_err = OK;
    }
    sockdriver_reply_generic(&spr->spr_call, r);
    return TRUE;
}

static int sockevent_resume_accept(struct sock *sock, struct sockevent_proc *spr) {
    char addr[SOCKADDR_MAX];
    socklen_t addr_len = 0;
    struct sock *newsock = NULL;
    sockid_t r;

    assert(sock->sock_opt & SO_ACCEPTCONN);

    r = sock->sock_ops->sop_accept(sock, (struct sockaddr *)&addr, &addr_len,
                                   spr->spr_endpt, &newsock);
    if (r == SUSPEND) {
        return FALSE;
    }

    if (r >= 0) {
        assert(addr_len <= sizeof(addr));
        sockevent_accepted(sock, newsock, r);
    }

    sockdriver_reply_accept(&spr->spr_call, r, (struct sockaddr *)&addr, addr_len);
    return TRUE;
}

static int sockevent_resume_send(struct sock *sock, struct sockevent_proc *spr) {
    struct sockdriver_data data, ctl;
    sockid_t r;

    if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
        r = sockevent_get_send_error(sock, spr);
    } else {
        r = sockevent_do_send(sock, spr, &data, &ctl);
        if (r == SUSPEND) {
            return FALSE;
        }
        if ((spr->spr_dataoff > 0 || spr->spr_ctloff > 0) && r < 0) {
            r = spr->spr_dataoff;
        }
    }

    if (r == EPIPE) {
        sockevent_sigpipe(sock, spr->spr_endpt, spr->spr_flags);
    }

    sockdriver_reply_generic(&spr->spr_call, r);
    return TRUE;
}

static sockid_t sockevent_get_send_error(struct sock *sock, struct sockevent_proc *spr) {
    if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
        return (int)spr->spr_dataoff;
    }
    if (sock->sock_err != OK) {
        sockid_t err = sock->sock_err;
        sock->sock_err = OK;
        return err;
    }
    return EPIPE;
}

static sockid_t sockevent_do_send(struct sock *sock, struct sockevent_proc *spr,
                                  struct sockdriver_data *data, struct sockdriver_data *ctl) {
    sockdriver_unpack_data(data, &spr->spr_call, &spr->spr_data, spr->spr_datalen);
    sockdriver_unpack_data(ctl, &spr->spr_call, &spr->spr_ctl, spr->spr_ctllen);

    size_t len = spr->spr_datalen - spr->spr_dataoff;
    size_t min = (sock->sock_slowat > len) ? len : sock->sock_slowat;

    sockid_t r = sock->sock_ops->sop_send(sock, data, len, &spr->spr_dataoff,
                                          ctl, spr->spr_ctllen - spr->spr_ctloff,
                                          &spr->spr_ctloff, NULL, 0, spr->spr_endpt,
                                          spr->spr_flags, min);
    assert(r <= 0);
    return r;
}

static int sockevent_resume_recv(struct sock *sock, struct sockevent_proc *spr) {
    char addr[SOCKADDR_MAX];
    socklen_t addr_len = 0;
    sockid_t r;

    if (sock->sock_flags & SFL_SHUT_RD) {
        r = SOCKEVENT_EOF;
    } else {
        r = sockevent_do_recv(sock, spr, addr, &addr_len);
        if (r == SUSPEND) {
            if (sock->sock_err == OK) {
                return FALSE;
            }
            r = SOCKEVENT_EOF;
        }
        assert(addr_len <= sizeof(addr));
    }

    r = sockevent_calc_recv_result(sock, spr, r);
    sockdriver_reply_recv(&spr->spr_call, r, spr->spr_ctloff,
                         (struct sockaddr *)&addr, addr_len, spr->spr_rflags);
    return TRUE;
}

static sockid_t sockevent_do_recv(struct sock *sock, struct sockevent_proc *spr,
                                  char *addr, socklen_t *addr_len) {
    struct sockdriver_data data, ctl;
    size_t len = spr->spr_datalen - spr->spr_dataoff;
    size_t min = (sock->sock_err == OK) ? 
                 ((sock->sock_rlowat > len) ? len : sock->sock_rlowat) : 0;

    sockdriver_unpack_data(&data, &spr->spr_call, &spr->spr_data, spr->spr_datalen);
    sockdriver_unpack_data(&ctl, &spr->spr_call, &spr->spr_ctl, spr->spr_ctllen);

    return sock->sock_ops->sop_recv(sock, &data, len, &spr->spr_dataoff,
                                    &ctl, spr->spr_ctllen - spr->spr_ctloff,
                                    &spr->spr_ctloff, (struct sockaddr *)addr,
                                    addr_len, spr->spr_endpt, spr->spr_flags,
                                    min, &spr->spr_rflags);
}

static sockid_t sockevent_calc_recv_result(struct sock *sock, struct sockevent_proc *spr,
                                           sockid_t r) {
    if (r == OK || spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
        return (int)spr->spr_dataoff;
    }
    if (sock->sock_err != OK) {
        sockid_t err = sock->sock_err;
        sock->sock_err = OK;
        return err;
    }
    if (r == SOCKEVENT_EOF) {
        return 0;
    }
    return r;
}

/*
 * Return TRUE if the given socket is ready for reading for a select call, or
 * FALSE otherwise.
 */
static int
sockevent_test_readable(struct sock * sock)
{
	int r;

	if ((sock->sock_flags & SFL_SHUT_RD) || (sock->sock_err != OK))
		return TRUE;

	if (sock->sock_opt & SO_ACCEPTCONN) {
		if (sock->sock_ops->sop_test_accept == NULL)
			return TRUE;
		r = sock->sock_ops->sop_test_accept(sock);
	} else {
		if (sock->sock_ops->sop_test_recv == NULL)
			return TRUE;
		r = sock->sock_ops->sop_test_recv(sock, sock->sock_rlowat, NULL);
	}

	return (r != SUSPEND);
}

/*
 * Return TRUE if the given socket is ready for writing for a select call, or
 * FALSE otherwise.
 */
static int
sockevent_test_writable(struct sock *sock)
{
	int result;

	if (sock->sock_err != OK) {
		return TRUE;
	}

	if (sock->sock_flags & SFL_SHUT_WR) {
		return TRUE;
	}

	if (sock->sock_ops->sop_test_send == NULL) {
		return TRUE;
	}

	result = sock->sock_ops->sop_test_send(sock, sock->sock_slowat);

	return (result != SUSPEND);
}

/*
 * Test whether any of the given select operations are ready on the given
 * socket.  Return the subset of ready operations; zero if none.
 */
static unsigned int
sockevent_test_select(struct sock * sock, unsigned int ops)
{
	unsigned int ready_ops;
	unsigned int valid_ops = SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR;

	assert(!(ops & ~valid_ops));

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
	unsigned int r, ops;

	if (mask & SEV_CONNECT)
		mask |= SEV_SEND;

	sprp = &sock->sock_proc;
	while (*sprp != NULL) {
		spr = *sprp;
		unsigned int flag = spr->spr_event;

		if ((mask & flag) && sockevent_resume(sock, spr)) {
			*sprp = spr->spr_next;
			sockevent_proc_free(spr);
			continue;
		}
		
		mask &= ~flag;
		sprp = &spr->spr_next;
	}

	if ((mask & (SEV_ACCEPT | SEV_SEND | SEV_RECV)) == 0)
		goto check_close;
		
	if (sock->sock_select.ss_endpt == NONE)
		goto check_close;
		
	if (sock->sock_selops == 0)
		goto check_close;

	ops = sock->sock_selops;
	if ((mask & (SEV_ACCEPT | SEV_RECV)) == 0)
		ops &= ~SDEV_OP_RD;
	if ((mask & SEV_SEND) == 0)
		ops &= ~SDEV_OP_WR;

	if (ops == 0)
		goto check_close;

	r = sockevent_test_select(sock, ops);
	if (r == 0)
		goto check_close;

	sockdriver_reply_select(&sock->sock_select, sock->sock_id, r);
	sock->sock_selops &= ~r;

	if (sock->sock_selops == 0)
		sock->sock_select.ss_endpt = NONE;

check_close:
	if ((mask & SEV_CLOSE) == 0)
		return;
		
	if ((sock->sock_flags & (SFL_CLONED | SFL_CLOSING)) == 0)
		return;
		
	sockevent_free(sock);
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
	unsigned int mask;

	if (!sockevent_working) {
		return;
	}

	while (!SIMPLEQ_EMPTY(&sockevent_pending)) {
		sock = SIMPLEQ_FIRST(&sockevent_pending);
		if (sock == NULL) {
			break;
		}
		
		SIMPLEQ_REMOVE_HEAD(&sockevent_pending, sock_next);

		mask = sock->sock_events;
		if (mask == 0) {
			continue;
		}
		
		sock->sock_events = 0;
		sockevent_fire(sock, mask);
	}
}

/*
 * Return TRUE if any events are pending on any sockets, or FALSE otherwise.
 */
static int sockevent_has_events(void)
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

		if (sock->sock_events == 0)
			SIMPLEQ_INSERT_TAIL(&sockevent_pending, sock,
			    sock_next);

		sock->sock_events |= mask;
		return;
	}

	sockevent_working = TRUE;
	sockevent_fire(sock, mask);

	if (sockevent_has_events())
		sockevent_pump();

	sockevent_working = FALSE;
}

/*
 * Set a pending error on the socket object, and wake up any suspended
 * operations that are affected by this.
 */
void sockevent_set_error(struct sock *sock, int err)
{
    if (sock == NULL || sock->sock_ops == NULL || err >= 0) {
        return;
    }

    sock->sock_err = err;
    sockevent_raise(sock, SEV_BIND | SEV_CONNECT | SEV_SEND | SEV_RECV);
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
sockevent_expire(struct sock * sock, clock_t now)
{
	struct sockevent_proc *spr, **sprp;
	clock_t lowest, left;
	int r;

	if (sock->sock_flags & SFL_CLOSING) {
		if ((sock->sock_opt & SO_LINGER) &&
		    tmr_is_first(sock->sock_linger, now)) {
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

			if (r == SUSPEND)
				sock->sock_opt &= ~SO_LINGER;
			else
				sockevent_free(sock);
		}

		return TMR_NEVER;
	}

	lowest = TMR_NEVER;

	sprp = &sock->sock_proc;
	while (*sprp != NULL) {
		spr = *sprp;

		if (spr->spr_timer == 0) {
			sprp = &spr->spr_next;
			continue;
		}

		assert(spr->spr_event == SEV_SEND ||
		    spr->spr_event == SEV_RECV);

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

	memcpy(&oldtimer, &socktimer, sizeof(oldtimer));
	SLIST_INIT(&socktimer);

	now = getticks();
	lowest = TMR_NEVER;

	SLIST_FOREACH_SAFE(sock, &oldtimer, sock_timer, tsock) {
		assert(sock->sock_flags & SFL_TIMER);
		sock->sock_flags &= ~SFL_TIMER;

		left = sockevent_expire(sock, now);

		if (left != TMR_NEVER) {
			if (lowest == TMR_NEVER || lowest > left)
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
socktimer_add(struct sock * sock, clock_t ticks)
{
	clock_t now;
	clock_t new_expiry;

	if (ticks > TMRDIFF_MAX) {
		return 0;
	}

	if (!(sock->sock_flags & SFL_TIMER)) {
		SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
		sock->sock_flags |= SFL_TIMER;
	}

	now = getticks();
	new_expiry = now + ticks;

	if (!tmr_is_set(&sockevent_timer) ||
	    tmr_is_first(new_expiry, tmr_exp_time(&sockevent_timer))) {
		set_timer(&sockevent_timer, ticks, socktimer_expire, 0);
	}

	return new_expiry;
}

/*
 * Remove a socket object from the set of socket objects with timers.  Since
 * the timer list is maintained lazily, this needs to be done only right before
 * the socket object is freed.
 */
static void socktimer_del(struct sock *sock)
{
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
sockevent_bind(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * __restrict call)
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

	if (r == SUSPEND) {
		if (call == NULL)
			return EINPROGRESS;

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
	struct sockdriver_call fakecall;
	struct sockevent_proc *spr;
	struct sock *sock;
	int r;

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

	if (call == NULL && !sockevent_has_events())
		return EINPROGRESS;

	if (call == NULL) {
		fakecall.sc_endpt = NONE;
		call = &fakecall;
	}

	if (sockevent_has_suspended(sock, SEV_SEND | SEV_RECV))
		return EINVAL;

	sockevent_suspend(sock, SEV_CONNECT, call, user_endpt);

	if (call != &fakecall)
		return SUSPEND;

	sockevent_pump();

	spr = sockevent_unsuspend(sock, call);
	if (spr != NULL) {
		sockevent_proc_free(spr);
		return EINPROGRESS;
	}

	r = sock->sock_err;
	if (r != OK) {
		sock->sock_err = OK;
		return r;
	}

	sockevent_raise(sock, SEV_SEND);
	return OK;
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
	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_listen == NULL)
		return EOPNOTSUPP;

	if (backlog < 0)
		backlog = 0;
	
	if (backlog < SOMAXCONN) {
		unsigned int adjustment = ((unsigned int)backlog >> 1);
		backlog = backlog + 1 + adjustment;
	}
	
	if (backlog > SOMAXCONN)
		backlog = SOMAXCONN;

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
	sockid_t result;

	sock = sockhash_get(id);
	if (sock == NULL) {
		return EINVAL;
	}

	if (sock->sock_ops == NULL || sock->sock_ops->sop_accept == NULL) {
		return EOPNOTSUPP;
	}

	newsock = NULL;
	result = sock->sock_ops->sop_accept(sock, addr, addr_len, user_endpt, &newsock);

	if (result == SUSPEND) {
		if ((sock->sock_opt & SO_ACCEPTCONN) == 0) {
			return EINVAL;
		}

		if (call == NULL) {
			return EWOULDBLOCK;
		}

		sockevent_suspend(sock, SEV_ACCEPT, call, user_endpt);
		return SUSPEND;
	}

	if (result >= 0) {
		sockevent_accepted(sock, newsock, result);
	}

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
	clock_t time;
	size_t min, off;
	socklen_t ctl_off;
	int r, timer;

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

	off = 0;
	ctl_off = 0;

	if ((flags & MSG_OOB) != 0) {
		r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
		    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, 0);

		if (r == SUSPEND)
			panic("libsockevent: MSG_OOB send calls may not be "
			    "suspended");

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
				time = socktimer_add(sock, sock->sock_stimeo);
			} else {
				timer = FALSE;
				time = 0;
			}

			sockevent_suspend_data(sock, SEV_SEND, timer, call,
			    user_endpt, data, len, off, ctl_data, ctl_len,
			    ctl_off, flags, 0, time);
		} else {
			r = ((off > 0) || (ctl_off > 0)) ? OK : EWOULDBLOCK;
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

	if (sock->sock_ops->sop_pre_recv != NULL) {
		r = sock->sock_ops->sop_pre_recv(sock, user_endpt,
		    inflags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (r != OK)
			return r;
	}

	if (sock->sock_flags & SFL_SHUT_RD)
		return SOCKEVENT_EOF;

	if (sock->sock_ops->sop_recv == NULL)
		return EOPNOTSUPP;

	oob = (inflags & MSG_OOB);

	if (oob && (sock->sock_opt & SO_OOBINLINE))
		return EINVAL;

	if (!oob && sockevent_has_suspended(sock, SEV_RECV)) {
		r = SUSPEND;
	} else {
		if (!oob && sock->sock_err == OK) {
			min = (sock->sock_rlowat < len) ? sock->sock_rlowat : len;
		} else {
			min = 0;
		}

		r = sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
		    ctl_len, ctl_off, addr, addr_len, user_endpt, inflags, min,
		    flags);
	}

	if (r > 0 && r != SOCKEVENT_EOF) {
		panic("libsockevent: invalid sop_recv return value");
	}

	if (r != SUSPEND)
		return r;

	if (oob) {
		panic("libsockevent: MSG_OOB receive calls may not be suspended");
	}

	if (call == NULL || sock->sock_err != OK)
		return EWOULDBLOCK;

	timer = (sock->sock_rtimeo != 0);
	time = timer ? socktimer_add(sock, sock->sock_rtimeo) : 0;

	sockevent_suspend_data(sock, SEV_RECV, timer, call,
	    user_endpt, data, len, *off, ctl_data,
	    ctl_len, *ctl_off, inflags, *flags, time);

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

	if (r == OK)
		return (int)off;
	
	if (r != SUSPEND && (off > 0 || *ctl_len > 0))
		return (int)off;
	
	if (sock->sock_err != OK) {
		assert(r != SUSPEND);
		r = sock->sock_err;
		sock->sock_err = OK;
		return r;
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
	size_t size;
	int val;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	if (request == FIONREAD) {
		size = 0;
		if ((sock->sock_flags & SFL_SHUT_RD) == 0 &&
		    sock->sock_ops->sop_test_recv != NULL) {
			sock->sock_ops->sop_test_recv(sock, 0, &size);
		}

		val = (size > INT_MAX) ? INT_MAX : (int)size;
		return sockdriver_copyout(data, 0, &val, sizeof(val));
	}

	if (sock->sock_ops->sop_ioctl == NULL)
		return ENOTTY;

	int r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

	if (r == SUSPEND) {
		panic("libsockevent: socket driver suspended IOCTL 0x%lx",
		    request);
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
	struct linger linger;
	struct timeval tv;
	clock_t secs, ticks;
	int r, val;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (level != SOL_SOCKET) {
		if (sock->sock_ops->sop_setsockopt == NULL)
			return ENOPROTOOPT;
		return sock->sock_ops->sop_setsockopt(sock, level, name, data, len);
	}

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

	case SO_SNDLOWAT:
	case SO_RCVLOWAT:
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

	case SO_SNDTIMEO:
	case SO_RCVTIMEO:
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

	case SO_ACCEPTCONN:
	case SO_ERROR:
	case SO_TYPE:
		return ENOPROTOOPT;

	default:
		if (sock->sock_ops->sop_setsockopt == NULL)
			return ENOPROTOOPT;
		return sock->sock_ops->sop_setsockopt(sock, level, name, data, len);
	}
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

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if (level != SOL_SOCKET) {
		if (sock->sock_ops->sop_getsockopt == NULL)
			return ENOPROTOOPT;
		return sock->sock_ops->sop_getsockopt(sock, level, name, data, len);
	}

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
		linger.l_onoff = !!(sock->sock_opt & SO_LINGER);
		linger.l_linger = sock->sock_linger / sys_hz();
		return sockdriver_copyout_opt(data, &linger, sizeof(linger), len);

	case SO_ERROR:
		val = -sock->sock_err;
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
		ticks = sock->sock_stimeo;
		tv.tv_sec = ticks / sys_hz();
		tv.tv_usec = (ticks % sys_hz()) * US / sys_hz();
		return sockdriver_copyout_opt(data, &tv, sizeof(tv), len);

	case SO_RCVTIMEO:
		ticks = sock->sock_rtimeo;
		tv.tv_sec = ticks / sys_hz();
		tv.tv_usec = (ticks % sys_hz()) * US / sys_hz();
		return sockdriver_copyout_opt(data, &tv, sizeof(tv), len);

	default:
		if (sock->sock_ops->sop_getsockopt == NULL)
			return ENOPROTOOPT;
		return sock->sock_ops->sop_getsockopt(sock, level, name, data, len);
	}
}

/*
 * Retrieve a socket's local address.
 */
static int
sockevent_getsockname(sockid_t id, struct sockaddr * __restrict addr,
	socklen_t * __restrict addr_len)
{
	struct sock *sock;
	const struct sock_ops *ops;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	ops = sock->sock_ops;
	if (ops == NULL || ops->sop_getsockname == NULL)
		return EOPNOTSUPP;

	return ops->sop_getsockname(sock, addr, addr_len);
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

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	if ((sock->sock_opt & SO_ACCEPTCONN) != 0)
		return ENOTCONN;

	if (sock->sock_ops == NULL || sock->sock_ops->sop_getpeername == NULL)
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
void sockevent_set_shutdown(struct sock *sock, unsigned int flags)
{
    unsigned int mask;
    unsigned int new_flags;

    assert(sock->sock_ops != NULL);
    assert(!(flags & ~(SFL_SHUT_RD | SFL_SHUT_WR)));

    new_flags = flags & ~sock->sock_flags;

    if (new_flags == 0) {
        return;
    }

    sock->sock_flags |= new_flags;

    mask = 0;
    if (new_flags & SFL_SHUT_RD) {
        mask |= SEV_RECV;
    }
    if (new_flags & SFL_SHUT_WR) {
        mask |= SEV_SEND;
    }
    if (sock->sock_opt & SO_ACCEPTCONN) {
        mask |= SEV_ACCEPT;
    }

    assert(mask != 0);
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
	int r;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	flags = 0;
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

	if (sock->sock_ops->sop_shutdown != NULL)
		r = sock->sock_ops->sop_shutdown(sock, flags);
	else
		r = OK;

	if (r == OK)
		sockevent_set_shutdown(sock, flags);

	return r;
}

/*
 * Close a socket.
 */
static int
sockevent_close(sockid_t id, const struct sockdriver_call * call)
{
	struct sock *sock;
	int r, force;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	assert(sock->sock_proc == NULL);
	sock->sock_select.ss_endpt = NONE;

	force = ((sock->sock_opt & SO_LINGER) != 0 && sock->sock_linger == 0);

	if (sock->sock_ops->sop_close != NULL)
		r = sock->sock_ops->sop_close(sock, force);
	else
		r = OK;

	assert(r == OK || r == SUSPEND);

	if (r != SUSPEND) {
		if (r == OK)
			sockevent_free(sock);
		return r;
	}

	sock->sock_flags |= SFL_CLOSING;

	if (force)
		return OK;

	if ((sock->sock_opt & SO_LINGER) != 0) {
		sock->sock_linger = socktimer_add(sock, sock->sock_linger);
	} else {
		call = NULL;
	}

	if (call != NULL) {
		sockevent_suspend(sock, SEV_CLOSE, call, NONE);
		return SUSPEND;
	}

	return OK;
}

/*
 * Cancel a suspended send request.
 */
static void
sockevent_cancel_send(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int result;

	if (spr == NULL || sock == NULL) {
		return;
	}

	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
		result = (int)spr->spr_dataoff;
	} else {
		result = err;
	}

	sockdriver_reply_generic(&spr->spr_call, result);

	sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static void
sockevent_cancel_recv(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int result;

	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
		result = (int)spr->spr_dataoff;
	} else {
		result = err;
	}

	sockdriver_reply_recv(&spr->spr_call, result, spr->spr_ctloff, NULL, 0,
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

	sock = sockhash_get(id);
	if (sock == NULL) {
		return;
	}

	spr = sockevent_unsuspend(sock, call);
	if (spr == NULL) {
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
	unsigned int result, notify, pending_ops;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	notify = (ops & SDEV_NOTIFY);
	ops &= (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR);

	result = sockevent_test_select(sock, ops);

	assert(!(sock->sock_selops & result));

	pending_ops = ops & ~result;

	if (notify && pending_ops != 0) {
		if (sock->sock_select.ss_endpt != NONE) {
			if (sock->sock_select.ss_endpt != sel->ss_endpt) {
				printf("libsockevent: no support for multiple "
				    "select callers yet\n");
				return EIO;
			}
			sock->sock_selops |= pending_ops;
		} else {
			assert(sel->ss_endpt != NONE);
			sock->sock_select = *sel;
			sock->sock_selops = pending_ops;
		}
	}

	return result;
}

/*
 * An alarm has triggered.  Expire any timers.  Socket drivers that do not pass
 * clock notification messages to libsockevent must call expire_timers(3)
 * themselves instead.
 */
static void sockevent_alarm(clock_t now)
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
void sockevent_init(sockevent_socket_cb_t socket_cb)
{
    if (socket_cb == NULL) {
        return;
    }
    
    sockhash_init();
    socktimer_init();
    sockevent_proc_init();
    SIMPLEQ_INIT(&sockevent_pending);
    sockevent_socket_cb = socket_cb;
    sockdriver_announce();
    sockevent_working = FALSE;
}

/*
 * Process a socket driver request message.
 */
void sockevent_process(const message *m_ptr, int ipc_status)
{
    if (m_ptr == NULL) {
        return;
    }

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
