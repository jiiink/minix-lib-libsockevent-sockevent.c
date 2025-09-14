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
static void sockhash_init(void) {
    for (unsigned int slot = 0; slot < __arraycount(sockhash); ++slot) {
        SLIST_INIT(&sockhash[slot]);
    }
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
static unsigned int sockhash_slot(sockid_t id) {
    unsigned int shifted_id = id + (id >> 16);
    return shifted_id % SOCKHASH_SLOTS;
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *sockhash_get(sockid_t id)
{
	unsigned int slot = sockhash_slot(id);
	struct sock *sock = NULL;

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

    if (slot >= SOCKHASH_SIZE) {
        return;
    }

    SLIST_INSERT_HEAD(&sockhash[slot], sock, sock_hash);
}

/*
 * Remove a sock object from the hash table.  The sock object must be in the
 * hash table.
 */
static void sockhash_del(struct sock *sock) {
    unsigned int slot;

    if (sock == NULL) {
        return;
    }

    slot = sockhash_slot(sock->sock_id);

    if (slot >= SOCKHASH_SIZE) {
        return;
    }

    SLIST_REMOVE(&sockhash[slot], sock, sock, sock_hash);
}

/*
 * Reset a socket object to a proper initial state, with a particular socket
 * identifier, a SOCK_ type, and a socket operations table.  The socket is
 * added to the ID-to-object hash table.  This function always succeeds.
 */
static void sockevent_reset(struct sock *sock, sockid_t id, int domain, int type, const struct sockevent_ops *ops) {
    if (!sock) {
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
    if (!sock || !newsock) {
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
static void sockevent_accepted(struct sock *sock, struct sock *newsock, sockid_t newid) {
    if (newsock == NULL) {
        newsock = sockhash_get(newid);
        if (newsock == NULL) {
            panic("libsockdriver: socket driver returned unknown ID %d from accept callback", newid);
        }
    } else {
        sockevent_clone(sock, newsock, newid);
    }

    if (!(newsock->sock_flags & SFL_CLONED)) {
        panic("libsockdriver: expected SFL_CLONED flag to be set on accepted socket (ID %d)", newid);
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
static int sockevent_alloc(int domain, int type, int protocol, endpoint_t user_endpt, struct sock **sockp)
{
    if (sockp == NULL)
        return EINVAL;

    if (domain < 0 || domain > UINT8_MAX)
        return EAFNOSUPPORT;

    if (sockevent_socket_cb == NULL)
        return ENOSYS;

    struct sock *sock = NULL;
    const struct sockevent_ops *ops = NULL;
    sockid_t r = sockevent_socket_cb(domain, type, protocol, user_endpt, &sock, &ops);
    if (r < 0)
        return r;

    if (sock == NULL || ops == NULL)
        return EFAULT;

    sockevent_reset(sock, r, domain, type, ops);

    *sockp = sock;
    return OK;
}

/*
 * Free a previously allocated sock object.
 */
static void sockevent_free(struct sock *sock) {
    if (!sock || sock->sock_proc != NULL) {
        return;
    }

    socktimer_del(sock);
    sockhash_del(sock);

    const struct sockevent_ops *ops = sock->sock_ops;
    sock->sock_ops = NULL;

    if (!ops || !ops->sop_free) {
        return;
    }

    ops->sop_free(sock);
}


/*
 * Create a new socket.
 */
static sockid_t sockevent_socket(int domain, int type, int protocol, endpoint_t user_endpt) {
	struct sock *sock = NULL;
	int result = sockevent_alloc(domain, type, protocol, user_endpt, &sock);
	if (result != OK || sock == NULL) {
		return result;
	}
	return sock->sock_id;
}

/*
 * Create a pair of connected sockets.
 */
static int sockevent_socketpair(int domain, int type, int protocol, endpoint_t user_endpt, sockid_t id[2]) {
    struct sock *sock1 = NULL, *sock2 = NULL;
    int r;

    r = sockevent_alloc(domain, type, protocol, user_endpt, &sock1);
    if (r != OK)
        return r;

    if (!sock1 || !sock1->sock_ops || !sock1->sock_ops->sop_pair) {
        if (sock1)
            sockevent_free(sock1);
        return EOPNOTSUPP;
    }

    r = sockevent_alloc(domain, type, protocol, user_endpt, &sock2);
    if (r != OK) {
        sockevent_free(sock1);
        return r;
    }

    if (!sock2 || sock1->sock_ops != sock2->sock_ops) {
        if (sock2)
            sockevent_free(sock2);
        sockevent_free(sock1);
        return EFAULT;
    }

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
static void sockevent_sigpipe(struct sock *sock, endpoint_t user_endpt, int flags)
{
    if (!sock || sock->sock_type != SOCK_STREAM)
        return;

    if ((flags & MSG_NOSIGNAL) || (sock->sock_opt & SO_NOSIGPIPE))
        return;

    if (sys_kill(user_endpt, SIGPIPE) != 0) {
        /* Error handling can be added here if required */
    }
}

/*
 * Suspend a request without data, that is, a bind, connect, accept, or close
 * request.
 */
static void sockevent_suspend(struct sock *sock, unsigned int event,
	const struct sockdriver_call *call, endpoint_t user_endpt)
{
	struct sockevent_proc *spr;

	spr = sockevent_proc_alloc();
	if (spr == NULL)
		panic("libsockevent: too many suspended processes");

	spr->spr_next = NULL;
	spr->spr_event = event;
	spr->spr_timer = FALSE;
	spr->spr_call = *call;
	spr->spr_endpt = user_endpt;

	if (sock->sock_proc == NULL) {
		sock->sock_proc = spr;
	} else {
		struct sockevent_proc *last = sock->sock_proc;
		while (last->spr_next != NULL)
			last = last->spr_next;
		last->spr_next = spr;
	}
}

/*
 * Suspend a request with data, that is, a send or receive request.
 */
static void sockevent_suspend_data(
    struct sock *sock, unsigned int event, int timer,
    const struct sockdriver_call *call, endpoint_t user_endpt,
    const struct sockdriver_data *data, size_t len, size_t off,
    const struct sockdriver_data *ctl, socklen_t ctl_len,
    socklen_t ctl_off, int flags, int rflags, clock_t time)
{
    struct sockevent_proc *spr;
    struct sockevent_proc **sprp;

    spr = sockevent_proc_alloc();
    if (spr == NULL) {
        panic("libsockevent: too many suspended processes");
        return;
    }

    spr->spr_next = NULL;
    spr->spr_event = event;
    spr->spr_timer = timer;
    if (call) {
        spr->spr_call = *call;
    } else {
        memset(&spr->spr_call, 0, sizeof(spr->spr_call));
    }
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

    sprp = &sock->sock_proc;
    while (*sprp != NULL) {
        sprp = &(*sprp)->spr_next;
    }
    *sprp = spr;
}

/*
 * Return TRUE if there are any suspended requests on the given socket's queue
 * that match any of the events in the given event mask, or FALSE otherwise.
 */
static int sockevent_has_suspended(struct sock *sock, unsigned int mask)
{
	struct sockevent_proc *spr = sock ? sock->sock_proc : NULL;

	while (spr)
	{
		if (spr->spr_event & mask)
			return 1;
		spr = spr->spr_next;
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
sockevent_unsuspend(struct sock *sock, const struct sockdriver_call *call)
{
	struct sockevent_proc *current = sock->sock_proc;
	struct sockevent_proc *prev = NULL;

	while (current != NULL) {
		if (current->spr_call.sc_endpt == call->sc_endpt &&
		    current->spr_call.sc_req == call->sc_req) {
			if (prev == NULL) {
				sock->sock_proc = current->spr_next;
			} else {
				prev->spr_next = current->spr_next;
			}
			return current;
		}
		prev = current;
		current = current->spr_next;
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
static int sockevent_resume(struct sock *sock, struct sockevent_proc *spr)
{
    struct sock *newsock = NULL;
    struct sockdriver_data data, ctl;
    char addr[SOCKADDR_MAX];
    socklen_t addr_len = 0;
    size_t len, min;
    sockid_t r = OK;

    switch (spr->spr_event) {
    case SEV_CONNECT:
        if (spr->spr_call.sc_endpt == NONE)
            return TRUE;
        // fallthrough

    case SEV_BIND:
        r = sock->sock_err;
        if (r != OK)
            sock->sock_err = OK;
        sockdriver_reply_generic(&spr->spr_call, r);
        return TRUE;

    case SEV_ACCEPT:
        assert(sock->sock_opt & SO_ACCEPTCONN);
        addr_len = 0;
        newsock = NULL;
        r = sock->sock_ops->sop_accept(sock, (struct sockaddr *)&addr, &addr_len, spr->spr_endpt, &newsock);
        if (r == SUSPEND)
            return FALSE;
        if (r >= 0) {
            assert(addr_len <= sizeof(addr));
            sockevent_accepted(sock, newsock, r);
        }
        sockdriver_reply_accept(&spr->spr_call, r, (struct sockaddr *)&addr, addr_len);
        return TRUE;

    case SEV_SEND:
        if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
            if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
                r = (int)spr->spr_dataoff;
            } else if (sock->sock_err != OK) {
                r = sock->sock_err;
                sock->sock_err = OK;
            } else {
                r = EPIPE;
            }
        } else {
            sockdriver_unpack_data(&data, &spr->spr_call, &spr->spr_data, spr->spr_datalen);
            sockdriver_unpack_data(&ctl, &spr->spr_call, &spr->spr_ctl, spr->spr_ctllen);
            len = spr->spr_datalen > spr->spr_dataoff ? spr->spr_datalen - spr->spr_dataoff : 0;
            min = sock->sock_slowat < len ? sock->sock_slowat : len;
            r = sock->sock_ops->sop_send(sock, &data, len, &spr->spr_dataoff, &ctl, spr->spr_ctllen > spr->spr_ctloff ? spr->spr_ctllen - spr->spr_ctloff : 0, &spr->spr_ctloff, NULL, 0, spr->spr_endpt, spr->spr_flags, min);
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
        addr_len = 0;
        if (sock->sock_flags & SFL_SHUT_RD) {
            r = SOCKEVENT_EOF;
        } else {
            len = spr->spr_datalen > spr->spr_dataoff ? spr->spr_datalen - spr->spr_dataoff : 0;
            if (sock->sock_err == OK) {
                min = sock->sock_rlowat < len ? sock->sock_rlowat : len;
            } else {
                min = 0;
            }
            sockdriver_unpack_data(&data, &spr->spr_call, &spr->spr_data, spr->spr_datalen);
            sockdriver_unpack_data(&ctl, &spr->spr_call, &spr->spr_ctl, spr->spr_ctllen);
            r = sock->sock_ops->sop_recv(sock, &data, len, &spr->spr_dataoff, &ctl, spr->spr_ctllen > spr->spr_ctloff ? spr->spr_ctllen - spr->spr_ctloff : 0, &spr->spr_ctloff, (struct sockaddr *)&addr, &addr_len, spr->spr_endpt, spr->spr_flags, min, &spr->spr_rflags);
            if (r == SUSPEND && sock->sock_err == OK)
                return FALSE;
            if (r == SUSPEND && sock->sock_err != OK)
                r = SOCKEVENT_EOF;
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
        sockdriver_reply_recv(&spr->spr_call, r, spr->spr_ctloff, (struct sockaddr *)&addr, addr_len, spr->spr_rflags);
        return TRUE;

    case SEV_CLOSE:
        sockdriver_reply_generic(&spr->spr_call, OK);
        return TRUE;

    default:
        panic("libsockevent: process suspended on unknown event 0x%x", spr->spr_event);
        return FALSE;
    }
}

/*
 * Return TRUE if the given socket is ready for reading for a select call, or
 * FALSE otherwise.
 */
static int sockevent_test_readable(struct sock *sock) {
    if ((sock->sock_flags & SFL_SHUT_RD) || sock->sock_err != OK)
        return TRUE;

    if (sock->sock_opt & SO_ACCEPTCONN) {
        if (!sock->sock_ops->sop_test_accept)
            return TRUE;
        return sock->sock_ops->sop_test_accept(sock) != SUSPEND;
    } else {
        if (!sock->sock_ops->sop_test_recv)
            return TRUE;
        return sock->sock_ops->sop_test_recv(sock, sock->sock_rlowat, NULL) != SUSPEND;
    }
}

/*
 * Return TRUE if the given socket is ready for writing for a select call, or
 * FALSE otherwise.
 */
static int sockevent_test_writable(struct sock *sock) {
    if (!sock || !sock->sock_ops) return TRUE;

    if (sock->sock_err != OK ||
        (sock->sock_flags & SFL_SHUT_WR) ||
        !sock->sock_ops->sop_test_send)
        return TRUE;

    return sock->sock_ops->sop_test_send(sock, sock->sock_slowat) != SUSPEND;
}

/*
 * Test whether any of the given select operations are ready on the given
 * socket.  Return the subset of ready operations; zero if none.
 */
static unsigned int sockevent_test_select(struct sock *sock, unsigned int ops)
{
    unsigned int ready_ops = 0;

    if ((ops & ~(SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR)) != 0) {
        return 0;
    }

    if ((ops & SDEV_OP_RD) && sockevent_test_readable(sock)) {
        ready_ops |= SDEV_OP_RD;
    }

    if ((ops & SDEV_OP_WR) && sockevent_test_writable(sock)) {
        ready_ops |= SDEV_OP_WR;
    }

    return ready_ops;
}

/*
 * Fire the given mask of events on the given socket object now.
 */
static void sockevent_fire(struct sock *sock, unsigned int mask)
{
    struct sockevent_proc *spr;
    struct sockevent_proc **sprp;
    unsigned int ops, r;
    unsigned int flag;

    if (mask & SEV_CONNECT)
        mask |= SEV_SEND;

    for (sprp = &sock->sock_proc; (spr = *sprp) != NULL;) {
        flag = spr->spr_event;
        if ((mask & flag) && sockevent_resume(sock, spr)) {
            *sprp = spr->spr_next;
            sockevent_proc_free(spr);
        } else {
            mask &= ~flag;
            sprp = &spr->spr_next;
        }
    }

    if ((mask & (SEV_ACCEPT | SEV_SEND | SEV_RECV)) && sock->sock_select.ss_endpt != NONE) {
        assert(sock->sock_selops != 0);
        ops = sock->sock_selops;
        if (!(mask & (SEV_ACCEPT | SEV_RECV)))
            ops &= ~SDEV_OP_RD;
        if (!(mask & SEV_SEND))
            ops &= ~SDEV_OP_WR;
        ops &= ~SDEV_OP_ERR;
        if (ops) {
            r = sockevent_test_select(sock, ops);
            if (r) {
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
static void sockevent_pump(void)
{
    while (!SIMPLEQ_EMPTY(&sockevent_pending)) {
        struct sock *sock = SIMPLEQ_FIRST(&sockevent_pending);
        unsigned int mask;

        if (!sock) {
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
static int sockevent_has_events(void) {
    return !SIMPLEQ_EMPTY(&sockevent_pending) ? 1 : 0;
}

/*
 * Raise the given bitwise-OR'ed set of events on the given socket object.
 * Depending on the context of the call, they events may or may not be
 * processed immediately.
 */
void sockevent_raise(struct sock *sock, unsigned int mask)
{
    if (!sock || !sock->sock_ops) {
        return;
    }

    if (mask & SEV_CLOSE) {
        if (mask != SEV_CLOSE) {
            return;
        }
        sockevent_fire(sock, mask);
        return;
    }

    if (sockevent_working) {
        if (mask == 0 || mask > UCHAR_MAX) {
            return;
        }
        if (sock->sock_events == 0) {
            SIMPLEQ_INSERT_TAIL(&sockevent_pending, sock, sock_next);
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
void sockevent_set_error(struct sock *sock, int err) {
    if (err >= 0 || sock == NULL || sock->sock_ops == NULL) {
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
    if (init_timer(&sockevent_timer) != 0) {
        // Handle timer initialization failure appropriately
        // For this example, consider logging or error handling here
        // exit(EXIT_FAILURE); // Or another error handling mechanism
    }
}

/*
 * Check whether the given socket object has any suspended requests that have
 * now expired.  If so, cancel them.  Also, if the socket object has any
 * suspended requests with a timeout that has not yet expired, return the
 * earliest (relative) timeout of all of them, or TMR_NEVER if no such requests
 * are present.
 */
static clock_t sockevent_expire(struct sock *sock, clock_t now)
{
    struct sockevent_proc *spr, **sprp;
    clock_t lowest = TMR_NEVER;
    clock_t left;
    int r;

    if (sock->sock_flags & SFL_CLOSING) {
        if ((sock->sock_opt & SO_LINGER) && tmr_is_first(sock->sock_linger, now)) {
            if (!sock->sock_ops || !sock->sock_ops->sop_close)
                return TMR_NEVER;

            spr = sock->sock_proc;
            if (spr != NULL) {
                if (spr->spr_event == SEV_CLOSE && spr->spr_next == NULL) {
                    sock->sock_proc = NULL;
                    sockdriver_reply_generic(&spr->spr_call, OK);
                    sockevent_proc_free(spr);
                }
            }

            r = sock->sock_ops->sop_close(sock, TRUE);

            if (r == SUSPEND) {
                sock->sock_opt &= ~SO_LINGER;
            } else if (r == OK) {
                sockevent_free(sock);
            }
        }
        return TMR_NEVER;
    }

    for (sprp = &sock->sock_proc; (spr = *sprp) != NULL;) {
        if (spr->spr_timer == 0) {
            sprp = &spr->spr_next;
            continue;
        }

        if (spr->spr_event != SEV_SEND && spr->spr_event != SEV_RECV) {
            sprp = &spr->spr_next;
            continue;
        }

        if (tmr_is_first(spr->spr_time, now)) {
            *sprp = spr->spr_next;
            if (spr->spr_event == SEV_SEND) {
                sockevent_cancel_send(sock, spr, EWOULDBLOCK);
            } else {
                sockevent_cancel_recv(sock, spr, EWOULDBLOCK);
            }
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
static void socktimer_expire(int arg __unused)
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
		if (!(sock->sock_flags & SFL_TIMER))
			continue;

		sock->sock_flags &= ~SFL_TIMER;
		left = sockevent_expire(sock, now);

		if (left == TMR_NEVER)
			continue;

		if (lowest == TMR_NEVER || lowest > left)
			lowest = left;

		SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
		sock->sock_flags |= SFL_TIMER;
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
static clock_t socktimer_add(struct sock *sock, clock_t ticks) {
    clock_t now;

    if (ticks > TMRDIFF_MAX) {
        return (clock_t)-1;
    }

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
static void socktimer_del(struct sock *sock)
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
static int sockevent_bind(sockid_t id, const struct sockaddr *addr, socklen_t addr_len, endpoint_t user_endpt, const struct sockdriver_call *call)
{
	struct sock *sock;
	int r;

	sock = sockhash_get(id);
	if (!sock)
		return EINVAL;

	if (!sock->sock_ops || !sock->sock_ops->sop_bind)
		return EOPNOTSUPP;

	if (sock->sock_opt & SO_ACCEPTCONN)
		return EINVAL;

	r = sock->sock_ops->sop_bind(sock, addr, addr_len, user_endpt);

	if (r == SUSPEND) {
		if (!call)
			return EINPROGRESS;
		sockevent_suspend(sock, SEV_BIND, call, user_endpt);
	}

	return r;
}

/*
 * Connect a socket to a remote address.
 */
static int sockevent_connect(sockid_t id, const struct sockaddr * __restrict addr,
    socklen_t addr_len, endpoint_t user_endpt, const struct sockdriver_call *call)
{
    struct sockdriver_call fakecall;
    struct sockevent_proc *spr;
    struct sock *sock;
    int r;

    sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    if (!sock->sock_ops || !sock->sock_ops->sop_connect)
        return EOPNOTSUPP;

    if (sock->sock_opt & SO_ACCEPTCONN)
        return EOPNOTSUPP;

    r = sock->sock_ops->sop_connect(sock, addr, addr_len, user_endpt);

    if (r == SUSPEND) {
        int use_fakecall = 0;
        const struct sockdriver_call *actual_call = call;

        if (call == NULL && sockevent_has_events())
            use_fakecall = 1;

        if (call != NULL || sockevent_has_events()) {
            if (use_fakecall) {
                fakecall.sc_endpt = NONE;
                actual_call = &fakecall;
            }

            if (sockevent_has_suspended(sock, SEV_SEND | SEV_RECV))
                return EINVAL;

            sockevent_suspend(sock, SEV_CONNECT, actual_call, user_endpt);

            if (use_fakecall) {
                sockevent_pump();

                spr = sockevent_unsuspend(sock, actual_call);
                if (spr != NULL) {
                    sockevent_proc_free(spr);
                    r = EINPROGRESS;
                } else {
                    if (sock->sock_err != OK)
                        r = sock->sock_err;
                    sock->sock_err = OK;
                }
            }
        } else {
            r = EINPROGRESS;
        }
    }

    if (r == OK)
        sockevent_raise(sock, SEV_SEND);

    return r;
}


/*
 * Put a socket in listening mode.
 */
static int sockevent_listen(sockid_t id, int backlog)
{
    struct sock *sock;
    int r;

    sock = sockhash_get(id);
    if (!sock)
        return EINVAL;

    if (!sock->sock_ops || !sock->sock_ops->sop_listen)
        return EOPNOTSUPP;

    if (backlog < 0)
        backlog = 0;
    if (backlog < SOMAXCONN)
        backlog += 1 + ((unsigned int)backlog >> 1);
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
	struct sock *sock = sockhash_get(id);
	struct sock *newsock = NULL;
	sockid_t r;

	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops == NULL || sock->sock_ops->sop_accept == NULL)
		return EOPNOTSUPP;

	r = sock->sock_ops->sop_accept(sock, addr, addr_len, user_endpt, &newsock);
	if (r == SUSPEND) {
		if (!(sock->sock_opt & SO_ACCEPTCONN))
			return EOPNOTSUPP;

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
static int sockevent_send(sockid_t id, const struct sockdriver_data * __restrict data,
                          size_t len, const struct sockdriver_data * __restrict ctl_data,
                          socklen_t ctl_len, const struct sockaddr * __restrict addr,
                          socklen_t addr_len, endpoint_t user_endpt, int flags,
                          const struct sockdriver_call * __restrict call)
{
    struct sock *sock;
    clock_t time = 0;
    size_t min, off = 0;
    socklen_t ctl_off = 0;
    int r, timer = FALSE;

    sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    r = sock->sock_err;
    if (r != OK) {
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
        r = sock->sock_ops->sop_pre_send(sock, len, ctl_len, addr, addr_len, user_endpt,
                                         flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
        if (r != OK)
            return r;
    }

    if (sock->sock_ops->sop_send == NULL)
        return EOPNOTSUPP;

    if (flags & MSG_OOB) {
        r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data, ctl_len, &ctl_off,
                                     addr, addr_len, user_endpt, flags, 0);
        if (r == SUSPEND)
            panic("libsockevent: MSG_OOB send calls may not be suspended");
        return (r == OK) ? (int)off : r;
    }

    if (!sockevent_has_suspended(sock, SEV_SEND)) {
        min = (sock->sock_slowat < len) ? sock->sock_slowat : len;
        r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data, ctl_len, &ctl_off,
                                     addr, addr_len, user_endpt, flags, min);
    } else {
        r = SUSPEND;
    }

    if (r == SUSPEND) {
        if (call != NULL) {
            if (sock->sock_stimeo != 0) {
                timer = TRUE;
                time = socktimer_add(sock, sock->sock_stimeo);
            }
            sockevent_suspend_data(sock, SEV_SEND, timer, call, user_endpt,
                                   data, len, off, ctl_data, ctl_len, ctl_off,
                                   flags, 0, time);
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
sockevent_recv_inner(struct sock *sock,
	const struct sockdriver_data *data,
	size_t len, size_t *off,
	const struct sockdriver_data *ctl_data,
	socklen_t ctl_len, socklen_t *ctl_off,
	struct sockaddr *addr,
	socklen_t *addr_len, endpoint_t user_endpt,
	int *flags, const struct sockdriver_call *call)
{
	clock_t time = 0;
	size_t min = 0;
	int r = 0, oob = 0, inflags = 0, timer = 0;

	inflags = *flags;
	*flags = 0;

	if (sock->sock_ops->sop_pre_recv &&
	    (r = sock->sock_ops->sop_pre_recv(sock, user_endpt,
		inflags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))) != OK)
	{
		return r;
	}

	if (sock->sock_flags & SFL_SHUT_RD)
		return SOCKEVENT_EOF;

	if (!sock->sock_ops->sop_recv)
		return EOPNOTSUPP;

	oob = (inflags & MSG_OOB) ? 1 : 0;

	if (oob && (sock->sock_opt & SO_OOBINLINE))
		return EINVAL;

	if (oob || !sockevent_has_suspended(sock, SEV_RECV)) {
		if (!oob && sock->sock_err == OK) {
			min = (sock->sock_rlowat < len) ? sock->sock_rlowat : len;
		}
		r = sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
			ctl_len, ctl_off, addr, addr_len, user_endpt, inflags, min,
			flags);
	} else {
		r = SUSPEND;
	}

	if (r != SUSPEND) {
		if (r > 0 && r != SOCKEVENT_EOF) {
			r = 0;
		}
		return r;
	}

	if (oob) {
		panic("libsockevent: MSG_OOB receive calls may not be suspended");
	}

	if (call && sock->sock_err == OK) {
		if (sock->sock_rtimeo != 0) {
			timer = 1;
			time = socktimer_add(sock, sock->sock_rtimeo);
		}
		sockevent_suspend_data(sock, SEV_RECV, timer, call,
			user_endpt, data, len, *off, ctl_data,
			ctl_len, *ctl_off, inflags, *flags, time);
	} else {
		r = EWOULDBLOCK;
	}

	return r;
}

/*
 * Receive regular and/or control data.
 */
static int sockevent_recv(sockid_t id, const struct sockdriver_data * __restrict data,
    size_t len, const struct sockdriver_data * __restrict ctl_data,
    socklen_t * __restrict ctl_len, struct sockaddr * __restrict addr,
    socklen_t * __restrict addr_len, endpoint_t user_endpt,
    int * __restrict flags, const struct sockdriver_call * __restrict call)
{
    struct sock *sock = sockhash_get(id);
    size_t off = 0;
    socklen_t ctl_inlen;
    int r;

    if (sock == NULL)
        return EINVAL;

    ctl_inlen = *ctl_len;
    *ctl_len = 0;

    r = sockevent_recv_inner(sock, data, len, &off, ctl_data, ctl_inlen,
        ctl_len, addr, addr_len, user_endpt, flags, call);

    if (r == OK || (r != SUSPEND && (off > 0 || *ctl_len > 0))) {
        return (int)off;
    }

    if (sock->sock_err != OK) {
        if (r == SUSPEND) {
            return EIO;
        }
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
static int sockevent_ioctl(sockid_t id, unsigned long request,
    const struct sockdriver_data * __restrict data, endpoint_t user_endpt,
    const struct sockdriver_call * __restrict call __unused)
{
    struct sock *sock;
    size_t size = 0;
    int r;

    sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    if (request == FIONREAD) {
        int val = 0;
        if (!(sock->sock_flags & SFL_SHUT_RD) && sock->sock_ops->sop_test_recv) {
            (void)sock->sock_ops->sop_test_recv(sock, 0, &size);
        }
        val = (int)size;
        return sockdriver_copyout(data, 0, &val, sizeof(val));
    }

    if (!sock->sock_ops->sop_ioctl)
        return ENOTTY;

    r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

    if (r == SUSPEND)
        panic("libsockevent: socket driver suspended IOCTL 0x%lx", request);

    return r;
}

/*
 * Set socket options.
 */
static int sockevent_setsockopt(sockid_t id, int level, int name,
	const struct sockdriver_data *data, socklen_t len)
{
	struct sock *sock;
	struct linger linger;
	struct timeval tv;
	clock_t secs, ticks;
	int r, val;

	sock = sockhash_get(id);
	if (sock == NULL)
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
			r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
			if (r != OK)
				return r;

			if (val)
				sock->sock_opt |= (unsigned int)name;
			else
				sock->sock_opt &= ~(unsigned int)name;

			if (sock->sock_ops->sop_setsockmask)
				sock->sock_ops->sop_setsockmask(sock, sock->sock_opt);

			if (name == SO_OOBINLINE && val)
				sockevent_raise(sock, SEV_RECV);

			return OK;

		case SO_LINGER:
			r = sockdriver_copyin_opt(data, &linger, sizeof(linger), len);
			if (r != OK)
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
			r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
			if (r != OK)
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
			r = sockdriver_copyin_opt(data, &tv, sizeof(tv), len);
			if (r != OK)
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
			break;
		}
	}

	if (!sock->sock_ops->sop_setsockopt)
		return ENOPROTOOPT;

	return sock->sock_ops->sop_setsockopt(sock, level, name, data, len);
}

/*
 * Retrieve socket options.
 */
static int sockevent_getsockopt(sockid_t id, int level, int name,
    const struct sockdriver_data * __restrict data,
    socklen_t * __restrict len)
{
    struct sock *sock;
    struct linger linger;
    struct timeval tv;
    clock_t ticks;
    int val;
    int ret;

    sock = sockhash_get(id);
    if (sock == NULL)
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
                val = (sock->sock_opt & (unsigned int)name) ? 1 : 0;
                ret = sockdriver_copyout_opt(data, &val, sizeof(val), len);
                return ret;

            case SO_LINGER:
                linger.l_onoff = (sock->sock_opt & SO_LINGER) ? 1 : 0;
                linger.l_linger = (int)(sock->sock_linger / sys_hz());
                ret = sockdriver_copyout_opt(data, &linger, sizeof(linger), len);
                return ret;

            case SO_ERROR:
                val = (sock->sock_err != OK) ? -sock->sock_err : OK;
                if (sock->sock_err != OK)
                    sock->sock_err = OK;
                ret = sockdriver_copyout_opt(data, &val, sizeof(val), len);
                return ret;

            case SO_TYPE:
                val = sock->sock_type;
                ret = sockdriver_copyout_opt(data, &val, sizeof(val), len);
                return ret;

            case SO_SNDLOWAT:
                val = (int)sock->sock_slowat;
                ret = sockdriver_copyout_opt(data, &val, sizeof(val), len);
                return ret;

            case SO_RCVLOWAT:
                val = (int)sock->sock_rlowat;
                ret = sockdriver_copyout_opt(data, &val, sizeof(val), len);
                return ret;

            case SO_SNDTIMEO:
            case SO_RCVTIMEO:
                ticks = (name == SO_SNDTIMEO) ? sock->sock_stimeo : sock->sock_rtimeo;
                tv.tv_sec = ticks / sys_hz();
                tv.tv_usec = (ticks % sys_hz()) * US / sys_hz();
                ret = sockdriver_copyout_opt(data, &tv, sizeof(tv), len);
                return ret;

            default:
                break;
        }
    }

    if (!sock->sock_ops || !sock->sock_ops->sop_getsockopt)
        return ENOPROTOOPT;

    return sock->sock_ops->sop_getsockopt(sock, level, name, data, len);
}

/*
 * Retrieve a socket's local address.
 */
static int sockevent_getsockname(sockid_t id, struct sockaddr * __restrict addr, socklen_t * __restrict addr_len)
{
	struct sock *sock = sockhash_get(id);

	if (!sock)
		return EINVAL;

	if (!sock->sock_ops || !sock->sock_ops->sop_getsockname)
		return EOPNOTSUPP;

	return sock->sock_ops->sop_getsockname(sock, addr, addr_len);
}

/*
 * Retrieve a socket's remote address.
 */
static int sockevent_getpeername(sockid_t id, struct sockaddr * __restrict addr, socklen_t * __restrict addr_len)
{
    struct sock *sock = sockhash_get(id);
    if (!sock)
        return EINVAL;

    if (sock->sock_opt & SO_ACCEPTCONN)
        return ENOTCONN;

    if (!sock->sock_ops || !sock->sock_ops->sop_getpeername)
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
void sockevent_set_shutdown(struct sock *sock, unsigned int flags) {
    unsigned int mask = 0;

    if (!sock || !sock->sock_ops)
        return;

    if (flags & ~(SFL_SHUT_RD | SFL_SHUT_WR))
        return;

    flags &= ~sock->sock_flags;
    if (flags == 0)
        return;

    sock->sock_flags |= flags;

    if (flags & SFL_SHUT_RD)
        mask |= SEV_RECV;
    if (flags & SFL_SHUT_WR)
        mask |= SEV_SEND;
    if (sock->sock_opt & SO_ACCEPTCONN)
        mask |= SEV_ACCEPT;

    if (mask != 0)
        sockevent_raise(sock, mask);
}

/*
 * Shut down socket send and receive operations.
 */
static int sockevent_shutdown(sockid_t id, int how) {
    struct sock *sock = sockhash_get(id);
    if (sock == NULL)
        return EINVAL;

    unsigned int flags = 0;
    if (how == SHUT_RD || how == SHUT_RDWR)
        flags |= SFL_SHUT_RD;
    if (how == SHUT_WR || how == SHUT_RDWR)
        flags |= SFL_SHUT_WR;

    if (flags == 0)
        return EINVAL;

    int r = (sock->sock_ops && sock->sock_ops->sop_shutdown)
        ? sock->sock_ops->sop_shutdown(sock, flags)
        : OK;

    if (r == OK)
        sockevent_set_shutdown(sock, flags);

    return r;
}

/*
 * Close a socket.
 */
static int
sockevent_close(sockid_t id, const struct sockdriver_call *call)
{
	struct sock *sock;
	int r = OK;
	int force = 0;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	assert(sock->sock_proc == NULL);
	sock->sock_select.ss_endpt = NONE;

	if ((sock->sock_opt & SO_LINGER) && sock->sock_linger == 0)
		force = 1;

	if (sock->sock_ops->sop_close)
		r = sock->sock_ops->sop_close(sock, force);

	assert(r == OK || r == SUSPEND);

	if (r == SUSPEND) {
		sock->sock_flags |= SFL_CLOSING;

		if (force)
			return OK;

		if (sock->sock_opt & SO_LINGER)
			sock->sock_linger = socktimer_add(sock, sock->sock_linger);
		else
			call = NULL;

		if (call)
			sockevent_suspend(sock, SEV_CLOSE, call, NONE);
		else
			r = OK;
	} else if (r == OK) {
		sockevent_free(sock);
	}

	return r;
}

/*
 * Cancel a suspended send request.
 */
static void sockevent_cancel_send(struct sock *sock, struct sockevent_proc *spr, int err) {
    int r = err;

    if (spr == NULL || sock == NULL) {
        return;
    }

    if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) {
        r = (int)spr->spr_dataoff;
    }

    sockdriver_reply_generic(&spr->spr_call, r);

    sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static void sockevent_cancel_recv(struct sock *sock, struct sockevent_proc *spr, int err)
{
    int result = (spr->spr_dataoff > 0 || spr->spr_ctloff > 0) ? (int)spr->spr_dataoff : err;

    sockdriver_reply_recv(&spr->spr_call, result, spr->spr_ctloff, NULL, 0, spr->spr_rflags);
    sockevent_raise(sock, SEV_RECV);
}

/*
 * Cancel a previous request that may currently be suspended.  The cancel
 * operation itself does not have a reply.  Instead, if the given request was
 * found to be suspended, that request must be aborted and an appropriate reply
 * must be sent for the request.  If no matching request was found, no reply
 * must be sent at all.
 */
static void sockevent_cancel(sockid_t id, const struct sockdriver_call *call)
{
    struct sockevent_proc *spr = NULL;
    struct sock *sock = sockhash_get(id);

    if (sock == NULL)
        return;

    spr = sockevent_unsuspend(sock, call);
    if (spr == NULL)
        return;

    switch (spr->spr_event) {
        case SEV_BIND:
        case SEV_CONNECT:
            if (spr->spr_call.sc_endpt == NONE) {
                sockevent_proc_free(spr);
                return;
            }
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
static int sockevent_select(sockid_t id, unsigned int ops, const struct sockdriver_select *sel) {
    struct sock *sock;
    unsigned int result_ops, notify;
    if ((sock = sockhash_get(id)) == NULL)
        return EINVAL;

    notify = (ops & SDEV_NOTIFY);
    ops &= (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR);

    result_ops = sockevent_test_select(sock, ops);

    if (sock->sock_selops & result_ops)
        return EIO;

    ops &= ~result_ops;

    if (notify && ops) {
        if (sock->sock_select.ss_endpt != NONE) {
            if (sock->sock_select.ss_endpt != sel->ss_endpt)
                return EIO;
            sock->sock_selops |= ops;
        } else {
            if (sel->ss_endpt == NONE)
                return EINVAL;
            sock->sock_select = *sel;
            sock->sock_selops = ops;
        }
    }

    return result_ops;
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
    if (sockevent_working) {
        return;
    }

    sockevent_working = TRUE;

    sockdriver_process(&sockevent_tab, m_ptr, ipc_status);

    while (sockevent_has_events()) {
        sockevent_pump();
    }

    sockevent_working = FALSE;
}
