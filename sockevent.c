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

	for (slot = 0; slot < __arraycount(sockhash); slot++)
		SLIST_INIT(&sockhash[slot]);
}

/*
 * Given a socket identifier, return a hash table slot number.
 */
static unsigned int
sockhash_slot(sockid_t id)
{
	const unsigned int CLASS_SHIFT = 16;
	return (id + (id >> CLASS_SHIFT)) % SOCKHASH_SLOTS;
}

/*
 * Obtain a sock object from the hash table using its unique identifier.
 * Return a pointer to the object if found, or NULL otherwise.
 */
static struct sock *
sockhash_get(sockid_t id)
{
	struct sock *sock;
	unsigned int slot = sockhash_slot(id);

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
	unsigned int slot = sockhash_slot(sock->sock_id);
	SLIST_INSERT_HEAD(&sockhash[slot], sock, sock_hash);
}

/*
 * Remove a sock object from the hash table.  The sock object must be in the
 * hash table.
 */
static void
sockhash_del(struct sock * sock)
{
	unsigned int slot = sockhash_slot(sock->sock_id);
	SLIST_REMOVE(&sockhash[slot], sock, sock, sock_hash);
}

/*
 * Reset a socket object to a proper initial state, with a particular socket
 * identifier, a SOCK_ type, and a socket operations table.  The socket is
 * added to the ID-to-object hash table.  This function always succeeds.
 */
static void initialize_sock_defaults(struct sock *sock)
{
    sock->sock_slowat = 1;
    sock->sock_rlowat = 1;
    sock->sock_proc = NULL;
    sock->sock_select.ss_endpt = NONE;
}

static void set_sock_properties(struct sock *sock, sockid_t id, int domain, 
    int type, const struct sockevent_ops *ops)
{
    sock->sock_id = id;
    sock->sock_domain = domain;
    sock->sock_type = type;
    sock->sock_ops = ops;
}

static void sockevent_reset(struct sock *sock, sockid_t id, int domain, int type,
    const struct sockevent_ops *ops)
{
    assert(sock != NULL);
    
    memset(sock, 0, sizeof(*sock));
    
    set_sock_properties(sock, id, domain, type, ops);
    initialize_sock_defaults(sock);
    
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
static int validate_domain(int domain)
{
	if (domain < 0 || domain > UINT8_MAX)
		return EAFNOSUPPORT;
	return OK;
}

static int check_initialization(void)
{
	if (sockevent_socket_cb == NULL)
		panic("libsockevent: not initialized");
	return OK;
}

static int create_socket(int domain, int type, int protocol, 
	endpoint_t user_endpt, struct sock **sock, 
	const struct sockevent_ops **ops)
{
	sockid_t r;
	
	r = sockevent_socket_cb(domain, type, protocol, user_endpt, sock, ops);
	if (r < 0)
		return r;
		
	assert(*sock != NULL);
	assert(*ops != NULL);
	
	return r;
}

static int
sockevent_alloc(int domain, int type, int protocol, endpoint_t user_endpt,
	struct sock ** sockp)
{
	struct sock *sock;
	const struct sockevent_ops *ops;
	sockid_t socket_id;
	int result;

	result = validate_domain(domain);
	if (result != OK)
		return result;

	check_initialization();

	sock = NULL;
	ops = NULL;

	socket_id = create_socket(domain, type, protocol, user_endpt, 
		&sock, &ops);
	if (socket_id < 0)
		return socket_id;

	sockevent_reset(sock, socket_id, domain, type, ops);

	*sockp = sock;
	return OK;
}

/*
 * Free a previously allocated sock object.
 */
static void invalidate_socket_operations(struct sock *sock)
{
	sock->sock_ops = NULL;
}

static void cleanup_socket_resources(struct sock *sock)
{
	socktimer_del(sock);
	sockhash_del(sock);
}

static void call_socket_free_operation(const struct sockevent_ops *ops, struct sock *sock)
{
	assert(ops != NULL);
	assert(ops->sop_free != NULL);
	ops->sop_free(sock);
}

static void
sockevent_free(struct sock * sock)
{
	const struct sockevent_ops *ops;

	assert(sock->sock_proc == NULL);

	cleanup_socket_resources(sock);

	ops = sock->sock_ops;
	invalidate_socket_operations(sock);

	call_socket_free_operation(ops, sock);
}

/*
 * Create a new socket.
 */
static sockid_t
sockevent_socket(int domain, int type, int protocol, endpoint_t user_endpt)
{
	struct sock *sock;
	int r;

	r = sockevent_alloc(domain, type, protocol, user_endpt, &sock);
	if (r != OK)
		return r;

	return sock->sock_id;
}

/*
 * Create a pair of connected sockets.
 */
static int create_socket_pair(int domain, int type, int protocol, endpoint_t user_endpt, struct sock **sock1, struct sock **sock2)
{
    int r;
    
    if ((r = sockevent_alloc(domain, type, protocol, user_endpt, sock1)) != OK)
        return r;
    
    if ((*sock1)->sock_ops->sop_pair == NULL) {
        sockevent_free(*sock1);
        return EOPNOTSUPP;
    }
    
    if ((r = sockevent_alloc(domain, type, protocol, user_endpt, sock2)) != OK) {
        sockevent_free(*sock1);
        return r;
    }
    
    return OK;
}

static void cleanup_sockets(struct sock *sock1, struct sock *sock2)
{
    sockevent_free(sock2);
    sockevent_free(sock1);
}

static int
sockevent_socketpair(int domain, int type, int protocol, endpoint_t user_endpt,
    sockid_t id[2])
{
    struct sock *sock1, *sock2;
    int r;
    
    r = create_socket_pair(domain, type, protocol, user_endpt, &sock1, &sock2);
    if (r != OK)
        return r;
    
    assert(sock1->sock_ops == sock2->sock_ops);
    
    r = sock1->sock_ops->sop_pair(sock1, sock2, user_endpt);
    
    if (r != OK) {
        cleanup_sockets(sock1, sock2);
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
static int should_send_sigpipe(struct sock *sock, int flags)
{
	if (sock->sock_type != SOCK_STREAM)
		return 0;

	if (flags & MSG_NOSIGNAL)
		return 0;

	if (sock->sock_opt & SO_NOSIGPIPE)
		return 0;

	return 1;
}

static void
sockevent_sigpipe(struct sock *sock, endpoint_t user_endpt, int flags)
{
	if (!should_send_sigpipe(sock, flags))
		return;

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
	struct sockevent_proc *spr, **sprp;

	if ((spr = sockevent_proc_alloc()) == NULL)
		panic("libsockevent: too many suspended processes");

	spr->spr_next = NULL;
	spr->spr_event = event;
	spr->spr_timer = FALSE;
	spr->spr_call = *call;
	spr->spr_endpt = user_endpt;

	for (sprp = &sock->sock_proc; *sprp != NULL;
	     sprp = &(*sprp)->spr_next);
	*sprp = spr;
}

/*
 * Suspend a request with data, that is, a send or receive request.
 */
static void init_sockevent_proc(struct sockevent_proc *spr, unsigned int event, int timer,
    const struct sockdriver_call *call, endpoint_t user_endpt,
    const struct sockdriver_data *data, size_t len, size_t off,
    const struct sockdriver_data *ctl, socklen_t ctl_len,
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

static void append_to_proc_queue(struct sock *sock, struct sockevent_proc *spr)
{
    struct sockevent_proc **sprp;
    
    for (sprp = &sock->sock_proc; *sprp != NULL; sprp = &(*sprp)->spr_next);
    *sprp = spr;
}

static void
sockevent_suspend_data(struct sock *sock, unsigned int event, int timer,
    const struct sockdriver_call *__restrict call, endpoint_t user_endpt,
    const struct sockdriver_data *__restrict data, size_t len, size_t off,
    const struct sockdriver_data *__restrict ctl, socklen_t ctl_len,
    socklen_t ctl_off, int flags, int rflags, clock_t time)
{
    struct sockevent_proc *spr;

    if ((spr = sockevent_proc_alloc()) == NULL)
        panic("libsockevent: too many suspended processes");

    init_sockevent_proc(spr, event, timer, call, user_endpt, data, len, off,
        ctl, ctl_len, ctl_off, flags, rflags, time);
    
    append_to_proc_queue(sock, spr);
}

/*
 * Return TRUE if there are any suspended requests on the given socket's queue
 * that match any of the events in the given event mask, or FALSE otherwise.
 */
static int
sockevent_has_suspended(struct sock * sock, unsigned int mask)
{
	struct sockevent_proc *spr;

	for (spr = sock->sock_proc; spr != NULL; spr = spr->spr_next)
		if (spr->spr_event & mask)
			return TRUE;

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
find_matching_proc(struct sockevent_proc **sprp, const struct sockdriver_call *call)
{
	struct sockevent_proc *spr;

	while ((spr = *sprp) != NULL) {
		if (spr->spr_call.sc_endpt == call->sc_endpt &&
		    spr->spr_call.sc_req == call->sc_req) {
			return spr;
		}
		sprp = &spr->spr_next;
	}
	return NULL;
}

static struct sockevent_proc *
sockevent_unsuspend(struct sock *sock, const struct sockdriver_call *call)
{
	struct sockevent_proc *spr, **sprp;

	sprp = &sock->sock_proc;
	spr = find_matching_proc(sprp, call);
	
	if (spr == NULL) {
		return NULL;
	}

	while (*sprp != spr) {
		sprp = &(*sprp)->spr_next;
	}
	
	*sprp = spr->spr_next;
	return spr;
}

/*
 * Attempt to resume the given suspended request for the given socket object.
 * Return TRUE if the suspended request has been fully resumed and can be
 * removed from the queue of suspended requests, or FALSE if it has not been
 * fully resumed and should stay on the queue.  In the latter case, no
 * resumption will be attempted for other suspended requests of the same type.
 */
static int handle_connect_bind(struct sock *sock, struct sockevent_proc *spr)
{
	sockid_t r = (sock->sock_err != OK) ? sock->sock_err : OK;
	if (r != OK)
		sock->sock_err = OK;
	sockdriver_reply_generic(&spr->spr_call, r);
	return TRUE;
}

static int handle_accept(struct sock *sock, struct sockevent_proc *spr)
{
	char addr[SOCKADDR_MAX];
	socklen_t addr_len = 0;
	struct sock *newsock = NULL;
	sockid_t r;

	assert(sock->sock_opt & SO_ACCEPTCONN);

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
}

static sockid_t get_send_error(struct sock *sock, struct sockevent_proc *spr)
{
	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
		return (int)spr->spr_dataoff;
	
	sockid_t r = sock->sock_err;
	if (r != OK) {
		sock->sock_err = OK;
		return r;
	}
	return EPIPE;
}

static sockid_t perform_send(struct sock *sock, struct sockevent_proc *spr)
{
	struct sockdriver_data data, ctl;
	size_t len, min;

	sockdriver_unpack_data(&data, &spr->spr_call, 
	    &spr->spr_data, spr->spr_datalen);
	sockdriver_unpack_data(&ctl, &spr->spr_call, 
	    &spr->spr_ctl, spr->spr_ctllen);

	len = spr->spr_datalen - spr->spr_dataoff;
	min = (sock->sock_slowat > len) ? len : sock->sock_slowat;

	sockid_t r = sock->sock_ops->sop_send(sock, &data, len,
	    &spr->spr_dataoff, &ctl, spr->spr_ctllen - spr->spr_ctloff,
	    &spr->spr_ctloff, NULL, 0, spr->spr_endpt, spr->spr_flags, min);

	assert(r <= 0);

	if (r != SUSPEND && (spr->spr_dataoff > 0 || spr->spr_ctloff > 0))
		r = spr->spr_dataoff;

	return r;
}

static int handle_send(struct sock *sock, struct sockevent_proc *spr)
{
	sockid_t r;

	if (sock->sock_err != OK || (sock->sock_flags & SFL_SHUT_WR)) {
		r = get_send_error(sock, spr);
	} else {
		r = perform_send(sock, spr);
		if (r == SUSPEND)
			return FALSE;
	}

	if (r == EPIPE)
		sockevent_sigpipe(sock, spr->spr_endpt, spr->spr_flags);

	sockdriver_reply_generic(&spr->spr_call, r);
	return TRUE;
}

static sockid_t perform_recv(struct sock *sock, struct sockevent_proc *spr, 
    char *addr, socklen_t *addr_len)
{
	struct sockdriver_data data, ctl;
	size_t len, min;

	len = spr->spr_datalen - spr->spr_dataoff;
	min = (sock->sock_err == OK) ? 
	    ((sock->sock_rlowat > len) ? len : sock->sock_rlowat) : 0;

	sockdriver_unpack_data(&data, &spr->spr_call, 
	    &spr->spr_data, spr->spr_datalen);
	sockdriver_unpack_data(&ctl, &spr->spr_call, 
	    &spr->spr_ctl, spr->spr_ctllen);

	sockid_t r = sock->sock_ops->sop_recv(sock, &data, len,
	    &spr->spr_dataoff, &ctl, spr->spr_ctllen - spr->spr_ctloff,
	    &spr->spr_ctloff, (struct sockaddr *)addr, addr_len,
	    spr->spr_endpt, spr->spr_flags, min, &spr->spr_rflags);

	if (r == SUSPEND && sock->sock_err != OK)
		r = SOCKEVENT_EOF;

	assert(*addr_len <= SOCKADDR_MAX);
	return r;
}

static sockid_t get_recv_result(struct sock *sock, struct sockevent_proc *spr, 
    sockid_t r)
{
	if (r == OK || spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
		return (int)spr->spr_dataoff;
	
	if (sock->sock_err != OK) {
		sockid_t err = sock->sock_err;
		sock->sock_err = OK;
		return err;
	}
	
	return (r == SOCKEVENT_EOF) ? 0 : r;
}

static int handle_recv(struct sock *sock, struct sockevent_proc *spr)
{
	char addr[SOCKADDR_MAX];
	socklen_t addr_len = 0;
	sockid_t r;

	if (sock->sock_flags & SFL_SHUT_RD) {
		r = SOCKEVENT_EOF;
	} else {
		r = perform_recv(sock, spr, addr, &addr_len);
		if (r == SUSPEND)
			return FALSE;
	}

	r = get_recv_result(sock, spr, r);

	sockdriver_reply_recv(&spr->spr_call, r, spr->spr_ctloff,
	    (struct sockaddr *)&addr, addr_len, spr->spr_rflags);
	return TRUE;
}

static int handle_close(struct sockevent_proc *spr)
{
	sockdriver_reply_generic(&spr->spr_call, OK);
	return TRUE;
}

static int sockevent_resume(struct sock *sock, struct sockevent_proc *spr)
{
	switch (spr->spr_event) {
	case SEV_CONNECT:
		if (spr->spr_call.sc_endpt == NONE)
			return TRUE;
		return handle_connect_bind(sock, spr);
	case SEV_BIND:
		return handle_connect_bind(sock, spr);
	case SEV_ACCEPT:
		return handle_accept(sock, spr);
	case SEV_SEND:
		return handle_send(sock, spr);
	case SEV_RECV:
		return handle_recv(sock, spr);
	case SEV_CLOSE:
		return handle_close(spr);
	default:
		panic("libsockevent: process suspended on unknown event 0x%x",
		    spr->spr_event);
	}
}

/*
 * Return TRUE if the given socket is ready for reading for a select call, or
 * FALSE otherwise.
 */
static int is_shutdown_or_error(struct sock *sock)
{
    return (sock->sock_flags & SFL_SHUT_RD) || (sock->sock_err != OK);
}

static int test_accept_ready(struct sock *sock)
{
    if (sock->sock_ops->sop_test_accept == NULL)
        return TRUE;
    
    return sock->sock_ops->sop_test_accept(sock);
}

static int test_receive_ready(struct sock *sock)
{
    if (sock->sock_ops->sop_test_recv == NULL)
        return TRUE;
    
    return sock->sock_ops->sop_test_recv(sock, sock->sock_rlowat, NULL);
}

static int
sockevent_test_readable(struct sock *sock)
{
    int r;
    
    if (is_shutdown_or_error(sock))
        return TRUE;
    
    if (sock->sock_opt & SO_ACCEPTCONN) {
        r = test_accept_ready(sock);
    } else {
        r = test_receive_ready(sock);
    }
    
    return (r != SUSPEND);
}

/*
 * Return TRUE if the given socket is ready for writing for a select call, or
 * FALSE otherwise.
 */
static int is_socket_error_or_shutdown(struct sock *sock)
{
    return (sock->sock_err != OK) || (sock->sock_flags & SFL_SHUT_WR);
}

static int has_no_send_test_operation(struct sock *sock)
{
    return (sock->sock_ops->sop_test_send == NULL);
}

static int test_send_would_not_block(struct sock *sock)
{
    int r = sock->sock_ops->sop_test_send(sock, sock->sock_slowat);
    return (r != SUSPEND);
}

static int sockevent_test_writable(struct sock *sock)
{
    if (is_socket_error_or_shutdown(sock))
        return TRUE;

    if (has_no_send_test_operation(sock))
        return TRUE;

    return test_send_would_not_block(sock);
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
static void handle_connect_event(unsigned int *mask)
{
	if (*mask & SEV_CONNECT)
		*mask |= SEV_SEND;
}

static void resume_system_calls(struct sock *sock, unsigned int *mask)
{
	struct sockevent_proc *spr, **sprp;
	unsigned int flag;

	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL; ) {
		flag = spr->spr_event;

		if ((*mask & flag) && sockevent_resume(sock, spr)) {
			*sprp = spr->spr_next;
			sockevent_proc_free(spr);
		} else {
			*mask &= ~flag;
			sprp = &spr->spr_next;
		}
	}
}

static unsigned int get_testable_operations(unsigned int mask, unsigned int selops)
{
	unsigned int ops = selops;
	
	if (!(mask & (SEV_ACCEPT | SEV_RECV)))
		ops &= ~SDEV_OP_RD;
	if (!(mask & SEV_SEND))
		ops &= ~SDEV_OP_WR;
	if (!(0))
		ops &= ~SDEV_OP_ERR;
		
	return ops;
}

static void process_select_operations(struct sock *sock, unsigned int ops)
{
	unsigned int r = sockevent_test_select(sock, ops);
	
	if (r != 0) {
		sockdriver_reply_select(&sock->sock_select, sock->sock_id, r);
		sock->sock_selops &= ~r;
		
		if (sock->sock_selops == 0)
			sock->sock_select.ss_endpt = NONE;
	}
}

static void handle_select_queries(struct sock *sock, unsigned int mask)
{
	unsigned int ops;
	
	if (!(mask & (SEV_ACCEPT | SEV_SEND | SEV_RECV)))
		return;
		
	if (sock->sock_select.ss_endpt == NONE)
		return;
		
	assert(sock->sock_selops != 0);
	
	ops = get_testable_operations(mask, sock->sock_selops);
	
	if (ops != 0)
		process_select_operations(sock, ops);
}

static void handle_close_event(struct sock *sock, unsigned int mask)
{
	if (mask & SEV_CLOSE) {
		assert(sock->sock_flags & (SFL_CLONED | SFL_CLOSING));
		sockevent_free(sock);
	}
}

static void sockevent_fire(struct sock *sock, unsigned int mask)
{
	handle_connect_event(&mask);
	resume_system_calls(sock, &mask);
	handle_select_queries(sock, mask);
	handle_close_event(sock, mask);
}

/*
 * Process all pending events.  Events must still be blocked, so that if
 * handling one event generates a new event, that event is handled from here
 * rather than immediately.
 */
static void process_single_sock_event(struct sock *sock)
{
    unsigned int mask = sock->sock_events;
    assert(mask != 0);
    sock->sock_events = 0;
    sockevent_fire(sock, mask);
}

static struct sock* get_next_pending_sock(void)
{
    struct sock *sock = SIMPLEQ_FIRST(&sockevent_pending);
    SIMPLEQ_REMOVE_HEAD(&sockevent_pending, sock_next);
    return sock;
}

static void sockevent_pump(void)
{
    assert(sockevent_working);

    while (!SIMPLEQ_EMPTY(&sockevent_pending)) {
        struct sock *sock = get_next_pending_sock();
        process_single_sock_event(sock);
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
		sockevent_defer(sock, mask);
	} else {
		sockevent_process_immediate(sock, mask);
	}
}

static void
sockevent_defer(struct sock * sock, unsigned int mask)
{
	assert(mask != 0);
	assert(mask <= UCHAR_MAX);

	if (sock->sock_events == 0)
		SIMPLEQ_INSERT_TAIL(&sockevent_pending, sock, sock_next);

	sock->sock_events |= mask;
}

static void
sockevent_process_immediate(struct sock * sock, unsigned int mask)
{
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
    assert(err < 0);
    assert(sock->sock_ops != NULL);

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
handle_linger_timer(struct sock *sock, clock_t now)
{
	struct sockevent_proc *spr;
	int r;

	if (!(sock->sock_opt & SO_LINGER))
		return TMR_NEVER;

	if (!tmr_is_first(sock->sock_linger, now))
		return TMR_NEVER;

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

	return TMR_NEVER;
}

static void
cancel_expired_request(struct sock *sock, struct sockevent_proc *spr)
{
	if (spr->spr_event == SEV_SEND)
		sockevent_cancel_send(sock, spr, EWOULDBLOCK);
	else
		sockevent_cancel_recv(sock, spr, EWOULDBLOCK);
}

static clock_t
process_request_timeout(struct sock *sock, struct sockevent_proc *spr, clock_t now, clock_t lowest)
{
	clock_t left;

	if (spr->spr_timer == 0)
		return lowest;

	assert(spr->spr_event == SEV_SEND || spr->spr_event == SEV_RECV);

	if (tmr_is_first(spr->spr_time, now)) {
		cancel_expired_request(sock, spr);
		return lowest;
	}

	left = spr->spr_time - now;

	if (lowest == TMR_NEVER || lowest > left)
		return left;

	return lowest;
}

static clock_t
process_pending_requests(struct sock *sock, clock_t now)
{
	struct sockevent_proc *spr, **sprp, *next;
	clock_t lowest = TMR_NEVER;

	for (sprp = &sock->sock_proc; (spr = *sprp) != NULL; ) {
		next = spr->spr_next;

		if (spr->spr_timer == 0) {
			sprp = &spr->spr_next;
			continue;
		}

		lowest = process_request_timeout(sock, spr, now, lowest);

		if (tmr_is_first(spr->spr_time, now)) {
			*sprp = next;
			sockevent_proc_free(spr);
		} else {
			sprp = &spr->spr_next;
		}
	}

	return lowest;
}

static clock_t
sockevent_expire(struct sock *sock, clock_t now)
{
	if (sock->sock_flags & SFL_CLOSING)
		return handle_linger_timer(sock, now);

	return process_pending_requests(sock, now);
}

/*
 * The socket event alarm went off.  Go through the set of socket objects with
 * timers, and see if any of their requests have now expired.  Set a new alarm
 * as necessary.
 */
static void process_socket_timeout(struct sock *sock, clock_t now, clock_t *lowest)
{
	clock_t left = sockevent_expire(sock, now);
	
	if (left != TMR_NEVER) {
		if (*lowest == TMR_NEVER || *lowest > left)
			*lowest = left;
		
		SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
		sock->sock_flags |= SFL_TIMER;
	}
}

static void handle_event_processing(int was_working)
{
	if (!was_working) {
		if (sockevent_has_events())
			sockevent_pump();
		
		sockevent_working = FALSE;
	}
}

static void set_timer_if_needed(clock_t lowest)
{
	if (lowest != TMR_NEVER)
		set_timer(&sockevent_timer, lowest, socktimer_expire, 0);
}

static int begin_event_processing(void)
{
	int was_working = sockevent_working;
	
	if (!was_working)
		sockevent_working = TRUE;
	
	return was_working;
}

static void transfer_timer_list(SLIST_HEAD(, sock) *oldtimer)
{
	memcpy(oldtimer, &socktimer, sizeof(*oldtimer));
	SLIST_INIT(&socktimer);
}

static void clear_timer_flag(struct sock *sock)
{
	assert(sock->sock_flags & SFL_TIMER);
	sock->sock_flags &= ~SFL_TIMER;
}

static void socktimer_expire(int arg __unused)
{
	SLIST_HEAD(, sock) oldtimer;
	struct sock *sock, *tsock;
	clock_t now, lowest;
	int was_working;
	
	was_working = begin_event_processing();
	transfer_timer_list(&oldtimer);
	
	now = getticks();
	lowest = TMR_NEVER;
	
	SLIST_FOREACH_SAFE(sock, &oldtimer, sock_timer, tsock) {
		clear_timer_flag(sock);
		process_socket_timeout(sock, now, &lowest);
	}
	
	set_timer_if_needed(lowest);
	handle_event_processing(was_working);
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

	socktimer_add_to_list(sock);

	now = getticks();

	socktimer_update_timer_if_needed(now, ticks);

	return now + ticks;
}

static void
socktimer_add_to_list(struct sock * sock)
{
	if (sock->sock_flags & SFL_TIMER)
		return;

	SLIST_INSERT_HEAD(&socktimer, sock, sock_timer);
	sock->sock_flags |= SFL_TIMER;
}

static void
socktimer_update_timer_if_needed(clock_t now, clock_t ticks)
{
	if (socktimer_should_update_timer(now, ticks))
		set_timer(&sockevent_timer, ticks, socktimer_expire, 0);
}

static int
socktimer_should_update_timer(clock_t now, clock_t ticks)
{
	return !tmr_is_set(&sockevent_timer) ||
	       tmr_is_first(now + ticks, tmr_exp_time(&sockevent_timer));
}

/*
 * Remove a socket object from the set of socket objects with timers.  Since
 * the timer list is maintained lazily, this needs to be done only right before
 * the socket object is freed.
 */
static void
socktimer_del(struct sock * sock)
{
	if (!(sock->sock_flags & SFL_TIMER)) {
		return;
	}
	
	SLIST_REMOVE(&socktimer, sock, sock, sock_timer);
	sock->sock_flags &= ~SFL_TIMER;
}

/*
 * Bind a socket to a local address.
 */
static int validate_bind_preconditions(struct sock *sock)
{
	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_bind == NULL)
		return EOPNOTSUPP;

	if (sock->sock_opt & SO_ACCEPTCONN)
		return EINVAL;

	return 0;
}

static int handle_bind_suspension(struct sock *sock, int result, 
	const struct sockdriver_call * __restrict call, endpoint_t user_endpt)
{
	if (result != SUSPEND)
		return result;

	if (call == NULL)
		return EINPROGRESS;

	sockevent_suspend(sock, SEV_BIND, call, user_endpt);
	return result;
}

static int
sockevent_bind(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call * __restrict call)
{
	struct sock *sock;
	int r;

	sock = sockhash_get(id);
	
	r = validate_bind_preconditions(sock);
	if (r != 0)
		return r;

	r = sock->sock_ops->sop_bind(sock, addr, addr_len, user_endpt);

	return handle_bind_suspension(sock, r, call, user_endpt);
}

/*
 * Connect a socket to a remote address.
 */
static int validate_connect_socket(struct sock *sock)
{
	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_connect == NULL)
		return EOPNOTSUPP;

	if (sock->sock_opt & SO_ACCEPTCONN)
		return EOPNOTSUPP;

	return OK;
}

static void setup_fake_call(struct sockdriver_call *fakecall)
{
	fakecall->sc_endpt = NONE;
}

static int handle_immediate_connect(struct sock *sock, 
	const struct sockdriver_call *call, endpoint_t user_endpt)
{
	struct sockdriver_call fakecall;
	struct sockevent_proc *spr;
	const struct sockdriver_call *use_call;
	int r;

	if (call == NULL) {
		setup_fake_call(&fakecall);
		use_call = &fakecall;
	} else {
		use_call = call;
	}

	assert(!sockevent_has_suspended(sock, SEV_SEND | SEV_RECV));
	sockevent_suspend(sock, SEV_CONNECT, use_call, user_endpt);

	if (use_call == &fakecall) {
		sockevent_pump();

		spr = sockevent_unsuspend(sock, use_call);
		if (spr != NULL) {
			sockevent_proc_free(spr);
			r = EINPROGRESS;
		} else if ((r = sock->sock_err) != OK) {
			sock->sock_err = OK;
		} else {
			r = OK;
		}
	} else {
		r = SUSPEND;
	}

	return r;
}

static int process_suspend_result(struct sock *sock, 
	const struct sockdriver_call *call, endpoint_t user_endpt)
{
	if (call != NULL || sockevent_has_events()) {
		return handle_immediate_connect(sock, call, user_endpt);
	}
	return EINPROGRESS;
}

static void mark_socket_writable(struct sock *sock)
{
	sockevent_raise(sock, SEV_SEND);
}

static int sockevent_connect(sockid_t id, const struct sockaddr * __restrict addr,
	socklen_t addr_len, endpoint_t user_endpt,
	const struct sockdriver_call *call)
{
	struct sock *sock;
	int r;

	sock = sockhash_get(id);
	
	r = validate_connect_socket(sock);
	if (r != OK)
		return r;

	r = sock->sock_ops->sop_connect(sock, addr, addr_len, user_endpt);

	if (r == SUSPEND) {
		r = process_suspend_result(sock, call, user_endpt);
	}

	if (r == OK) {
		mark_socket_writable(sock);
	}

	return r;
}

/*
 * Put a socket in listening mode.
 */
static int validate_socket(sockid_t id, struct sock **sock)
{
	*sock = sockhash_get(id);
	if (*sock == NULL)
		return EINVAL;
	
	if ((*sock)->sock_ops->sop_listen == NULL)
		return EOPNOTSUPP;
	
	return OK;
}

static int adjust_backlog(int backlog)
{
	#define BACKLOG_FUDGE_FACTOR_SHIFT 1
	
	if (backlog < 0)
		backlog = 0;
	
	if (backlog < SOMAXCONN)
		backlog += 1 + ((unsigned int)backlog >> BACKLOG_FUDGE_FACTOR_SHIFT);
	
	if (backlog > SOMAXCONN)
		backlog = SOMAXCONN;
	
	return backlog;
}

static void handle_listen_success(struct sock *sock)
{
	sock->sock_opt |= SO_ACCEPTCONN;
	sockevent_raise(sock, SEV_ACCEPT);
}

static int
sockevent_listen(sockid_t id, int backlog)
{
	struct sock *sock;
	int r;

	r = validate_socket(id, &sock);
	if (r != OK)
		return r;

	backlog = adjust_backlog(backlog);

	r = sock->sock_ops->sop_listen(sock, backlog);

	if (r == OK)
		handle_listen_success(sock);

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

	r = sock->sock_ops->sop_accept(sock, addr, addr_len, user_endpt, &newsock);

	if (r == SUSPEND)
		return handle_suspend_accept(sock, call, user_endpt);

	if (r >= 0)
		sockevent_accepted(sock, newsock, r);

	return r;
}

static sockid_t
handle_suspend_accept(struct sock *sock, const struct sockdriver_call *call,
	endpoint_t user_endpt)
{
	assert(sock->sock_opt & SO_ACCEPTCONN);

	if (call == NULL)
		return EWOULDBLOCK;

	sockevent_suspend(sock, SEV_ACCEPT, call, user_endpt);

	return SUSPEND;
}

/*
 * Send regular and/or control data.
 */
static int check_socket_errors(struct sock *sock, endpoint_t user_endpt, int flags)
{
	int r;

	if ((r = sock->sock_err) != OK) {
		sock->sock_err = OK;
		return r;
	}

	if (sock->sock_flags & SFL_SHUT_WR) {
		sockevent_sigpipe(sock, user_endpt, flags);
		return EPIPE;
	}

	return OK;
}

static int apply_socket_options(struct sock *sock, int flags)
{
	if (sock->sock_opt & SO_DONTROUTE)
		flags |= MSG_DONTROUTE;
	return flags;
}

static int validate_send_request(struct sock *sock, size_t len, socklen_t ctl_len,
	const struct sockaddr *addr, socklen_t addr_len, endpoint_t user_endpt, int flags)
{
	int r;

	if (sock->sock_ops->sop_pre_send != NULL) {
		r = sock->sock_ops->sop_pre_send(sock, len, ctl_len, addr,
		    addr_len, user_endpt, flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
		if (r != OK)
			return r;
	}

	if (sock->sock_ops->sop_send == NULL)
		return EOPNOTSUPP;

	return OK;
}

static int handle_oob_send(struct sock *sock, const struct sockdriver_data *data,
	size_t len, const struct sockdriver_data *ctl_data, socklen_t ctl_len,
	const struct sockaddr *addr, socklen_t addr_len, endpoint_t user_endpt, int flags)
{
	size_t off = 0;
	socklen_t ctl_off = 0;
	int r;

	r = sock->sock_ops->sop_send(sock, data, len, &off, ctl_data,
	    ctl_len, &ctl_off, addr, addr_len, user_endpt, flags, 0);

	if (r == SUSPEND)
		panic("libsockevent: MSG_OOB send calls may not be suspended");

	return (r == OK) ? (int)off : r;
}

static size_t calculate_min_send(struct sock *sock, size_t len)
{
	size_t min = sock->sock_slowat;
	if (min > len)
		min = len;
	return min;
}

static void setup_send_timer(struct sock *sock, int *timer, clock_t *time)
{
	if (sock->sock_stimeo != 0) {
		*timer = TRUE;
		*time = socktimer_add(sock, sock->sock_stimeo);
	} else {
		*timer = FALSE;
		*time = 0;
	}
}

static int perform_regular_send(struct sock *sock, const struct sockdriver_data *data,
	size_t len, size_t *off, const struct sockdriver_data *ctl_data, socklen_t ctl_len,
	socklen_t *ctl_off, const struct sockaddr *addr, socklen_t addr_len,
	endpoint_t user_endpt, int flags)
{
	size_t min;

	if (!sockevent_has_suspended(sock, SEV_SEND)) {
		min = calculate_min_send(sock, len);
		return sock->sock_ops->sop_send(sock, data, len, off, ctl_data,
		    ctl_len, ctl_off, addr, addr_len, user_endpt, flags, min);
	}

	return SUSPEND;
}

static int handle_suspend_result(struct sock *sock, int r, size_t off, socklen_t ctl_off,
	const struct sockdriver_call *call, endpoint_t user_endpt,
	const struct sockdriver_data *data, size_t len,
	const struct sockdriver_data *ctl_data, socklen_t ctl_len, int flags)
{
	int timer;
	clock_t time;

	if (r == SUSPEND) {
		if (call != NULL) {
			setup_send_timer(sock, &timer, &time);
			sockevent_suspend_data(sock, SEV_SEND, timer, call,
			    user_endpt, data, len, off, ctl_data, ctl_len,
			    ctl_off, flags, 0, time);
		} else {
			r = (off > 0 || ctl_off > 0) ? OK : EWOULDBLOCK;
		}
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
	size_t off = 0;
	socklen_t ctl_off = 0;
	int r;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	if ((r = check_socket_errors(sock, user_endpt, flags)) != OK)
		return r;

	flags = apply_socket_options(sock, flags);

	if ((r = validate_send_request(sock, len, ctl_len, addr, addr_len,
	    user_endpt, flags)) != OK)
		return r;

	if (flags & MSG_OOB)
		return handle_oob_send(sock, data, len, ctl_data, ctl_len,
		    addr, addr_len, user_endpt, flags);

	r = perform_regular_send(sock, data, len, &off, ctl_data, ctl_len,
	    &ctl_off, addr, addr_len, user_endpt, flags);

	return handle_suspend_result(sock, r, off, ctl_off, call, user_endpt,
	    data, len, ctl_data, ctl_len, flags);
}

/*
 * The inner part of the receive request handler.  An error returned from here
 * may be overridden by an error pending on the socket, although data returned
 * from here trumps such pending errors.
 */
static int validate_recv_request(struct sock *sock, endpoint_t user_endpt, int inflags)
{
	if (sock->sock_ops->sop_pre_recv == NULL)
		return OK;
	
	return sock->sock_ops->sop_pre_recv(sock, user_endpt, 
		inflags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
}

static int check_recv_preconditions(struct sock *sock, int inflags)
{
	if (sock->sock_flags & SFL_SHUT_RD)
		return SOCKEVENT_EOF;

	if (sock->sock_ops->sop_recv == NULL)
		return EOPNOTSUPP;

	if ((inflags & MSG_OOB) && (sock->sock_opt & SO_OOBINLINE))
		return EINVAL;

	return OK;
}

static size_t calculate_min_recv_size(struct sock *sock, size_t len, int oob)
{
	size_t min;

	if (oob || sock->sock_err != OK)
		return 0;

	min = sock->sock_rlowat;
	if (min > len)
		min = len;

	return min;
}

static void setup_recv_timer(struct sock *sock, int *timer, clock_t *time)
{
	if (sock->sock_rtimeo != 0) {
		*timer = TRUE;
		*time = socktimer_add(sock, sock->sock_rtimeo);
	} else {
		*timer = FALSE;
		*time = 0;
	}
}

static int handle_recv_suspension(struct sock *sock, 
	const struct sockdriver_call *call, endpoint_t user_endpt,
	const struct sockdriver_data *data, size_t len, size_t off,
	const struct sockdriver_data *ctl_data, socklen_t ctl_len,
	socklen_t ctl_off, int inflags, int flags)
{
	clock_t time;
	int timer;

	if (call != NULL && sock->sock_err == OK) {
		setup_recv_timer(sock, &timer, &time);
		sockevent_suspend_data(sock, SEV_RECV, timer, call,
			user_endpt, data, len, off, ctl_data,
			ctl_len, ctl_off, inflags, flags, time);
		return SUSPEND;
	}
	
	return EWOULDBLOCK;
}

static int perform_recv_operation(struct sock *sock,
	const struct sockdriver_data *data, size_t len, size_t *off,
	const struct sockdriver_data *ctl_data, socklen_t ctl_len,
	socklen_t *ctl_off, struct sockaddr *addr, socklen_t *addr_len,
	endpoint_t user_endpt, int inflags, int *flags, int oob)
{
	size_t min;

	if (oob || !sockevent_has_suspended(sock, SEV_RECV)) {
		min = calculate_min_recv_size(sock, len, oob);
		return sock->sock_ops->sop_recv(sock, data, len, off, ctl_data,
			ctl_len, ctl_off, addr, addr_len, user_endpt, inflags, min,
			flags);
	}
	
	return SUSPEND;
}

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
	int r, oob, inflags;

	inflags = *flags;
	*flags = 0;

	r = validate_recv_request(sock, user_endpt, inflags);
	if (r != OK)
		return r;

	r = check_recv_preconditions(sock, inflags);
	if (r != OK)
		return r;

	oob = (inflags & MSG_OOB);

	r = perform_recv_operation(sock, data, len, off, ctl_data, ctl_len,
		ctl_off, addr, addr_len, user_endpt, inflags, flags, oob);

	assert(r <= 0 || r == SOCKEVENT_EOF);

	if (r == SUSPEND) {
		if (oob)
			panic("libsockevent: MSG_OOB receive calls may not be "
				"suspended");

		r = handle_recv_suspension(sock, call, user_endpt, data, len,
			*off, ctl_data, ctl_len, *ctl_off, inflags, *flags);
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
	size_t off;
	socklen_t ctl_inlen;
	int r;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	off = 0;
	ctl_inlen = *ctl_len;
	*ctl_len = 0;

	r = sockevent_recv_inner(sock, data, len, &off, ctl_data, ctl_inlen,
	    ctl_len, addr, addr_len, user_endpt, flags, call);

	if (r == OK || (r != SUSPEND && (off > 0 || *ctl_len > 0)))
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
static int handle_fionread(struct sock *sock, const struct sockdriver_data *data)
{
    size_t size = 0;
    int val;

    if (!(sock->sock_flags & SFL_SHUT_RD) &&
        sock->sock_ops->sop_test_recv != NULL) {
        (void)sock->sock_ops->sop_test_recv(sock, 0, &size);
    }

    val = (int)size;
    return sockdriver_copyout(data, 0, &val, sizeof(val));
}

static int handle_custom_ioctl(struct sock *sock, unsigned long request,
    const struct sockdriver_data *data, endpoint_t user_endpt)
{
    int r;

    if (sock->sock_ops->sop_ioctl == NULL)
        return ENOTTY;

    r = sock->sock_ops->sop_ioctl(sock, request, data, user_endpt);

    if (r == SUSPEND)
        panic("libsockevent: socket driver suspended IOCTL 0x%lx",
            request);

    return r;
}

static int
sockevent_ioctl(sockid_t id, unsigned long request,
    const struct sockdriver_data * __restrict data, endpoint_t user_endpt,
    const struct sockdriver_call * __restrict call __unused)
{
    struct sock *sock;

    if ((sock = sockhash_get(id)) == NULL)
        return EINVAL;

    switch (request) {
    case FIONREAD:
        return handle_fionread(sock, data);
    }

    return handle_custom_ioctl(sock, request, data, user_endpt);
}

/*
 * Set socket options.
 */
static int copy_and_validate_option(const struct sockdriver_data *data, void *buf, 
                                   size_t buf_size, socklen_t len)
{
    return sockdriver_copyin_opt(data, buf, buf_size, len);
}

static void update_socket_flag(struct sock *sock, unsigned int flag, int enable)
{
    if (enable)
        sock->sock_opt |= flag;
    else
        sock->sock_opt &= ~flag;
}

static void notify_sockmask_change(struct sock *sock)
{
    if (sock->sock_ops->sop_setsockmask != NULL)
        sock->sock_ops->sop_setsockmask(sock, sock->sock_opt);
}

static int handle_simple_flag_option(struct sock *sock, int name, 
                                    const struct sockdriver_data *data, socklen_t len)
{
    int r, val;
    
    if ((r = copy_and_validate_option(data, &val, sizeof(val), len)) != OK)
        return r;
    
    update_socket_flag(sock, (unsigned int)name, val);
    notify_sockmask_change(sock);
    
    if (name == SO_OOBINLINE && val)
        sockevent_raise(sock, SEV_RECV);
    
    return OK;
}

static int handle_linger_option(struct sock *sock, const struct sockdriver_data *data, 
                               socklen_t len)
{
    struct linger linger;
    clock_t secs;
    int r;
    
    if ((r = copy_and_validate_option(data, &linger, sizeof(linger), len)) != OK)
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

static int handle_lowat_option(struct sock *sock, int name, 
                              const struct sockdriver_data *data, socklen_t len)
{
    int r, val;
    
    if ((r = copy_and_validate_option(data, &val, sizeof(val), len)) != OK)
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

static int validate_timeval(struct timeval *tv)
{
    if (tv->tv_sec < 0 || tv->tv_usec < 0 || 
        (unsigned long)tv->tv_usec >= US)
        return EINVAL;
    if (tv->tv_sec >= TMRDIFF_MAX / sys_hz())
        return EDOM;
    return OK;
}

static clock_t timeval_to_ticks(struct timeval *tv)
{
    return tv->tv_sec * sys_hz() + (tv->tv_usec * sys_hz() + US - 1) / US;
}

static int handle_timeout_option(struct sock *sock, int name, 
                                const struct sockdriver_data *data, socklen_t len)
{
    struct timeval tv;
    clock_t ticks;
    int r;
    
    if ((r = copy_and_validate_option(data, &tv, sizeof(tv), len)) != OK)
        return r;
    
    if ((r = validate_timeval(&tv)) != OK)
        return r;
    
    ticks = timeval_to_ticks(&tv);
    
    if (name == SO_SNDTIMEO)
        sock->sock_stimeo = ticks;
    else
        sock->sock_rtimeo = ticks;
    
    return OK;
}

static int is_simple_flag_option(int name)
{
    return (name == SO_DEBUG || name == SO_REUSEADDR || name == SO_KEEPALIVE ||
            name == SO_DONTROUTE || name == SO_BROADCAST || name == SO_OOBINLINE ||
            name == SO_REUSEPORT || name == SO_NOSIGPIPE || name == SO_TIMESTAMP);
}

static int is_readonly_option(int name)
{
    return (name == SO_ACCEPTCONN || name == SO_ERROR || name == SO_TYPE);
}

static int handle_socket_level_option(struct sock *sock, int name,
                                     const struct sockdriver_data *data, socklen_t len)
{
    if (is_simple_flag_option(name))
        return handle_simple_flag_option(sock, name, data, len);
    
    if (name == SO_LINGER)
        return handle_linger_option(sock, data, len);
    
    if (name == SO_SNDLOWAT || name == SO_RCVLOWAT)
        return handle_lowat_option(sock, name, data, len);
    
    if (name == SO_SNDTIMEO || name == SO_RCVTIMEO)
        return handle_timeout_option(sock, name, data, len);
    
    if (is_readonly_option(name))
        return ENOPROTOOPT;
    
    return -1;
}

static int
sockevent_setsockopt(sockid_t id, int level, int name,
    const struct sockdriver_data *data, socklen_t len)
{
    struct sock *sock;
    int result;
    
    if ((sock = sockhash_get(id)) == NULL)
        return EINVAL;
    
    if (level == SOL_SOCKET) {
        result = handle_socket_level_option(sock, name, data, len);
        if (result >= 0)
            return result;
    }
    
    if (sock->sock_ops->sop_setsockopt == NULL)
        return ENOPROTOOPT;
    
    return sock->sock_ops->sop_setsockopt(sock, level, name, data, len);
}

/*
 * Retrieve socket options.
 */
static int get_boolean_option(struct sock *sock, int name, 
    const struct sockdriver_data *data, socklen_t *len)
{
    int val = !!(sock->sock_opt & (unsigned int)name);
    return sockdriver_copyout_opt(data, &val, sizeof(val), len);
}

static int get_linger_option(struct sock *sock, 
    const struct sockdriver_data *data, socklen_t *len)
{
    struct linger linger;
    linger.l_onoff = !!(sock->sock_opt & SO_LINGER);
    linger.l_linger = sock->sock_linger / sys_hz();
    return sockdriver_copyout_opt(data, &linger, sizeof(linger), len);
}

static int get_error_option(struct sock *sock, 
    const struct sockdriver_data *data, socklen_t *len)
{
    int val = -sock->sock_err;
    if (val != OK)
        sock->sock_err = OK;
    return sockdriver_copyout_opt(data, &val, sizeof(val), len);
}

static int get_int_value_option(int value, 
    const struct sockdriver_data *data, socklen_t *len)
{
    return sockdriver_copyout_opt(data, &value, sizeof(value), len);
}

static int get_timeout_option(clock_t ticks, 
    const struct sockdriver_data *data, socklen_t *len)
{
    struct timeval tv;
    tv.tv_sec = ticks / sys_hz();
    tv.tv_usec = (ticks % sys_hz()) * US / sys_hz();
    return sockdriver_copyout_opt(data, &tv, sizeof(tv), len);
}

static int handle_socket_level_option(struct sock *sock, int name,
    const struct sockdriver_data *data, socklen_t *len)
{
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
        return get_boolean_option(sock, name, data, len);

    case SO_LINGER:
        return get_linger_option(sock, data, len);

    case SO_ERROR:
        return get_error_option(sock, data, len);

    case SO_TYPE:
        return get_int_value_option(sock->sock_type, data, len);

    case SO_SNDLOWAT:
        return get_int_value_option((int)sock->sock_slowat, data, len);

    case SO_RCVLOWAT:
        return get_int_value_option((int)sock->sock_rlowat, data, len);

    case SO_SNDTIMEO:
        return get_timeout_option(sock->sock_stimeo, data, len);

    case SO_RCVTIMEO:
        return get_timeout_option(sock->sock_rtimeo, data, len);

    default:
        return -1;
    }
}

static int
sockevent_getsockopt(sockid_t id, int level, int name,
    const struct sockdriver_data * __restrict data,
    socklen_t * __restrict len)
{
    struct sock *sock;
    int result;

    if ((sock = sockhash_get(id)) == NULL)
        return EINVAL;

    if (level == SOL_SOCKET) {
        result = handle_socket_level_option(sock, name, data, len);
        if (result >= 0)
            return result;
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
	struct sock *sock;

	sock = sockhash_get(id);
	if (sock == NULL)
		return EINVAL;

	if (sock->sock_ops->sop_getsockname == NULL)
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
	struct sock *sock;

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
	assert(sock->sock_ops != NULL);
	assert(!(flags & ~(SFL_SHUT_RD | SFL_SHUT_WR)));

	flags &= ~(unsigned int)sock->sock_flags;

	if (flags == 0)
		return;

	sock->sock_flags |= flags;

	unsigned int mask = 0;
	if (flags & SFL_SHUT_RD)
		mask |= SEV_RECV;
	if (flags & SFL_SHUT_WR)
		mask |= SEV_SEND;
	if (sock->sock_opt & SO_ACCEPTCONN)
		mask |= SEV_ACCEPT;

	assert(mask != 0);
	sockevent_raise(sock, mask);
}

/*
 * Shut down socket send and receive operations.
 */
static int get_shutdown_flags(int how)
{
	unsigned int flags = 0;
	
	if (how == SHUT_RD || how == SHUT_RDWR)
		flags |= SFL_SHUT_RD;
	if (how == SHUT_WR || how == SHUT_RDWR)
		flags |= SFL_SHUT_WR;
	
	return flags;
}

static int perform_shutdown(struct sock *sock, unsigned int flags)
{
	if (sock->sock_ops->sop_shutdown != NULL)
		return sock->sock_ops->sop_shutdown(sock, flags);
	
	return OK;
}

static int
sockevent_shutdown(sockid_t id, int how)
{
	struct sock *sock;
	unsigned int flags;
	int r;

	if ((sock = sockhash_get(id)) == NULL)
		return EINVAL;

	flags = get_shutdown_flags(how);
	r = perform_shutdown(sock, flags);

	if (r == OK)
		sockevent_set_shutdown(sock, flags);

	return r;
}

/*
 * Close a socket.
 */
static int handle_close_suspension(struct sock *sock, const struct sockdriver_call *call, int force) {
    sock->sock_flags |= SFL_CLOSING;
    
    if (force) {
        return OK;
    }
    
    if (sock->sock_opt & SO_LINGER) {
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

static int get_force_close_flag(struct sock *sock) {
    return (sock->sock_opt & SO_LINGER) && sock->sock_linger == 0;
}

static int call_close_operation(struct sock *sock, int force) {
    if (sock->sock_ops->sop_close != NULL) {
        return sock->sock_ops->sop_close(sock, force);
    }
    return OK;
}

static int sockevent_close(sockid_t id, const struct sockdriver_call *call) {
    struct sock *sock;
    int r, force;
    
    if ((sock = sockhash_get(id)) == NULL) {
        return EINVAL;
    }
    
    assert(sock->sock_proc == NULL);
    sock->sock_select.ss_endpt = NONE;
    
    force = get_force_close_flag(sock);
    r = call_close_operation(sock, force);
    
    assert(r == OK || r == SUSPEND);
    
    if (r == SUSPEND) {
        return handle_close_suspension(sock, call, force);
    }
    
    if (r == OK) {
        sockevent_free(sock);
    }
    
    return r;
}

/*
 * Cancel a suspended send request.
 */
static int calculate_send_result(const struct sockevent_proc *spr, int err)
{
	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
		return (int)spr->spr_dataoff;
	return err;
}

static int has_sent_data(const struct sockevent_proc *spr)
{
	return (spr->spr_dataoff > 0 || spr->spr_ctloff > 0);
}

static void
sockevent_cancel_send(struct sock *sock, struct sockevent_proc *spr, int err)
{
	int r = calculate_send_result(spr, err);

	sockdriver_reply_generic(&spr->spr_call, r);

	sockevent_raise(sock, SEV_SEND);
}

/*
 * Cancel a suspended receive request.
 */
static int calculate_recv_result(struct sockevent_proc * spr, int err)
{
	if (spr->spr_dataoff > 0 || spr->spr_ctloff > 0)
		return (int)spr->spr_dataoff;
	return err;
}

static void sockevent_cancel_recv(struct sock * sock, struct sockevent_proc * spr, int err)
{
	int r = calculate_recv_result(spr, err);

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
sockevent_cancel(sockid_t id, const struct sockdriver_call * call)
{
	struct sockevent_proc *spr;
	struct sock *sock;

	sock = sockhash_get(id);
	if (sock == NULL)
		return;

	spr = sockevent_unsuspend(sock, call);
	if (spr == NULL)
		return;

	handle_cancel_by_event(sock, spr);
	sockevent_proc_free(spr);
}

static void
handle_cancel_by_event(struct sock *sock, struct sockevent_proc *spr)
{
	switch (spr->spr_event) {
	case SEV_BIND:
	case SEV_CONNECT:
		handle_bind_connect_cancel(spr);
		break;
	case SEV_ACCEPT:
		handle_accept_cancel(spr);
		break;
	case SEV_SEND:
		handle_send_cancel(sock, spr);
		break;
	case SEV_RECV:
		handle_recv_cancel(sock, spr);
		break;
	case SEV_CLOSE:
		handle_close_cancel(spr);
		break;
	default:
		panic("libsockevent: process suspended on unknown event 0x%x",
		    spr->spr_event);
	}
}

static void
handle_bind_connect_cancel(struct sockevent_proc *spr)
{
	assert(spr->spr_call.sc_endpt != NONE);
	sockdriver_reply_generic(&spr->spr_call, EINTR);
}

static void
handle_accept_cancel(struct sockevent_proc *spr)
{
	sockdriver_reply_accept(&spr->spr_call, EINTR, NULL, 0);
}

static void
handle_send_cancel(struct sock *sock, struct sockevent_proc *spr)
{
	sockevent_cancel_send(sock, spr, EINTR);
}

static void
handle_recv_cancel(struct sock *sock, struct sockevent_proc *spr)
{
	sockevent_cancel_recv(sock, spr, EINTR);
}

static void
handle_close_cancel(struct sockevent_proc *spr)
{
	sockdriver_reply_generic(&spr->spr_call, EINPROGRESS);
}

/*
 * Process a select request.
 */
static int validate_sock_and_ops(sockid_t id, unsigned int *ops, unsigned int *notify, struct sock **sock)
{
	*sock = sockhash_get(id);
	if (*sock == NULL)
		return EINVAL;

	*notify = (*ops & SDEV_NOTIFY);
	*ops &= (SDEV_OP_RD | SDEV_OP_WR | SDEV_OP_ERR);
	return 0;
}

static int handle_multiple_callers(struct sock *sock, const struct sockdriver_select *sel)
{
	if (sock->sock_select.ss_endpt != sel->ss_endpt) {
		printf("libsockevent: no support for multiple select callers yet\n");
		return EIO;
	}
	return 0;
}

static void save_pending_operations(struct sock *sock, const struct sockdriver_select *sel, unsigned int ops)
{
	if (sock->sock_select.ss_endpt != NONE) {
		int err = handle_multiple_callers(sock, sel);
		if (err != 0)
			return;
		sock->sock_selops |= ops;
		return;
	}

	assert(sel->ss_endpt != NONE);
	sock->sock_select = *sel;
	sock->sock_selops = ops;
}

static int sockevent_select(sockid_t id, unsigned int ops, const struct sockdriver_select *sel)
{
	struct sock *sock;
	unsigned int r, notify;
	int err;

	err = validate_sock_and_ops(id, &ops, &notify, &sock);
	if (err != 0)
		return err;

	r = sockevent_test_select(sock, ops);
	assert(!(sock->sock_selops & r));

	ops &= ~r;

	if (notify && ops != 0)
		save_pending_operations(sock, sel, ops);

	return r;
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
    sockhash_init();
    socktimer_init();
    sockevent_proc_init();
    SIMPLEQ_INIT(&sockevent_pending);
    
    assert(socket_cb != NULL);
    sockevent_socket_cb = socket_cb;
    
    sockdriver_announce();
    sockevent_working = FALSE;
}

/*
 * Process a socket driver request message.
 */
void sockevent_process(const message *m_ptr, int ipc_status)
{
    assert(!sockevent_working);
    sockevent_working = TRUE;

    sockdriver_process(&sockevent_tab, m_ptr, ipc_status);

    if (sockevent_has_events())
        sockevent_pump();

    sockevent_working = FALSE;
}
