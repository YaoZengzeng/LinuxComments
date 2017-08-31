/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp.c,v 1.216 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *
 * Fixes:
 *		Alan Cox	:	Numerous verify_area() calls
 *		Alan Cox	:	Set the ACK bit on a reset
 *		Alan Cox	:	Stopped it crashing if it closed while
 *					sk->inuse=1 and was trying to connect
 *					(tcp_err()).
 *		Alan Cox	:	All icmp error handling was broken
 *					pointers passed where wrong and the
 *					socket was looked up backwards. Nobody
 *					tested any icmp error code obviously.
 *		Alan Cox	:	tcp_err() now handled properly. It
 *					wakes people on errors. poll
 *					behaves and the icmp error race
 *					has gone by moving it into sock.c
 *		Alan Cox	:	tcp_send_reset() fixed to work for
 *					everything not just packets for
 *					unknown sockets.
 *		Alan Cox	:	tcp option processing.
 *		Alan Cox	:	Reset tweaked (still not 100%) [Had
 *					syn rule wrong]
 *		Herp Rosmanith  :	More reset fixes
 *		Alan Cox	:	No longer acks invalid rst frames.
 *					Acking any kind of RST is right out.
 *		Alan Cox	:	Sets an ignore me flag on an rst
 *					receive otherwise odd bits of prattle
 *					escape still
 *		Alan Cox	:	Fixed another acking RST frame bug.
 *					Should stop LAN workplace lockups.
 *		Alan Cox	: 	Some tidyups using the new skb list
 *					facilities
 *		Alan Cox	:	sk->keepopen now seems to work
 *		Alan Cox	:	Pulls options out correctly on accepts
 *		Alan Cox	:	Fixed assorted sk->rqueue->next errors
 *		Alan Cox	:	PSH doesn't end a TCP read. Switched a
 *					bit to skb ops.
 *		Alan Cox	:	Tidied tcp_data to avoid a potential
 *					nasty.
 *		Alan Cox	:	Added some better commenting, as the
 *					tcp is hard to follow
 *		Alan Cox	:	Removed incorrect check for 20 * psh
 *	Michael O'Reilly	:	ack < copied bug fix.
 *	Johannes Stille		:	Misc tcp fixes (not all in yet).
 *		Alan Cox	:	FIN with no memory -> CRASH
 *		Alan Cox	:	Added socket option proto entries.
 *					Also added awareness of them to accept.
 *		Alan Cox	:	Added TCP options (SOL_TCP)
 *		Alan Cox	:	Switched wakeup calls to callbacks,
 *					so the kernel can layer network
 *					sockets.
 *		Alan Cox	:	Use ip_tos/ip_ttl settings.
 *		Alan Cox	:	Handle FIN (more) properly (we hope).
 *		Alan Cox	:	RST frames sent on unsynchronised
 *					state ack error.
 *		Alan Cox	:	Put in missing check for SYN bit.
 *		Alan Cox	:	Added tcp_select_window() aka NET2E
 *					window non shrink trick.
 *		Alan Cox	:	Added a couple of small NET2E timer
 *					fixes
 *		Charles Hedrick :	TCP fixes
 *		Toomas Tamm	:	TCP window fixes
 *		Alan Cox	:	Small URG fix to rlogin ^C ack fight
 *		Charles Hedrick	:	Rewrote most of it to actually work
 *		Linus		:	Rewrote tcp_read() and URG handling
 *					completely
 *		Gerhard Koerting:	Fixed some missing timer handling
 *		Matthew Dillon  :	Reworked TCP machine states as per RFC
 *		Gerhard Koerting:	PC/TCP workarounds
 *		Adam Caldwell	:	Assorted timer/timing errors
 *		Matthew Dillon	:	Fixed another RST bug
 *		Alan Cox	:	Move to kernel side addressing changes.
 *		Alan Cox	:	Beginning work on TCP fastpathing
 *					(not yet usable)
 *		Arnt Gulbrandsen:	Turbocharged tcp_check() routine.
 *		Alan Cox	:	TCP fast path debugging
 *		Alan Cox	:	Window clamping
 *		Michael Riepe	:	Bug in tcp_check()
 *		Matt Dillon	:	More TCP improvements and RST bug fixes
 *		Matt Dillon	:	Yet more small nasties remove from the
 *					TCP code (Be very nice to this man if
 *					tcp finally works 100%) 8)
 *		Alan Cox	:	BSD accept semantics.
 *		Alan Cox	:	Reset on closedown bug.
 *	Peter De Schrijver	:	ENOTCONN check missing in tcp_sendto().
 *		Michael Pall	:	Handle poll() after URG properly in
 *					all cases.
 *		Michael Pall	:	Undo the last fix in tcp_read_urg()
 *					(multi URG PUSH broke rlogin).
 *		Michael Pall	:	Fix the multi URG PUSH problem in
 *					tcp_readable(), poll() after URG
 *					works now.
 *		Michael Pall	:	recv(...,MSG_OOB) never blocks in the
 *					BSD api.
 *		Alan Cox	:	Changed the semantics of sk->socket to
 *					fix a race and a signal problem with
 *					accept() and async I/O.
 *		Alan Cox	:	Relaxed the rules on tcp_sendto().
 *		Yury Shevchuk	:	Really fixed accept() blocking problem.
 *		Craig I. Hagan  :	Allow for BSD compatible TIME_WAIT for
 *					clients/servers which listen in on
 *					fixed ports.
 *		Alan Cox	:	Cleaned the above up and shrank it to
 *					a sensible code size.
 *		Alan Cox	:	Self connect lockup fix.
 *		Alan Cox	:	No connect to multicast.
 *		Ross Biro	:	Close unaccepted children on master
 *					socket close.
 *		Alan Cox	:	Reset tracing code.
 *		Alan Cox	:	Spurious resets on shutdown.
 *		Alan Cox	:	Giant 15 minute/60 second timer error
 *		Alan Cox	:	Small whoops in polling before an
 *					accept.
 *		Alan Cox	:	Kept the state trace facility since
 *					it's handy for debugging.
 *		Alan Cox	:	More reset handler fixes.
 *		Alan Cox	:	Started rewriting the code based on
 *					the RFC's for other useful protocol
 *					references see: Comer, KA9Q NOS, and
 *					for a reference on the difference
 *					between specifications and how BSD
 *					works see the 4.4lite source.
 *		A.N.Kuznetsov	:	Don't time wait on completion of tidy
 *					close.
 *		Linus Torvalds	:	Fin/Shutdown & copied_seq changes.
 *		Linus Torvalds	:	Fixed BSD port reuse to work first syn
 *		Alan Cox	:	Reimplemented timers as per the RFC
 *					and using multiple timers for sanity.
 *		Alan Cox	:	Small bug fixes, and a lot of new
 *					comments.
 *		Alan Cox	:	Fixed dual reader crash by locking
 *					the buffers (much like datagram.c)
 *		Alan Cox	:	Fixed stuck sockets in probe. A probe
 *					now gets fed up of retrying without
 *					(even a no space) answer.
 *		Alan Cox	:	Extracted closing code better
 *		Alan Cox	:	Fixed the closing state machine to
 *					resemble the RFC.
 *		Alan Cox	:	More 'per spec' fixes.
 *		Jorge Cwik	:	Even faster checksumming.
 *		Alan Cox	:	tcp_data() doesn't ack illegal PSH
 *					only frames. At least one pc tcp stack
 *					generates them.
 *		Alan Cox	:	Cache last socket.
 *		Alan Cox	:	Per route irtt.
 *		Matt Day	:	poll()->select() match BSD precisely on error
 *		Alan Cox	:	New buffers
 *		Marc Tamsky	:	Various sk->prot->retransmits and
 *					sk->retransmits misupdating fixed.
 *					Fixed tcp_write_timeout: stuck close,
 *					and TCP syn retries gets used now.
 *		Mark Yarvis	:	In tcp_read_wakeup(), don't send an
 *					ack if state is TCP_CLOSED.
 *		Alan Cox	:	Look up device on a retransmit - routes may
 *					change. Doesn't yet cope with MSS shrink right
 *					but it's a start!
 *		Marc Tamsky	:	Closing in closing fixes.
 *		Mike Shaver	:	RFC1122 verifications.
 *		Alan Cox	:	rcv_saddr errors.
 *		Alan Cox	:	Block double connect().
 *		Alan Cox	:	Small hooks for enSKIP.
 *		Alexey Kuznetsov:	Path MTU discovery.
 *		Alan Cox	:	Support soft errors.
 *		Alan Cox	:	Fix MTU discovery pathological case
 *					when the remote claims no mtu!
 *		Marc Tamsky	:	TCP_CLOSE fix.
 *		Colin (G3TNE)	:	Send a reset on syn ack replies in
 *					window but wrong (fixes NT lpd problems)
 *		Pedro Roque	:	Better TCP window handling, delayed ack.
 *		Joerg Reuter	:	No modification of locked buffers in
 *					tcp_do_retransmit()
 *		Eric Schenk	:	Changed receiver side silly window
 *					avoidance algorithm to BSD style
 *					algorithm. This doubles throughput
 *					against machines running Solaris,
 *					and seems to result in general
 *					improvement.
 *	Stefan Magdalinski	:	adjusted tcp_readable() to fix FIONREAD
 *	Willy Konynenberg	:	Transparent proxying support.
 *	Mike McLagan		:	Routing by source
 *		Keith Owens	:	Do proper merging with partial SKB's in
 *					tcp_do_sendmsg to avoid burstiness.
 *		Eric Schenk	:	Fix fast close down bug with
 *					shutdown() followed by close().
 *		Andi Kleen 	:	Make poll agree with SIGIO
 *	Salvatore Sanfilippo	:	Support SO_LINGER with linger == 1 and
 *					lingertime == 0 (RFC 793 ABORT Call)
 *	Hirokazu Takahashi	:	Use copy_from_user() instead of
 *					csum_and_copy_from_user() if possible.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 *
 * Description of States:
 *
 *	TCP_SYN_SENT		sent a connection request, waiting for ack
 *
 *	TCP_SYN_RECV		received a connection request, sent ack,
 *				waiting for final ack in three-way handshake.
 *
 *	TCP_ESTABLISHED		connection established
 *
 *	TCP_FIN_WAIT1		our side has shutdown, waiting to complete
 *				transmission of remaining buffered data
 *
 *	TCP_FIN_WAIT2		all buffered data sent, waiting for remote
 *				to shutdown
 *
 *	TCP_CLOSING		both sides have shutdown but we still have
 *				data we have to finish sending
 *
 *	TCP_TIME_WAIT		timeout to catch resent junk before entering
 *				closed, can only be entered from FIN_WAIT2
 *				or CLOSING.  Required because the other end
 *				may not have gotten our last ACK causing it
 *				to retransmit the data packet (which we ignore)
 *
 *	TCP_CLOSE_WAIT		remote side has shutdown and is waiting for
 *				us to finish writing our data and to shutdown
 *				(we have to close() to move on to LAST_ACK)
 *
 *	TCP_LAST_ACK		out side has shutdown after remote has
 *				shutdown.  There may still be data in our
 *				buffer that we have to finish sending
 *
 *	TCP_CLOSE		socket is finished
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/bootmem.h>
#include <linux/cache.h>
#include <linux/err.h>
#include <linux/crypto.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/netdma.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

int sysctl_tcp_fin_timeout __read_mostly = TCP_FIN_TIMEOUT;

DEFINE_SNMP_STAT(struct tcp_mib, tcp_statistics) __read_mostly;

atomic_t tcp_orphan_count = ATOMIC_INIT(0);

EXPORT_SYMBOL_GPL(tcp_orphan_count);

int sysctl_tcp_mem[3] __read_mostly;
int sysctl_tcp_wmem[3] __read_mostly;
int sysctl_tcp_rmem[3] __read_mostly;

EXPORT_SYMBOL(sysctl_tcp_mem);
EXPORT_SYMBOL(sysctl_tcp_rmem);
EXPORT_SYMBOL(sysctl_tcp_wmem);

atomic_t tcp_memory_allocated;	/* Current allocated memory. */
atomic_t tcp_sockets_allocated;	/* Current number of TCP sockets. */

EXPORT_SYMBOL(tcp_memory_allocated);
EXPORT_SYMBOL(tcp_sockets_allocated);

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the sk_stream_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int tcp_memory_pressure;

EXPORT_SYMBOL(tcp_memory_pressure);

void tcp_enter_memory_pressure(void)
{
	if (!tcp_memory_pressure) {
		NET_INC_STATS(LINUX_MIB_TCPMEMORYPRESSURES);
		tcp_memory_pressure = 1;
	}
}

EXPORT_SYMBOL(tcp_enter_memory_pressure);

/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	poll_wait(file, sk->sk_sleep, wait);
	if (sk->sk_state == TCP_LISTEN)
		return inet_csk_listen_poll(sk);

	/* Socket is not locked. We are protected from async events
	   by poll logic and correct handling of state changes
	   made by another threads is impossible in any case.
	 */

	mask = 0;
	if (sk->sk_err)
		mask = POLLERR;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if PULLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why PULLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if ((tp->rcv_nxt != tp->copied_seq) &&
		    (tp->urg_seq != tp->copied_seq ||
		     tp->rcv_nxt != tp->copied_seq + 1 ||
		     sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data))
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}

		if (tp->urg_data & TCP_URG_VALID)
			mask |= POLLPRI;
	}
	return mask;
}

int tcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int answ;

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !tp->urg_data ||
			 before(tp->urg_seq, tp->copied_seq) ||
			 !before(tp->urg_seq, tp->rcv_nxt)) {
			answ = tp->rcv_nxt - tp->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			if (answ && !skb_queue_empty(&sk->sk_receive_queue))
				answ -=
		       ((struct sk_buff *)sk->sk_receive_queue.prev)->h.th->fin;
		} else
			answ = tp->urg_seq - tp->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:
		answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_una;
		break;
	default:
		return -ENOIOCTLCMD;
	};

	return put_user(answ, (int __user *)arg);
}

static inline void tcp_mark_push(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static inline void skb_entail(struct sock *sk, struct tcp_sock *tp,
			      struct sk_buff *skb)
{
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->flags   = TCPCB_FLAG_ACK;
	tcb->sacked  = 0;
	skb_header_release(skb);
	__skb_queue_tail(&sk->sk_write_queue, skb);
	sk_charge_skb(sk, skb);
	if (!sk->sk_send_head)
		sk->sk_send_head = skb;
	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH; 
}

static inline void tcp_mark_urg(struct tcp_sock *tp, int flags,
				struct sk_buff *skb)
{
	if (flags & MSG_OOB) {
		tp->urg_mode = 1;
		tp->snd_up = tp->write_seq;
		TCP_SKB_CB(skb)->sacked |= TCPCB_URG;
	}
}

static inline void tcp_push(struct sock *sk, struct tcp_sock *tp, int flags,
			    int mss_now, int nonagle)
{
	if (sk->sk_send_head) {
		struct sk_buff *skb = sk->sk_write_queue.prev;
		if (!(flags & MSG_MORE) || forced_push(tp))
			tcp_mark_push(tp, skb);
		tcp_mark_urg(tp, flags, skb);
		__tcp_push_pending_frames(sk, tp, mss_now,
					  (flags & MSG_MORE) ? TCP_NAGLE_CORK : nonagle);
	}
}

static ssize_t do_tcp_sendpages(struct sock *sk, struct page **pages, int poffset,
			 size_t psize, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now, size_goal;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
	size_goal = tp->xmit_size_goal;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (psize > 0) {
		struct sk_buff *skb = sk->sk_write_queue.prev;
		struct page *page = pages[poffset / PAGE_SIZE];
		int copy, i, can_coalesce;
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		if (!sk->sk_send_head || (copy = size_goal - skb->len) <= 0) {
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			skb = sk_stream_alloc_pskb(sk, 0, 0,
						   sk->sk_allocation);
			if (!skb)
				goto wait_for_memory;

			skb_entail(sk, tp, skb);
			copy = size_goal;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= MAX_SKB_FRAGS) {
			tcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (!sk_stream_wmem_schedule(sk, copy))
			goto wait_for_memory;
		
		if (can_coalesce) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk->sk_forward_alloc -= copy;
		skb->ip_summed = CHECKSUM_PARTIAL;
		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		skb_shinfo(skb)->gso_segs = 0;

		if (!copied)
			TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

		copied += copy;
		poffset += copy;
		if (!(psize -= copy))
			goto out;

		if (skb->len < mss_now || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, tp, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == sk->sk_send_head)
			tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			tcp_push(sk, tp, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

		if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
			goto do_error;

		mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
		size_goal = tp->xmit_size_goal;
	}

out:
	if (copied)
		tcp_push(sk, tp, flags, mss_now, tp->nonagle);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	return sk_stream_error(sk, flags, err);
}

ssize_t tcp_sendpage(struct socket *sock, struct page *page, int offset,
		     size_t size, int flags)
{
	ssize_t res;
	struct sock *sk = sock->sk;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM))
		return sock_no_sendpage(sock, page, offset, size, flags);

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);
	res = do_tcp_sendpages(sk, &page, offset, size, flags);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return res;
}

#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)

static inline int select_size(struct sock *sk, struct tcp_sock *tp)
{
	int tmp = tp->mss_cache;

	if (sk->sk_route_caps & NETIF_F_SG) {
		if (sk_can_gso(sk))
			tmp = 0;
		else {
			int pgbreak = SKB_MAX_HEAD(MAX_TCP_HEADER);

			if (tmp >= pgbreak &&
			    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
				tmp = pgbreak;
		}
	}

	return tmp;
}

int tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t size)
{
	struct iovec *iov;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	// mss_now存放当前打开的套接字最大段的长度，该值通常与MTU有关
	int mss_now, size_goal;
	int err, copied;
	// 存放SO_SENDTIMEO（套接字设定的传送超时的时间）选项，除设置了MSG_DONTWAIT标志外
	long timeo;

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	// 在开始传送数据之前，首先应与通信端建立连接，如果当前打开的套接字状态不是TCPF_ESTABLISHED
	// 或TCPF_CLOSE_WAIT，说明tcp协议实例还没有准备好传送数据，它必须等待连接建立起来。由SO_SENDTIMEO
	// 套接字选项设定等待连接超时的时间值作为参数，传给等待连接建立函数sk_stream_wait_connect
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	// mss_now当前套接字可发送的最大tcp数据段的大小，这是根据mtu设定的
	mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
	size_goal = tp->xmit_size_goal;

	/* Ok commence sending. */
	// 提取发送数据地址和发送数据总数信息
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	// 准备从用户地址空间复制数据，设定与复制相关的参数
	while (--iovlen >= 0) {
		int seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;

		while (seglen > 0) {
			int copy;

			skb = sk->sk_write_queue.prev;	// 指向队列中最后一个skb

			if (!sk->sk_send_head ||
			    (copy = size_goal - skb->len) <= 0) {	// 队列中还没有skb或者剩余空间不足

new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;			// 如果已无内存可供分配，等待新的内存空间释放

				skb = sk_stream_alloc_pskb(sk, select_size(sk, tp),
							   0, sk->sk_allocation);	// 分配skb
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				// 设置skb的某些数据域，如校验和计算方式，看网络硬件设备是否可计算校验和
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
					skb->ip_summed = CHECKSUM_PARTIAL;

				// 将skb放入队列
				skb_entail(sk, tp, skb);
				copy = size_goal;
			}

			/* Try to append data to the end of skb. */
			// copy代表了本次复制的数据量
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {		// skb_tailroom(skb)就是用于判断skb的缓冲区是否还有剩余空间
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);
				// skb_add_data完成具体的数据复制操作
				if ((err = skb_add_data(skb, from, copy)) != 0)
					goto do_fault;
			} else {
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TCP_PAGE(sk);
				int off = TCP_OFF(sk);

				// skb_can_coalesce用于计算页面中是否仍有剩余空间接收新的数据
				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == MAX_SKB_FRAGS ||
					   (!i &&
					   !(sk->sk_route_caps & NETIF_F_SG))) {
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					// 如果struct skb_shared_info的页面数组中所有页面已填满，并且nr_frags=MAX_SKB_FRAGS
					// 即页面数据量已达到最大值，当前tcp段已不能再容纳更多数据，设置当前数据段tcp头的PSH标志
					// 表明当前数据段已可以发送
					tcp_mark_push(tp, skb);
					goto new_segment;
				} else if (page) {
					if (off == PAGE_SIZE) {
						put_page(page);
						TCP_PAGE(sk) = page = NULL;
						off = 0;
					}
				} else
					off = 0;

				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				if (!sk_stream_wmem_schedule(sk, copy))
					goto wait_for_memory;

				if (!page) {
					/* Allocate new cache page. */
					// 由sk_stream_alloc_page完成新页面的分配
					if (!(page = sk_stream_alloc_page(sk)))
						goto wait_for_memory;
				}

				/* Time to copy data. We are close to
				 * the end! */
				// skb_copy_to_page完成将数据复制到页面的操作
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (err) {
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				if (merge) {
					// merge为1，说明数据合并到了struct skb_shared_info数据结构的frags页面数组
					// 的最后一个页面i中，需要对第i个页面管理数据结构中描述数据量大小的size域更新
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;
				} else {
					// 将数据复制到frags页面数组的新页面中，应更新struct skb_shared_info数据结构中
					// frags数组中的页面数量，以及新页面在数组中的偏移量。由skb_fill_page_desc函数
					// 填写新页面在frags中的描述信息
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TCP_PAGE(sk)) {
						get_page(page);
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TCP_PAGE(sk) = page;
					}
				}

				TCP_OFF(sk) = off + copy;
			}

			if (!copied)
				TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

			tp->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			skb_shinfo(skb)->gso_segs = 0;

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < mss_now || (flags & MSG_OOB))
				continue;

			if (forced_push(tp)) {
				// 立即发送：这时即使只是一个小的tcp数据段也立即向外发送。函数force_push用于查看是否立即
				// 发送数据段，如果立即发送，则调用tcp_mark_push函数设置tcp协议头中的PSH标志
				tcp_mark_push(tp, skb);
				__tcp_push_pending_frames(sk, tp, mss_now, TCP_NAGLE_PUSH);
			} else if (skb == sk->sk_send_head)
				tcp_push_one(sk, mss_now);
			continue;

// 如果队列中还没有足够的缓冲区或页面，则等到有一定量的有效缓冲区后再发送
wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				tcp_push(sk, tp, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
			size_goal = tp->xmit_size_goal;
		}
	}

out:
	if (copied)
		tcp_push(sk, tp, flags, mss_now, tp->nonagle);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		if (sk->sk_send_head == skb)
			sk->sk_send_head = NULL;
		__skb_unlink(skb, &sk->sk_write_queue);
		sk_stream_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;
}

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int tcp_recv_urg(struct sock *sk, long timeo,
			struct msghdr *msg, int len, int flags,
			int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {
		int err = 0;
		char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time_to_ack = 0;

#if TCP_DEBUG
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

	BUG_TRAP(!skb || before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq));
#endif

	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}
	if (time_to_ack)
		tcp_send_ack(sk);
}

static void tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	NET_INC_STATS_USER(LINUX_MIB_TCPPREQUEUED);

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk->sk_backlog_rcv(sk, skb);
	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

static inline struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		offset = seq - TCP_SKB_CB(skb)->seq;
		if (skb->h.th->syn)
			offset--;
		if (offset < skb->len || skb->h.th->fin) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * This routine provides an alternative to tcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			size_t used, len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			if (offset != skb->len)
				break;
		}
		if (skb->h.th->fin) {
			sk_eat_skb(sk, skb, 0);
			++seq;
			break;
		}
		sk_eat_skb(sk, skb, 0);
		if (!desc->count)
			break;
	}
	tp->copied_seq = seq;

	tcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied)
		tcp_cleanup_rbuf(sk, copied);
	return copied;
}

/*
 *	This routine copies from a sock struct into the user buffer.
 *
 *	Technical note: in 2.3 we work on _locked_ socket, so that
 *	tricks with *seq access order and skb->users are not required.
 *	Probably, code can be easily improved even more.
 */

int tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int nonblock, int flags, int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct task_struct *user_recv = NULL;
	int copied_early = 0;

	lock_sock(sk);

	TCP_CHECK_TIMER(sk);

	err = -ENOTCONN;
	// 如果当前套接字处于侦听状态，说明还没有数据等待接收，跳出
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	/* Urgent data needs to be handled specially. */
	// 如果设置了MSG_OOB标志处理紧急数据（即输入段设置了URG标志），seq初始化为下一个准备读的字节
	// copied_seq中包含的是已处理的最后一个字节
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &tp->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	// 将本次读的字节数target，设置为sk->rcvlowat和len中小的值，MSG_WAITALL标志指明
	// 本次调用是否会阻塞
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	// 如果网络设备支持Scatter/Gather IO功能，内核配置了dma，则可以通过直接访问复制数据到
	// 用户地址空间
#ifdef CONFIG_NET_DMA
	tp->ucopy.dma_chan = NULL;
	preempt_disable();
	if ((len > sysctl_tcp_dma_copybreak) && !(flags & MSG_PEEK) &&
	    !sysctl_tcp_low_latency && __get_cpu_var(softnet_data).net_dma) {
		preempt_enable_no_resched();
		tp->ucopy.pinned_list = dma_pin_iovec_pages(msg->msg_iov, len);
	} else
		preempt_enable_no_resched();
#endif

	// do循环是tcp_recvmsg的主循环，在该循环中，我们将继续复制字节到用户地址空间，直到达到target
	// 或对输入数据段检测到了其他异常条件，退出循环
	do {
		struct sk_buff *skb;
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		// 如果复制了一些数据后，遇到紧急数据，则停止处理过程
		if (tp->urg_data && tp->urg_seq == *seq) {
			if (copied)
				break;
			// 这时检测该套接字上是否有信号等待处理，以确保能正确处理SIGUSR信号，接下来查看套接字是否超时
			// 如果超时则返回错误代码
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */
		// 获取接收队列上的第一个缓冲区指针，在do{}while循环内遍历接收队列直到发现第一个数据段，
		// 发现第一个数据段才知道有多少字节需要复制，跳到found_ok-skb的同时计算应从skb复制的字节数
		skb = skb_peek(&sk->sk_receive_queue);
		// 在循环内一直查看直到发现有效数据段，在此过程中查看FIN和SYN。如果发现SYN，则调整要复制的字节数
		// 从偏移量中减1，如果是FIN，跳出循环
		do {
			if (!skb)
				break;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			// 现在查看当前处理字节不在最近处理接收数据段的第一个字节前，这样可以判断当前处理是否
			// 超出当前队列数据包同步范围，这实际上是一个冗余检查，因为我们锁定了套接字，而且可以
			// 了解套接字有多少个队列防止数据丢失
			if (before(*seq, TCP_SKB_CB(skb)->seq)) {
				printk(KERN_INFO "recvmsg bug: copied %X "
				       "seq %X\n", *seq, TCP_SKB_CB(skb)->seq);
				break;
			}
			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (skb->h.th->syn)
				offset--;
			if (offset < skb->len)
				goto found_ok_skb;
			if (skb->h.th->fin)
				goto found_fin_ok;
			BUG_TRAP(flags & MSG_PEEK);
			skb = skb->next;
		} while (skb != (struct sk_buff *)&sk->sk_receive_queue);

		/* Well, if we have backlog, try to process it now yet. */
		// 程序运行到此说明套接字接收队列中已无数据，如果backlog队列中有数据包，则处理backlog队列中的数据
		if (copied >= target && !sk->sk_backlog.tail)
			break;
		// 这里必须做一些相应的检查看是否应停止处理数据包，看套接字是否已关闭或从远端收到断开连接请求
		// (在接收数据包中有RST标志)
		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current) ||
			    (flags & MSG_PEEK))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				// 当用户关闭了套接字，会设置SOCK_DONE标志，所以当连接状态是CLOSED时，其值为非零
				// 如果在CLOSED套接字上，则SOCK_DONE为非零，说明应用程序试图从一个从未建立起连接的
				// 套接字上读取数据，这是一个错误条件
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		tcp_cleanup_rbuf(sk, copied);
		// 这时在接收队列中已无数据段需要处理，我们将处理prequeue队列上的数据包，在此之前
		// 协议头预定向指明在连接为ESTABLISHED状态下可能收到有数据段。Prequeue队列是由
		// 用户进程现场处理而不是bottom half，将Ucopy.task设置为当前进程，current强制复制
		// prequeue队列中的数据段到用户空间
		if (!sysctl_tcp_low_latency && tp->ucopy.task == user_recv) {
			/* Install new reader */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {
				user_recv = current;
				tp->ucopy.task = user_recv;
				tp->ucopy.iov = msg->msg_iov;
			}

			tp->ucopy.len = len;

			BUG_TRAP(tp->copied_seq == tp->rcv_nxt ||
				 (flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */
			if (!skb_queue_empty(&tp->ucopy.prequeue))
				goto do_prequeue;

			/* __ Set realtime policy in scheduler __ */
		}

		if (copied >= target) {
			// 现在，处理backlog队列，看是否可能从该队列上直接复制数据，这时我们已经处理了prequeue
			// 队列，release_sock在唤醒等待在套接字上的用户进程前，先遍历backlog队列上的所有数据包
			// sk->backlog
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else
			// 如果已经没有数据要处理了，则等待新的数据到来，sk_wait_data把套接字放入等待状态
			sk_wait_data(sk, &timeo);

#ifdef CONFIG_NET_DMA
		tp->ucopy.wakeup = 0;
#endif

		if (user_recv) {
			int chunk;

			/* __ Restore normal policy in scheduler __ */
			// 计算在前面的步骤是否从backlog队列中直接复制了任何数据，也将进程调度器返回其正常状态
			if ((chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
				len -= chunk;
				copied += chunk;
			}

			if (tp->rcv_nxt == tp->copied_seq &&
			    !skb_queue_empty(&tp->ucopy.prequeue)) {
do_prequeue:
				// 处理prequeue队列处，由tcp_prequeue_process函数完成这项处理，调用此函数后
				// 调整从prequeue队列中已复制的数据量
				tcp_prequeue_process(sk);

				if ((chunk = len - tp->ucopy.len) != 0) {
					NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
					len -= chunk;
					copied += chunk;
				}
			}
		}
		if ((flags & MSG_PEEK) && peek_seq != tp->copied_seq) {
			if (net_ratelimit())
				printk(KERN_DEBUG "TCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, current->pid);
			peek_seq = tp->copied_seq;
		}
		continue;

	// 这里是在前面的循环中，我们发现在接收队列中有数据段时，就跳到此处，从skb->len数据域计算有多少数据域要复制
	// 以及它们的偏移量
	found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		/* Do we have urgent data here? */
		// 这时首先必须查看紧急数据，除非设置了套接字选项SO_OOBINLINE，这时我们不处理紧急数据，因为它已单独处理
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}

		// 复制数据到用户地址空间，如果在复制过程中有错，则返回EFAULT
		if (!(flags & MSG_TRUNC)) {
#ifdef CONFIG_NET_DMA
			if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
				tp->ucopy.dma_chan = get_softnet_dma();

			if (tp->ucopy.dma_chan) {
				tp->ucopy.dma_cookie = dma_skb_copy_datagram_iovec(
					tp->ucopy.dma_chan, skb, offset,
					msg->msg_iov, used,
					tp->ucopy.pinned_list);

				if (tp->ucopy.dma_cookie < 0) {

					printk(KERN_ALERT "dma_cookie < 0\n");

					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
				if ((offset + used) == skb->len)
					copied_early = 1;

			} else
#endif
			{
				err = skb_copy_datagram_iovec(skb, offset,
						msg->msg_iov, used);
				if (err) {
					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
			}
		}

		*seq += used;
		copied += used;
		len -= used;

		tcp_rcv_space_adjust(sk);

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			tp->urg_data = 0;
			// 现在处理完了紧急数据，转到Fast Path上，如果输入处理遇到有紧急数据的段
			// 则Fast Path会关闭
			tcp_fast_path_check(sk, tp);
		}
		if (used + offset < skb->len)
			continue;

		if (skb->h.th->fin)
			goto found_fin_ok;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		continue;

	// 如果在接收队列中的数据包有FIN标志，跳入此处，按照rfc793，必须在序列号中计算FIN的一个字节
	// 并重新计算TCP窗口
	found_fin_ok:
		/* Process the FIN. */
		++*seq;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		break;
	} while (len > 0);

	// 处于while循环体外处理套接字，直到满足应用程序调用要求的数据总量len，如果现在跳出了循环
	// 但仍在prequeue队列中留下了数据，则现在必须进行处理
	if (user_recv) {
		if (!skb_queue_empty(&tp->ucopy.prequeue)) {
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;

			tcp_prequeue_process(sk);

			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
				len -= chunk;
				copied += chunk;
			}
		}

		tp->ucopy.task = NULL;
		tp->ucopy.len = 0;
	}

#ifdef CONFIG_NET_DMA
	if (tp->ucopy.dma_chan) {
		struct sk_buff *skb;
		dma_cookie_t done, used;

		dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

		while (dma_async_memcpy_complete(tp->ucopy.dma_chan,
		                                 tp->ucopy.dma_cookie, &done,
		                                 &used) == DMA_IN_PROGRESS) {
			/* do partial cleanup of sk_async_wait_queue */
			while ((skb = skb_peek(&sk->sk_async_wait_queue)) &&
			       (dma_async_is_complete(skb->dma_cookie, done,
			                              used) == DMA_SUCCESS)) {
				__skb_dequeue(&sk->sk_async_wait_queue);
				kfree_skb(skb);
			}
		}

		/* Safe to free early-copied skbs now */
		__skb_queue_purge(&sk->sk_async_wait_queue);
		dma_chan_put(tp->ucopy.dma_chan);
		tp->ucopy.dma_chan = NULL;
	}
	if (tp->ucopy.pinned_list) {
		dma_unpin_iovec_pages(tp->ucopy.pinned_list);
		tp->ucopy.pinned_list = NULL;
	}
#endif

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	// cleanup_rbuf清楚tcp接收缓冲区，如果需要它也会发送ack
	tcp_cleanup_rbuf(sk, copied);

	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return copied;

	// 处理完成，释放套接字，跳出
out:
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;

	// 在处理数据段时遇到紧急数据，跳到此片，tcp_recv_urg复制紧急数据到用户地址空间
recv_urg:
	err = tcp_recv_urg(sk, timeo, msg, len, flags, addr_len);
	goto out;
}

/*
 *	State processing on a close. This implements the state shift for
 *	sending our FIN frame. Note that we only send a FIN for some
 *	states. A shutdown() may have already sent the FIN, or we may be
 *	closed.
 */

static const unsigned char new_state[16] = {
  /* current state:        new state:      action:	*/
  /* (Invalid)		*/ TCP_CLOSE,
  /* TCP_ESTABLISHED	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_SYN_SENT	*/ TCP_CLOSE,
  /* TCP_SYN_RECV	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_FIN_WAIT1	*/ TCP_FIN_WAIT1,
  /* TCP_FIN_WAIT2	*/ TCP_FIN_WAIT2,
  /* TCP_TIME_WAIT	*/ TCP_CLOSE,
  /* TCP_CLOSE		*/ TCP_CLOSE,
  /* TCP_CLOSE_WAIT	*/ TCP_LAST_ACK  | TCP_ACTION_FIN,
  /* TCP_LAST_ACK	*/ TCP_LAST_ACK,
  /* TCP_LISTEN		*/ TCP_CLOSE,
  /* TCP_CLOSING	*/ TCP_CLOSING,
};

static int tcp_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];
	int ns = next & TCP_STATE_MASK;

	tcp_set_state(sk, ns);

	return next & TCP_ACTION_FIN;
}

/*
 *	Shutdown the sending side of a connection. Much like close except
 *	that we don't receive shut down or set_sock_flag(sk, SOCK_DEAD).
 */

void tcp_shutdown(struct sock *sk, int how)
{
	/*	We need to grab some memory, and put together a FIN,
	 *	and then put it into the queue to be sent.
	 *		Tim MacKenzie(tym@dibbler.cs.monash.edu.au) 4 Dec '92.
	 */
	if (!(how & SEND_SHUTDOWN))
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
		/* Clear out any half completed packets.  FIN if needed. */
		if (tcp_close_state(sk))
			tcp_send_fin(sk);
	}
}

void tcp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  skb->h.th->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_stream_mem_reclaim(sk);

	/* As outlined in draft-ietf-tcpimpl-prob-03.txt, section
	 * 3.10, we send a RST here because data was lost.  To
	 * witness the awful effects of the old behavior of always
	 * doing a FIN, run an older 2.1.x kernel or 2.0.x, start
	 * a bulk GET in an FTP client, suspend the process, wait
	 * for the client to advertise a zero window, then kill -9
	 * the FTP client, wheee...  Note: timeout is always zero
	 * in such a case.
	 */
	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, GFP_KERNEL);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(sk)) {
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TCP_ESTABLISHED, TCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 */
		tcp_send_fin(sk);
	}

	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);
	atomic_inc(sk->sk_prot->orphan_count);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);


	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	BUG_TRAP(!sock_owned_by_user(sk));

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (sk->sk_state == TCP_FIN_WAIT2) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->linger2 < 0) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
			} else {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_stream_mem_reclaim(sk);
		if (atomic_read(sk->sk_prot->orphan_count) > sysctl_tcp_max_orphans ||
		    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
		     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {
			if (net_ratelimit())
				printk(KERN_INFO "TCP: too many of orphaned "
				       "sockets\n");
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		}
	}

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/* These states need RST on ABORT according to RFC793 */

static inline int tcp_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
		TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

int tcp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err = 0;
	int old_state = sk->sk_state;

	if (old_state != TCP_CLOSE)
		tcp_set_state(sk, TCP_CLOSE);

	/* ABORT function of RFC793 */
	if (old_state == TCP_LISTEN) {
		inet_csk_listen_stop(sk);
	} else if (tcp_need_reset(old_state) ||
		   (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		/* The last check adjusts for discrepancy of Linux wrt. RFC
		 * states
		 */
		tcp_send_active_reset(sk, gfp_any());
		sk->sk_err = ECONNRESET;
	} else if (old_state == TCP_SYN_SENT)
		sk->sk_err = ECONNRESET;

	tcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	sk_stream_writequeue_purge(sk);
	__skb_queue_purge(&tp->out_of_order_queue);
#ifdef CONFIG_NET_DMA
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif

	inet->dport = 0;

	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	icsk->icsk_backoff = 0;
	tp->snd_cwnd = 2;
	icsk->icsk_probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = 0x7fffffff;
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	tcp_set_ca_state(sk, TCP_CA_Open);
	tcp_clear_retrans(tp);
	inet_csk_delack_init(sk);
	sk->sk_send_head = NULL;
	tp->rx_opt.saw_tstamp = 0;
	tcp_sack_reset(&tp->rx_opt);
	__sk_dst_reset(sk);

	BUG_TRAP(!inet->num || icsk->icsk_bind_hash);

	sk->sk_error_report(sk);
	return err;
}

/*
 *	Socket option code for TCP.
 */
static int do_tcp_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int val;
	int err = 0;

	/* This is a string value all the others are int's */
	if (optname == TCP_CONGESTION) {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min(TCP_CA_NAME_MAX-1, optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = tcp_set_congestion_control(sk, name);
		release_sock(sk);
		return err;
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_MAXSEG:
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used */
		if (val < 8 || val > MAX_TCP_WINDOW) {
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;
		break;

	case TCP_NODELAY:
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk, tp);
		} else {
			tp->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;

	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TCP_NAGLE_CORK;
			if (tp->nonagle&TCP_NAGLE_OFF)
				tp->nonagle |= TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk, tp);
		}
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TCPF_CLOSE | TCPF_LISTEN))) {
				__u32 elapsed = tcp_time_stamp - tp->rcv_tstamp;
				if (tp->keepalive_time > elapsed)
					elapsed = tp->keepalive_time - elapsed;
				else
					elapsed = 0;
				inet_csk_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TCP_KEEPINTVL:
		if (val < 1 || val > MAX_TCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ;
		break;
	case TCP_KEEPCNT:
		if (val < 1 || val > MAX_TCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val;
		break;
	case TCP_SYNCNT:
		if (val < 1 || val > MAX_TCP_SYNCNT)
			err = -EINVAL;
		else
			icsk->icsk_syn_retries = val;
		break;

	case TCP_LINGER2:
		if (val < 0)
			tp->linger2 = -1;
		else if (val > sysctl_tcp_fin_timeout / HZ)
			tp->linger2 = 0;
		else
			tp->linger2 = val * HZ;
		break;

	case TCP_DEFER_ACCEPT:
		icsk->icsk_accept_queue.rskq_defer_accept = 0;
		if (val > 0) {
			/* Translate value in seconds to number of
			 * retransmits */
			while (icsk->icsk_accept_queue.rskq_defer_accept < 32 &&
			       val > ((TCP_TIMEOUT_INIT / HZ) <<
				       icsk->icsk_accept_queue.rskq_defer_accept))
				icsk->icsk_accept_queue.rskq_defer_accept++;
			icsk->icsk_accept_queue.rskq_defer_accept++;
		}
		break;

	case TCP_WINDOW_CLAMP:
		if (!val) {
			if (sk->sk_state != TCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TCP_QUICKACK:
		if (!val) {
			icsk->icsk_ack.pingpong = 1;
		} else {
			icsk->icsk_ack.pingpong = 0;
			if ((1 << sk->sk_state) &
			    (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
			    inet_csk_ack_scheduled(sk)) {
				icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
				tcp_cleanup_rbuf(sk, 1);
				if (!(val & 1))
					icsk->icsk_ack.pingpong = 1;
			}
		}
		break;

#ifdef CONFIG_TCP_MD5SIG
	case TCP_MD5SIG:
		/* Read the IP->Key mappings from userspace */
		err = tp->af_specific->md5_parse(sk, optval, optlen);
		break;
#endif

	default:
		err = -ENOPROTOOPT;
		break;
	};
	release_sock(sk);
	return err;
}

// tcp_setsockopt()会根据选项的级别来选择不同的函数处理
int tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)
		return icsk->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_tcp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_setsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}

EXPORT_SYMBOL(compat_tcp_setsockopt);
#endif

/* Return information about state of tcp endpoint in API format. */
void tcp_get_info(struct sock *sk, struct tcp_info *info)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now = tcp_time_stamp;

	memset(info, 0, sizeof(*info));

	info->tcpi_state = sk->sk_state;
	info->tcpi_ca_state = icsk->icsk_ca_state;
	info->tcpi_retransmits = icsk->icsk_retransmits;
	info->tcpi_probes = icsk->icsk_probes_out;
	info->tcpi_backoff = icsk->icsk_backoff;

	if (tp->rx_opt.tstamp_ok)
		info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (tp->rx_opt.sack_ok)
		info->tcpi_options |= TCPI_OPT_SACK;
	if (tp->rx_opt.wscale_ok) {
		info->tcpi_options |= TCPI_OPT_WSCALE;
		info->tcpi_snd_wscale = tp->rx_opt.snd_wscale;
		info->tcpi_rcv_wscale = tp->rx_opt.rcv_wscale;
	} 

	if (tp->ecn_flags&TCP_ECN_OK)
		info->tcpi_options |= TCPI_OPT_ECN;

	info->tcpi_rto = jiffies_to_usecs(icsk->icsk_rto);
	info->tcpi_ato = jiffies_to_usecs(icsk->icsk_ack.ato);
	info->tcpi_snd_mss = tp->mss_cache;
	info->tcpi_rcv_mss = icsk->icsk_ack.rcv_mss;

	info->tcpi_unacked = tp->packets_out;
	info->tcpi_sacked = tp->sacked_out;
	info->tcpi_lost = tp->lost_out;
	info->tcpi_retrans = tp->retrans_out;
	info->tcpi_fackets = tp->fackets_out;

	info->tcpi_last_data_sent = jiffies_to_msecs(now - tp->lsndtime);
	info->tcpi_last_data_recv = jiffies_to_msecs(now - icsk->icsk_ack.lrcvtime);
	info->tcpi_last_ack_recv = jiffies_to_msecs(now - tp->rcv_tstamp);

	info->tcpi_pmtu = icsk->icsk_pmtu_cookie;
	info->tcpi_rcv_ssthresh = tp->rcv_ssthresh;
	info->tcpi_rtt = jiffies_to_usecs(tp->srtt)>>3;
	info->tcpi_rttvar = jiffies_to_usecs(tp->mdev)>>2;
	info->tcpi_snd_ssthresh = tp->snd_ssthresh;
	info->tcpi_snd_cwnd = tp->snd_cwnd;
	info->tcpi_advmss = tp->advmss;
	info->tcpi_reordering = tp->reordering;

	info->tcpi_rcv_rtt = jiffies_to_usecs(tp->rcv_rtt_est.rtt)>>3;
	info->tcpi_rcv_space = tp->rcvq_space.space;

	info->tcpi_total_retrans = tp->total_retrans;
}

EXPORT_SYMBOL_GPL(tcp_get_info);

static int do_tcp_getsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_MAXSEG:
		val = tp->mss_cache;
		if (!val && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		break;
	case TCP_NODELAY:
		val = !!(tp->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(tp->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = (tp->keepalive_time ? : sysctl_tcp_keepalive_time) / HZ;
		break;
	case TCP_KEEPINTVL:
		val = (tp->keepalive_intvl ? : sysctl_tcp_keepalive_intvl) / HZ;
		break;
	case TCP_KEEPCNT:
		val = tp->keepalive_probes ? : sysctl_tcp_keepalive_probes;
		break;
	case TCP_SYNCNT:
		val = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		break;
	case TCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : sysctl_tcp_fin_timeout) / HZ;
		break;
	case TCP_DEFER_ACCEPT:
		val = !icsk->icsk_accept_queue.rskq_defer_accept ? 0 :
			((TCP_TIMEOUT_INIT / HZ) << (icsk->icsk_accept_queue.rskq_defer_accept - 1));
		break;
	case TCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TCP_INFO: {
		struct tcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		tcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUICKACK:
		val = !icsk->icsk_ack.pingpong;
		break;

	case TCP_CONGESTION:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TCP_CA_NAME_MAX);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_ca_ops->name, len))
			return -EFAULT;
		return 0;
	default:
		return -ENOPROTOOPT;
	};

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

int tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)
		return icsk->icsk_af_ops->getsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_tcp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_getsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}

EXPORT_SYMBOL(compat_tcp_getsockopt);
#endif

struct sk_buff *tcp_tso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct tcphdr *th;
	unsigned thlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int len;

	if (!pskb_may_pull(skb, sizeof(*th)))
		goto out;

	th = skb->h.th;
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */
		int type = skb_shinfo(skb)->gso_type;
		int mss;

		if (unlikely(type &
			     ~(SKB_GSO_TCPV4 |
			       SKB_GSO_DODGY |
			       SKB_GSO_TCP_ECN |
			       SKB_GSO_TCPV6 |
			       0) ||
			     !(type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))))
			goto out;

		mss = skb_shinfo(skb)->gso_size;
		skb_shinfo(skb)->gso_segs = (skb->len + mss - 1) / mss;

		segs = NULL;
		goto out;
	}

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	len = skb_shinfo(skb)->gso_size;
	delta = htonl(oldlen + (thlen + len));

	skb = segs;
	th = skb->h.th;
	seq = ntohl(th->seq);

	do {
		th->fin = th->psh = 0;

		th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				       (__force u32)delta));
		if (skb->ip_summed != CHECKSUM_PARTIAL)
			th->check = csum_fold(csum_partial(skb->h.raw, thlen,
							   skb->csum));

		seq += len;
		skb = skb->next;
		th = skb->h.th;

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	delta = htonl(oldlen + (skb->tail - skb->h.raw) + skb->data_len);
	th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				(__force u32)delta));
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		th->check = csum_fold(csum_partial(skb->h.raw, thlen,
						   skb->csum));

out:
	return segs;
}
EXPORT_SYMBOL(tcp_tso_segment);

#ifdef CONFIG_TCP_MD5SIG
static unsigned long tcp_md5sig_users;
static struct tcp_md5sig_pool **tcp_md5sig_pool;
static DEFINE_SPINLOCK(tcp_md5sig_pool_lock);

static void __tcp_free_md5sig_pool(struct tcp_md5sig_pool **pool)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct tcp_md5sig_pool *p = *per_cpu_ptr(pool, cpu);
		if (p) {
			if (p->md5_desc.tfm)
				crypto_free_hash(p->md5_desc.tfm);
			kfree(p);
			p = NULL;
		}
	}
	free_percpu(pool);
}

void tcp_free_md5sig_pool(void)
{
	struct tcp_md5sig_pool **pool = NULL;

	spin_lock(&tcp_md5sig_pool_lock);
	if (--tcp_md5sig_users == 0) {
		pool = tcp_md5sig_pool;
		tcp_md5sig_pool = NULL;
	}
	spin_unlock(&tcp_md5sig_pool_lock);
	if (pool)
		__tcp_free_md5sig_pool(pool);
}

EXPORT_SYMBOL(tcp_free_md5sig_pool);

static struct tcp_md5sig_pool **__tcp_alloc_md5sig_pool(void)
{
	int cpu;
	struct tcp_md5sig_pool **pool;

	pool = alloc_percpu(struct tcp_md5sig_pool *);
	if (!pool)
		return NULL;

	for_each_possible_cpu(cpu) {
		struct tcp_md5sig_pool *p;
		struct crypto_hash *hash;

		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			goto out_free;
		*per_cpu_ptr(pool, cpu) = p;

		hash = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
		if (!hash || IS_ERR(hash))
			goto out_free;

		p->md5_desc.tfm = hash;
	}
	return pool;
out_free:
	__tcp_free_md5sig_pool(pool);
	return NULL;
}

struct tcp_md5sig_pool **tcp_alloc_md5sig_pool(void)
{
	struct tcp_md5sig_pool **pool;
	int alloc = 0;

retry:
	spin_lock(&tcp_md5sig_pool_lock);
	pool = tcp_md5sig_pool;
	if (tcp_md5sig_users++ == 0) {
		alloc = 1;
		spin_unlock(&tcp_md5sig_pool_lock);
	} else if (!pool) {
		tcp_md5sig_users--;
		spin_unlock(&tcp_md5sig_pool_lock);
		cpu_relax();
		goto retry;
	} else
		spin_unlock(&tcp_md5sig_pool_lock);

	if (alloc) {
		/* we cannot hold spinlock here because this may sleep. */
		struct tcp_md5sig_pool **p = __tcp_alloc_md5sig_pool();
		spin_lock(&tcp_md5sig_pool_lock);
		if (!p) {
			tcp_md5sig_users--;
			spin_unlock(&tcp_md5sig_pool_lock);
			return NULL;
		}
		pool = tcp_md5sig_pool;
		if (pool) {
			/* oops, it has already been assigned. */
			spin_unlock(&tcp_md5sig_pool_lock);
			__tcp_free_md5sig_pool(p);
		} else {
			tcp_md5sig_pool = pool = p;
			spin_unlock(&tcp_md5sig_pool_lock);
		}
	}
	return pool;
}

EXPORT_SYMBOL(tcp_alloc_md5sig_pool);

struct tcp_md5sig_pool *__tcp_get_md5sig_pool(int cpu)
{
	struct tcp_md5sig_pool **p;
	spin_lock(&tcp_md5sig_pool_lock);
	p = tcp_md5sig_pool;
	if (p)
		tcp_md5sig_users++;
	spin_unlock(&tcp_md5sig_pool_lock);
	return (p ? *per_cpu_ptr(p, cpu) : NULL);
}

EXPORT_SYMBOL(__tcp_get_md5sig_pool);

void __tcp_put_md5sig_pool(void)
{
	tcp_free_md5sig_pool();
}

EXPORT_SYMBOL(__tcp_put_md5sig_pool);
#endif

extern void __skb_cb_too_small_for_tcp(int, int);
extern struct tcp_congestion_ops tcp_reno;

static __initdata unsigned long thash_entries;
static int __init set_thash_entries(char *str)
{
	if (!str)
		return 0;
	thash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("thash_entries=", set_thash_entries);

void __init tcp_init(void)
{
	struct sk_buff *skb = NULL;
	unsigned long limit;
	int order, i, max_share;

	// skb中cb数组必须大于tcp_skb_cb结构的大小，因为tcp层会在cb中存储一个tcp_skb_cb结构
	if (sizeof(struct tcp_skb_cb) > sizeof(skb->cb))
		__skb_cb_too_small_for_tcp(sizeof(struct tcp_skb_cb),
					   sizeof(skb->cb));

	// 创建用于分配inet_bind_hashbucket结构的后备高速缓存，该结构主要用来存储管理已绑定端口的信息
	tcp_hashinfo.bind_bucket_cachep =
		kmem_cache_create("tcp_bind_bucket",
				  sizeof(struct inet_bind_bucket), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	/* Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	// 分配用于存储tcp状态为TCP_ESTABLISHED的传输控制块的散列表
	tcp_hashinfo.ehash =
		alloc_large_system_hash("TCP established",
					sizeof(struct inet_ehash_bucket),
					thash_entries,
					(num_physpages >= 128 * 1024) ?
					13 : 15,
					0,
					&tcp_hashinfo.ehash_size,
					NULL,
					0);
	// 根据thash得到散列表的大小ehash_size，thash_entries作为内核参数，是TCP_ESTABLISHED状态
	// tcp套接口散列表允许使用的大小
	tcp_hashinfo.ehash_size = (1 << tcp_hashinfo.ehash_size) >> 1;
	// 初始化ehash散列表
	for (i = 0; i < (tcp_hashinfo.ehash_size << 1); i++) {
		rwlock_init(&tcp_hashinfo.ehash[i].lock);
		INIT_HLIST_HEAD(&tcp_hashinfo.ehash[i].chain);
	}

	// 分配用于存储已绑定端口信息的散列表，并根据ehash_size（在创建ehash散列表时得到）
	// 得到散列表的大小bhash_size
	tcp_hashinfo.bhash =
		alloc_large_system_hash("TCP bind",
					sizeof(struct inet_bind_hashbucket),
					tcp_hashinfo.ehash_size,
					(num_physpages >= 128 * 1024) ?
					13 : 15,
					0,
					&tcp_hashinfo.bhash_size,
					NULL,
					64 * 1024);
	tcp_hashinfo.bhash_size = 1 << tcp_hashinfo.bhash_size;
	// 初始化bhash散列表
	for (i = 0; i < tcp_hashinfo.bhash_size; i++) {
		spin_lock_init(&tcp_hashinfo.bhash[i].lock);
		INIT_HLIST_HEAD(&tcp_hashinfo.bhash[i].chain);
	}

	/* Try to be a bit smarter and adjust defaults depending
	 * on available memory.
	 */
	// 根据bhash_size来计算order的值，order用来确定如何设置可分配端口的区间
	// bhash_size的值最终由系统参数thash_entries确定，这是各应用策略问题，如果用作网络服务器
	// 则thash_entries参数应设置得大一些，而如果作为一般桌面系统或嵌入式系统，则thash_entries参数
	// 应设置地小一些，当然该区间在系统运行期也是可以修改的
	for (order = 0; ((1 << order) << PAGE_SHIFT) <
			(tcp_hashinfo.bhash_size * sizeof(struct inet_bind_hashbucket));
			order++)
		;
	// 由于order表示系统能提供资源的多少，因此需根据order的大小来设置可绑定端口的区间，保持在TIME_WAIT状态
	// 下的套接口的最大数max_tw_buckets、系统所能处理不属于任何进程的孤儿套接口的最大数tcp_max_orphans
	// 以及系统可以同时存在未完成三次握手的SYN请求的最大数max_syn_backlog
	if (order >= 4) {
		sysctl_local_port_range[0] = 32768;
		sysctl_local_port_range[1] = 61000;
		tcp_death_row.sysctl_max_tw_buckets = 180000;
		sysctl_tcp_max_orphans = 4096 << (order - 4);
		sysctl_max_syn_backlog = 1024;
	} else if (order < 3) {
		sysctl_local_port_range[0] = 1024 * (3 - order);
		tcp_death_row.sysctl_max_tw_buckets >>= (3 - order);
		sysctl_tcp_max_orphans >>= (3 - order);
		sysctl_max_syn_backlog = 128;
	}

	/* Allow no more than 3/4 kernel memory (usually less) allocated to TCP */
	// 初始化系统控制参数tcp_mem，是一组用于控制tcp栈缓存使用的阈值，参见tcp_mem系统参数
	sysctl_tcp_mem[0] = (1536 / sizeof (struct inet_bind_hashbucket)) << order;
	sysctl_tcp_mem[1] = sysctl_tcp_mem[0] * 4 / 3;
	sysctl_tcp_mem[2] = sysctl_tcp_mem[0] * 2;

	limit = ((unsigned long)sysctl_tcp_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL*1024*1024, limit);

	// 初始化系统参数tcp_wmem和tcp_rmem
	sysctl_tcp_wmem[0] = SK_STREAM_MEM_QUANTUM;
	sysctl_tcp_wmem[1] = 16*1024;
	sysctl_tcp_wmem[2] = max(64*1024, max_share);

	sysctl_tcp_rmem[0] = SK_STREAM_MEM_QUANTUM;
	sysctl_tcp_rmem[1] = 87380;
	sysctl_tcp_rmem[2] = max(87380, max_share);

	printk(KERN_INFO "TCP: Hash tables configured "
	       "(established %d bind %d)\n",
	       tcp_hashinfo.ehash_size << 1, tcp_hashinfo.bhash_size);

	// 向tcp传输控制块中注册reno拥塞控制算法，这是系统默认的拥塞控制算法
	tcp_register_congestion_control(&tcp_reno);
}

EXPORT_SYMBOL(tcp_close);
EXPORT_SYMBOL(tcp_disconnect);
EXPORT_SYMBOL(tcp_getsockopt);
EXPORT_SYMBOL(tcp_ioctl);
EXPORT_SYMBOL(tcp_poll);
EXPORT_SYMBOL(tcp_read_sock);
EXPORT_SYMBOL(tcp_recvmsg);
EXPORT_SYMBOL(tcp_sendmsg);
EXPORT_SYMBOL(tcp_sendpage);
EXPORT_SYMBOL(tcp_setsockopt);
EXPORT_SYMBOL(tcp_shutdown);
EXPORT_SYMBOL(tcp_statistics);
