/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>

#ifdef INET_CSK_DEBUG
const char inet_csk_timer_bug_msg[] = "inet_csk BUG: unknown timer value\n";
EXPORT_SYMBOL(inet_csk_timer_bug_msg);
#endif

/*
 * This array holds the first and last local port number.
 * For high-usage systems, use sysctl to change this to
 * 32768-61000
 */
int sysctl_local_port_range[2] = { 1024, 4999 };

int inet_csk_bind_conflict(const struct sock *sk,
			   const struct inet_bind_bucket *tb)
{
	const __be32 sk_rcv_saddr = inet_rcv_saddr(sk);
	struct sock *sk2;
	struct hlist_node *node;
	int reuse = sk->sk_reuse;

	sk_for_each_bound(sk2, node, &tb->owners) {
		if (sk != sk2 &&
		    !inet_v6_ipv6only(sk2) &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {
			if (!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == TCP_LISTEN) {
				const __be32 sk2_rcv_saddr = inet_rcv_saddr(sk2);
				if (!sk2_rcv_saddr || !sk_rcv_saddr ||
				    sk2_rcv_saddr == sk_rcv_saddr)
					break;
			}
		}
	}
	return node != NULL;
}

EXPORT_SYMBOL_GPL(inet_csk_bind_conflict);

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 */
// bind系统调用通过套接口层的inet_bind()之后，便会调用传输层的函数，tcp中的传输层接口函数为
// tcp_v4_get_port，它只是起了承上启下的作用，实现了接口并调用功能实现函数inet_csk_get_port()
// 如果待绑定的本地端口为0，则自动为套接口分配一个可用的端口
// hashinfo：tcp散列表管理结构实例tcp_hashinfo
// sk：当前进行绑定操作的传输控制块
// snum：进行绑定的端口号
// bind_conflict：一个函数指针，用来在指定端口信息块的传输控制块链表上查找是否存在与待绑定传输控制块相冲突
// 的传输控制块，tcp中使用的比较函数为inet_csk_bind_conflict()
int inet_csk_get_port(struct inet_hashinfo *hashinfo,
		      struct sock *sk, unsigned short snum,
		      int (*bind_conflict)(const struct sock *sk,
					   const struct inet_bind_bucket *tb))
{
	struct inet_bind_hashbucket *head;
	struct hlist_node *node;
	struct inet_bind_bucket *tb;
	int ret;

	local_bh_disable();
	if (!snum) {
		// 如果端口号没有指定
		// 取得端口号的使用范围
		// int sysctl_local_port_range[2] = {32768, 61000}
		int low = sysctl_local_port_range[0];
		int high = sysctl_local_port_range[1];
		// 重试分配次数remaining
		int remaining = (high - low) + 1;
		// 随机生成一个在分配区间内的起始端口号rover
		int rover = net_random() % (high - low) + low;

		do {
			// 在内核中查找一个端口号
			head = &hashinfo->bhash[inet_bhashfn(rover, hashinfo->bhash_size)];
			spin_lock(&head->lock);
			inet_bind_bucket_for_each(tb, node, &head->chain)
				if (tb->port == rover)
					goto next;
			break;
		next:
			spin_unlock(&head->lock);
			if (++rover > high)
				rover = low;
		} while (--remaining > 0);

		/* Exhausted local port range during search?  It is not
		 * possible for us to be holding one of the bind hash
		 * locks if this test triggers, because if 'remaining'
		 * drops to zero, we broke out of the do/while loop at
		 * the top level, not from the 'break;' statement.
		 */
		ret = 1;
		// 到此为止，获取空闲端口已完成，但成功与否尚不清楚，因此先初始化返回值为1，如果所有尝试
		// 次数都已用完，则说明获取端口失败，跳转到fail处直接返回失败退出，否则说明获取端口成功
		if (remaining <= 0)
			goto fail;

		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 */
		// snum指向最终的推荐端口号
		snum = rover;
	} else {
		// 在哈希桶队列中查找相同端口的桶结构
		head = &hashinfo->bhash[inet_bhashfn(snum, hashinfo->bhash_size)];
		spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, node, &head->chain)
			if (tb->port == snum)
				goto tb_found;
	}
	tb = NULL;
	goto tb_not_found;
tb_found:
	// 确定此端口号是否有对应的传输控制块，也就是是否有应用程序在使用该端口号
	// 如果没有，则直接跳转到tb_not_found处处理
	if (!hlist_empty(&tb->owners)) {	// 检查sock队列是否为空
		// 如果传输控制块可以强制复用端口，则不必检测端口能否被复用，跳转到success处进行绑定处理
		if (sk->sk_reuse > 1)
			goto success;
		// 如果端口可以被复用，传输控制块可复用端口且不处于侦听状态，则表示可使用该端口，跳转到success处作处理
		if (tb->fastreuse > 0 &&
		    sk->sk_reuse && sk->sk_state != TCP_LISTEN) {
			goto success;
		} else {
			ret = 1;	// 桶结构中的sock队列是否存在冲突
			// 其他情况，则调用bind_conflict()检测复用端口是否冲突，如有冲突则跳转到fail_unlock处作处理
			// 否则跳转到tb_not_found处作处理
			if (bind_conflict(sk, tb))
				goto fail_unlock;
		}
	}
tb_not_found:	// 如果桶结构不存在就创建
	ret = 1;
	// 处理没有找到的情况，创建新的绑定端口信息，然后根据条件确定是否能复用它
	if (!tb && (tb = inet_bind_bucket_create(hashinfo->bind_bucket_cachep, head, snum)) == NULL)
		goto fail_unlock;
	if (hlist_empty(&tb->owners)) {	// 如果sock队列为空
		// 如果此端口还没有被绑定，待绑定的传输控制块允许端口复用，且不处在侦听状态
		// 则端口可以被复用，否则不能复用
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
			tb->fastreuse = 1;	// 设置桶结构可以复用
		else
			tb->fastreuse = 0;
		// 如果此端口已经被绑定，即使该端口可以被复用，但传输控制块不可复用端口或处于侦听状态
		// 则此端口也不能被复用
	} else if (tb->fastreuse &&
		   (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
		tb->fastreuse = 0;
success:	// 如果还没有绑定桶结构
	if (!inet_csk(sk)->icsk_bind_hash)
		// 设置传输控制块的端口，将传输控制块加入到端口信息块的传输控制块链表中
		inet_bind_hash(sk, tb, snum);	// 绑定桶结构
	// 设置传输控制块的端口信息
	BUG_TRAP(inet_csk(sk)->icsk_bind_hash == tb);
 	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}

EXPORT_SYMBOL_GPL(inet_csk_get_port);

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
// inet_csk_wait_for_connect()中用于侦听的传输控制块在指定的时间内等待新的连接
// 直至建立新的连接，或等到超时，或者收到某个信号等其他请求
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	DEFINE_WAIT(wait);
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk->sk_sleep, &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo);
		lock_sock(sk);
		err = 0;
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk->sk_sleep, &wait);
	return err;
}

/*
 * This will accept the next outstanding connection.
 */
// inet_csk_accept()函数是accept系统调用传输层接口的实现，如果有完成连接的传输控制块
// 则将其从连接请求容器中取出，如果没有，则根据是否阻塞来决定返回或等待新连接
// flags：操作文件的标志，如O_NONBLOCK是最常用的
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sock *newsk;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	// accept调用只针对处于侦听状态的套接口，如果该套接口的状态不是LISTEN，则不能进行accept操作
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	// 如果该侦听套接口的已完成建立连接队列为空，则说明还没有收到新连接
	if (reqsk_queue_empty(&icsk->icsk_accept_queue)) {
		// 如果该套接口是非阻塞的，则直接返回而无需睡眠等待，否则在该套接口的超时时间内等待新连接
		// 如果超时时间到还没有等到新连接，则返回EAGAIN错误码
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}

	// 执行到此处，则肯定已接收了新的连接，因此需要从连接队列上将新的子传输控制块取出
	newsk = reqsk_queue_get_child(&icsk->icsk_accept_queue, sk);
	BUG_TRAP(newsk->sk_state != TCP_SYN_RECV);
out:
	release_sock(sk);
	return newsk;
out_err:
	newsk = NULL;
	*err = error;
	goto out;
}

EXPORT_SYMBOL(inet_csk_accept);

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies 
 * to optimize.
 */
// inet_csk_init_xmit_timers进行具体的初始化，主要是初始化inet_connection_sock
// 结构中的icsk_retransmit_timer和icsk_delack_timer，以及sock结构中的sk_timer定时器
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(unsigned long),
			       void (*delack_handler)(unsigned long),
			       void (*keepalive_handler)(unsigned long))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	// 初始化icsk_retransmit_timer、icsk_delack_timer以及sk_timer三个定时器
	init_timer(&icsk->icsk_retransmit_timer);
	init_timer(&icsk->icsk_delack_timer);
	init_timer(&sk->sk_timer);

	// 设置以上三个定时器的处理例程以及例程参数
	icsk->icsk_retransmit_timer.function = retransmit_handler;
	icsk->icsk_delack_timer.function     = delack_handler;
	sk->sk_timer.function		     = keepalive_handler;

	icsk->icsk_retransmit_timer.data = 
		icsk->icsk_delack_timer.data =
			sk->sk_timer.data  = (unsigned long)sk;

	// 初始化延时确认模式
	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}

EXPORT_SYMBOL(inet_csk_init_xmit_timers);

void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = icsk->icsk_ack.blocked = 0;

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}

EXPORT_SYMBOL(inet_csk_clear_xmit_timers);

void inet_csk_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

EXPORT_SYMBOL(inet_csk_delete_keepalive_timer);

void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

EXPORT_SYMBOL(inet_csk_reset_keepalive_timer);

struct dst_entry* inet_csk_route_req(struct sock *sk,
				     const struct request_sock *req)
{
	struct rtable *rt;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options *opt = inet_rsk(req)->opt;
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
			    .nl_u = { .ip4_u =
				      { .daddr = ((opt && opt->srr) ?
						  opt->faddr :
						  ireq->rmt_addr),
					.saddr = ireq->loc_addr,
					.tos = RT_CONN_FLAGS(sk) } },
			    .proto = sk->sk_protocol,
			    .uli_u = { .ports =
				       { .sport = inet_sk(sk)->sport,
					 .dport = ireq->rmt_port } } };

	security_req_classify_flow(req, &fl);
	if (ip_route_output_flow(&rt, &fl, sk, 0)) {
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway) {
		ip_rt_put(rt);
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	return &rt->u.dst;
}

EXPORT_SYMBOL_GPL(inet_csk_route_req);

static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return jhash_2words((__force u32)raddr, (__force u32)rport, rnd) & (synq_hsize - 1);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

struct request_sock *inet_csk_search_req(const struct sock *sk,
					 struct request_sock ***prevp,
					 const __be16 rport, const __be32 raddr,
					 const __be32 laddr)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	struct request_sock *req, **prev;

	for (prev = &lopt->syn_table[inet_synq_hash(raddr, rport, lopt->hash_rnd,
						    lopt->nr_table_entries)];
	     (req = *prev) != NULL;
	     prev = &req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			BUG_TRAP(!req->sk);
			*prevp = prev;
			break;
		}
	}

	return req;
}

EXPORT_SYMBOL_GPL(inet_csk_search_req);

// 在服务端，当侦听的套接口接收了一个新的连接请求后，会为该连接创建一个请求块，并将其添加到“父”传输控制块的连接
// 请求散列表中，最后启动连接建立定时器
void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr, inet_rsk(req)->rmt_port,
				     lopt->hash_rnd, lopt->nr_table_entries);

	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
	inet_csk_reqsk_queue_added(sk, timeout);
}

/* Only thing we need from tcp.h */
extern int sysctl_tcp_synack_retries;

EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_hash_add);

// inet_csk_reqsk_queue_prune()用于扫描半连接散列表，当半连接队列的连接请求块个数超过最大个数的一半时
// 需要为接受没有重传过的连接保留一半的空间。半连接队列里面要尽量保持没有重传过的连接，并删除一些长时间空闲
// 或者没有接收的连接
// parent：进行侦听的传输控制块
// Interval：建立连接定时器的超时时间
// Timeout：往返超时的初始值，每超时一次，加倍上次的超时时间
// max_rto：往返时间的最大值
void inet_csk_reqsk_queue_prune(struct sock *parent,
				const unsigned long interval,
				const unsigned long timeout,
				const unsigned long max_rto)
{
	struct inet_connection_sock *icsk = inet_csk(parent);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct listen_sock *lopt = queue->listen_opt;
	// 获取建立tcp连接时最多允许重传syn+ack段的次数
	int max_retries = icsk->icsk_syn_retries ? : sysctl_tcp_synack_retries;
	// 局部变量thresh用于控制重传次数，在计算thresh时，年轻连接越多则可容忍的重传次数也越多
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct request_sock **reqp, *req;
	int i, budget;

	// 如果该套接口中保存连接请求块的散列表还没有建立，或者还没有处于连接过程中的连接请求块
	// 则直接返回
	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 3 seconds, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	// 如果qlen已经超过了最大连接数的一半，并且尝试次数大于2，则需要调整重试次数的阈值thresh
	// 如果没有重传过syn+ack段的连接请求块不足所有连接请求块数的四分之一，则将阈值thresh减1
	// 如果在没有重传过syn+ack段中的连接请求块数的八分之一，则再将阈值thresh减1，直至2为止
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

	// 获取在启用加速连接情况下最多允许重传syn段的次数
	if (queue->rskq_defer_accept)
		max_retries = queue->rskq_defer_accept;

	// 计算需要检测的半连接队列的个数，得到预计值，由于半连接队列是一个链表，并且数量可能比较大
	// 因此为了提高效率，每次只是遍历几个链表
	budget = 2 * (lopt->nr_table_entries / (timeout / interval));
	// clock_hand的初始值为0，每次遍历完半连接队列，会把最后的i保存到clock_hand中，从而下一次遍历
	// 会从上次的clock_hand开始
	i = lopt->clock_hand;

	// 处理连接请求散列表中指定budget个入口的连接请求块
	do {
		// 获取当前处理入口的链表头，循环遍历该链表，处理其上的连接请求块
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {
			// 如果当前连接请求块的连接已经超时，则将根据已重传的次数来决定是再次重传还是放弃该连接建立
			if (time_after_eq(now, req->expires)) {
				// 在以下两种情况下需要累计重传syn+ack段的次数，并因重传而递减qlen_young，然后重新计算
				// 下次的超时时间（加倍上次的超时时间），设置到该连接请求块上，最后获取下一个连接请求块进行
				// 处理
				// syn+ack段重传次数未达到上限
				// 已经接收到第三次握手的ack段后，由于繁忙或其他原因导致未能建立起连接
				if ((req->retrans < thresh ||
				     (inet_rsk(req)->acked && req->retrans < max_retries))
				    && !req->rsk_ops->rtx_syn_ack(parent, req, NULL)) {
					unsigned long timeo;

					if (req->retrans++ == 0)
						lopt->qlen_young--;
					timeo = min((timeout << req->retrans), max_rto);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				// 如果syn+ack段重传次数超过指定值，则需要取消该连接请求，并将当前连接请求块从连接请求散列表中删除
				// 并释放
				inet_csk_reqsk_queue_unlink(parent, req, reqp);
				reqsk_queue_removed(queue, req);
				reqsk_free(req);
				continue;
			}
			// 取链表下一个连接请求块进行处理
			reqp = &req->dl_next;
		}

		// 当前入口链表上的连接请求块处理完后，处理下一入口链表上的连接请求块
		i = (i + 1) & (lopt->nr_table_entries - 1);

	} while (--budget > 0);

	// 保存当前处理的入口，下次超时时从保存的入口开始处理
	lopt->clock_hand = i;

	// 如果连接请求散列表中还有未完成连接的连接请求块，则再次启动定时器
	if (lopt->qlen)
		inet_csk_reset_keepalive_timer(parent, interval);
}

EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_prune);

struct sock *inet_csk_clone(struct sock *sk, const struct request_sock *req,
			    const gfp_t priority)
{
	struct sock *newsk = sk_clone(sk, priority);

	if (newsk != NULL) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->dport = inet_rsk(req)->rmt_port;
		newsk->sk_write_space = sk_stream_write_space;

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

		security_inet_csk_clone(newsk, req);
	}
	return newsk;
}

EXPORT_SYMBOL_GPL(inet_csk_clone);

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	BUG_TRAP(sk->sk_state == TCP_CLOSE);
	BUG_TRAP(sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	BUG_TRAP(sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->num, it must be bound */
	BUG_TRAP(!inet_sk(sk)->num || inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	atomic_dec(sk->sk_prot->orphan_count);
	sock_put(sk);
}

EXPORT_SYMBOL(inet_csk_destroy_sock);

// inet_csk_listen_start()函数使tcp传输控制块进入侦听状态，实现侦听的过程，为管理连接
// 请求块的散列表分配存储空间，接着使tcp传输控制块的状态迁移到LISTEN状态，然后将传输控制块
// 添加到侦听散列表中
// sock：进行侦听的传输控制块
// nr_table_entries：允许连接的队列长度上限，通过此值合理计算出存储连接请求块的散列表大小
int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	// 为管理连接请求块的散列表分配存储空间，如果失败则返回相应错误码
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);

	if (rc != 0)
		return rc;

	// 初始化连接队列长度上限，清除当前已建立连接数
	sk->sk_max_ack_backlog = 0;
	sk->sk_ack_backlog = 0;
	// 初始化传输控制块中与延时发送ack段有关的控制数据结构icsk_ack
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	// 设置传输控制块状态为侦听状态（LISTEN）
	sk->sk_state = TCP_LISTEN;
	// 调用get_port接口tcp_v4_get_port()，如果没有绑定端口，则进行绑定端口操作
	// 如果已经绑定了端口，则对绑定的端口进行校验，绑定或校验端口成功后，根据端口号
	// 在传输控制块中设置网络字节序的端口号成员，然后再清楚缓存在传输控制块中的目的路由
	// 缓存，最后调用hash接口tcp_v4_hash()将该传输控制块添加到侦听散列表listening_hash中
	// 完成侦听
	if (!sk->sk_prot->get_port(sk, inet->num)) {
		inet->sport = htons(inet->num);

		sk_dst_reset(sk);
		sk->sk_prot->hash(sk);

		return 0;
	}

	// 绑定或校验端口失败，则说明侦听失败，设置传输控制块状态为TCP_CLOSE状态
	sk->sk_state = TCP_CLOSE;
	// 释放之前分配的inet_bind_bucket实例
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}

EXPORT_SYMBOL_GPL(inet_csk_listen_start);

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock *acc_req;
	struct request_sock *req;

	inet_csk_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	acc_req = reqsk_queue_yank_acceptq(&icsk->icsk_accept_queue);

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	reqsk_queue_destroy(&icsk->icsk_accept_queue);

	while ((req = acc_req) != NULL) {
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		local_bh_disable();
		bh_lock_sock(child);
		BUG_TRAP(!sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		atomic_inc(sk->sk_prot->orphan_count);

		inet_csk_destroy_sock(child);

		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		__reqsk_free(req);
	}
	BUG_TRAP(!sk->sk_ack_backlog);
}

EXPORT_SYMBOL_GPL(inet_csk_listen_stop);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	const struct inet_sock *inet = inet_sk(sk);

	sin->sin_family		= AF_INET;
	sin->sin_addr.s_addr	= inet->daddr;
	sin->sin_port		= inet->dport;
}

EXPORT_SYMBOL_GPL(inet_csk_addr2sockaddr);

int inet_csk_ctl_sock_create(struct socket **sock, unsigned short family,
			     unsigned short type, unsigned char protocol)
{
	int rc = sock_create_kern(family, type, protocol, sock);

	if (rc == 0) {
		(*sock)->sk->sk_allocation = GFP_ATOMIC;
		inet_sk((*sock)->sk)->uc_ttl = -1;
		/*
		 * Unhash it so that IP input processing does not even see it,
		 * we do not wish this socket to see incoming packets.
		 */
		(*sock)->sk->sk_prot->unhash((*sock)->sk);
	}
	return rc;
}

EXPORT_SYMBOL_GPL(inet_csk_ctl_sock_create);

#ifdef CONFIG_COMPAT
int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_getsockopt != NULL)
		return icsk->icsk_af_ops->compat_getsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->getsockopt(sk, level, optname,
					     optval, optlen);
}

EXPORT_SYMBOL_GPL(inet_csk_compat_getsockopt);

int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_setsockopt != NULL)
		return icsk->icsk_af_ops->compat_setsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->setsockopt(sk, level, optname,
					     optval, optlen);
}

EXPORT_SYMBOL_GPL(inet_csk_compat_setsockopt);
#endif
