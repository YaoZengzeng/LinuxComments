/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_timer.c,v 1.88 2002/02/01 22:01:04 davem Exp $
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
 */

#include <linux/module.h>
#include <net/tcp.h>

int sysctl_tcp_syn_retries __read_mostly = TCP_SYN_RETRIES;
int sysctl_tcp_synack_retries __read_mostly = TCP_SYNACK_RETRIES;
int sysctl_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_tcp_orphan_retries __read_mostly;

static void tcp_write_timer(unsigned long);
static void tcp_delack_timer(unsigned long);
static void tcp_keepalive_timer (unsigned long data);

// 传输控制块定时器的初始化函数tcp_init_xmit_timers()在创建套接口，传输控制块时被调用
// 并进而调用inet_csk_init_xmit_timers()进行具体的初始化
void tcp_init_xmit_timers(struct sock *sk)
{
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
}

EXPORT_SYMBOL(tcp_init_xmit_timers);

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int orphans = atomic_read(&tcp_orphan_count);

	/* If peer does not open window for long time, or did not transmit 
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		orphans <<= 1;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		orphans <<= 1;

	if (orphans >= sysctl_tcp_max_orphans ||
	    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
	     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");

		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

/* A write timeout has occurred. Process the after effects. */
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int retry_until;
	int mss;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		// 在建立连接阶段超时，则需要检测使用的路由缓存项，并获取重试次数的最大值
		if (icsk->icsk_retransmits)
			dst_negative_advice(&sk->sk_dst_cache);
		retry_until = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
	} else {
		// 当重传次数达到tcp_retries1时，则需要进行黑洞检测，完成黑洞检测后还需要检测使用的路由缓存项
		if (icsk->icsk_retransmits >= sysctl_tcp_retries1) {
			/* Black hole detection */
			// 系统启用路径mtu发现时，如果路径mtu发现的控制数据块中的开关没有开启，则将其开启
			// 并根据pmtu同步mss，否则将当前路径mtu发现区间左端点的一半作为新区间的左端点重新设定
			// 路径mtu发现区间，并根据路径mtu同步mss
			if (sysctl_tcp_mtu_probing) {
				if (!icsk->icsk_mtup.enabled) {
					icsk->icsk_mtup.enabled = 1;
					tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
				} else {
					mss = min(sysctl_tcp_base_mss,
					          tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low)/2);
					mss = max(mss, 68 - tp->tcp_header_len);
					icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
					tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
				}
			}

			dst_negative_advice(&sk->sk_dst_cache);
		}

		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
			// 如果当前套接口连接已断开并即将关闭，则需要对当前使用的资源进行检测
			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);
 
 			// 当前孤儿套接口数量达到tcp_max_orphans或者当前已使用内存达到硬性限制时，需要即刻
 			// 关闭该套接口，这虽然不符合tcp的规范，但为了防止Dos攻击必须这么处理
			retry_until = tcp_orphan_retries(sk, alive);

			if (tcp_out_of_resources(sk, alive || icsk->icsk_retransmits < retry_until))
				return 1;
		}
	}

	// 当重传次数达到建立连接重传上限，超时重传上限或确认连接异常期间重试上限者三种上限之一
	// 都必须关闭套接口，并且需要报告相应错误
	if (icsk->icsk_retransmits >= retry_until) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock*)data;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		icsk->icsk_ack.blocked = 1;
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOCKED);
		sk_reset_timer(sk, &icsk->icsk_delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

	sk_stream_mem_reclaim(sk);

	if (sk->sk_state == TCP_CLOSE || !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;

	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
		struct sk_buff *skb;

		NET_INC_STATS_BH(LINUX_MIB_TCPSCHEDULERFAILED);

		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk->sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

	if (inet_csk_ack_scheduled(sk)) {
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}
		tcp_send_ack(sk);
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKS);
	}
	TCP_CHECK_TIMER(sk);

out:
	if (tcp_memory_pressure)
		sk_stream_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

// 持续定时器在对端通告接收窗口为0，阻止tcp继续发送数据时设定，由于连接对端发送的窗口通告不可靠
// （只有数据才会确认，ack不会被确认），允许tcp继续发送数据的后续窗口更新有可能丢失，因此，如果tcp
// 有数据要发送，而对端通告接收窗口为0，则持续定时器启动，超时后向对端发送1字节的数据，以判断对端接收窗口
// 是否已打开
static void tcp_probe_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	// 由于持续定时器会周期性地发送探测段，因此如果存在发送出去但未被确认的段
	// 或者在发送队列还有待发送的段，则无需另外组织探测段了，将icsk_probes_out清零后返回
	if (tp->packets_out || !sk->sk_send_head) {
		icsk->icsk_probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	// 获取确定断开连接前持续定时器周期性发送tcp段的数目上限，用于持续定时器发出段数量的检测
	max_probes = sysctl_tcp_retries2;

	// 处理连接已断开，套接口即将关闭的情况
	if (sock_flag(sk, SOCK_DEAD)) {
		// tcp协议规定rtt的最大值为120s（TCP_RTO_MAX），因此可以通过指数退避算法得出的超时时间
		// 与rtt最大值相比，来判断是否需要给对方发送rst
		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);
 
 		// 如果连接已断开，套接口即将关闭，则获取在关闭本段tcp连接前重试次数的上限
		max_probes = tcp_orphan_retries(sk, alive);

		// 释放资源，如果该套接口在释放过程中被关闭，则无需再发送持续探测段了
		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
			return;
	}

	if (icsk->icsk_probes_out > max_probes) {
		// 如果持续定时器或保活定时器周期性发送出但未被确认的tcp段数目达到上限
		// 则作出错处理，同时关闭tcp套接口
		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		// 再次发送持续探测段
		tcp_send_probe0(sk);
	}
}

/*
 *	The TCP retransmit timer.
 */

static void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	// 如果此时从发送队列输出的段都已得到了确认，则无需重传处理
	if (!tp->packets_out)
		goto out;

	BUG_TRAP(!skb_queue_empty(&sk->sk_write_queue));

	// 处理发送窗口已关闭，套接口不在DEAD状态且tcp状态不处于连接过程中的情况
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
#ifdef TCP_DEBUG
		if (net_ratelimit()) {
			struct inet_sock *inet = inet_sk(sk);
			printk(KERN_DEBUG "TCP: Treason uncloaked! Peer %u.%u.%u.%u:%u/%u shrinks window %u:%u. Repaired.\n",
			       NIPQUAD(inet->daddr), ntohs(inet->dport),
			       inet->num, tp->snd_una, tp->snd_nxt);
		}
#endif
		// 在重传过程中，如果超过重传超时上限TCP_RTO_MAX(120s)还没有接收到对方的确认，则认为有错误发生，调用
		// tcp_write_err()报告错误并关闭套接口，然后返回；否则tcp进入拥塞控制的LOSS状态，并重新传送重传队列中
		// 第一个段，此外由于发生了重传，传输控制块中目的路由缓存需更新，因此将其清除
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
		tcp_enter_loss(sk, 0);
		tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue));
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

	// 当发生重传之后，需要检测当前的资源使用情况和重传的次数，如果重传次数达到上限，则需要报告
	// 错误并强行关闭套接口，如果只是使用的资源达到使用的上限，则不进行此次重传
	if (tcp_write_timeout(sk))
		goto out;

	// 如果重传次数为0，说明刚刚进入重传阶段，则根据不同的拥塞状态进行相关的数据统计
	if (icsk->icsk_retransmits == 0) {
		if (icsk->icsk_ca_state == TCP_CA_Disorder ||
		    icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tp->rx_opt.sack_ok) {
				if (icsk->icsk_ca_state == TCP_CA_Recovery)
					NET_INC_STATS_BH(LINUX_MIB_TCPSACKRECOVERYFAIL);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPSACKFAILURES);
			} else {
				if (icsk->icsk_ca_state == TCP_CA_Recovery)
					NET_INC_STATS_BH(LINUX_MIB_TCPRENORECOVERYFAIL);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPRENOFAILURES);
			}
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			NET_INC_STATS_BH(LINUX_MIB_TCPLOSSFAILURES);
		} else {
			NET_INC_STATS_BH(LINUX_MIB_TCPTIMEOUTS);
		}
	}

	if (tcp_use_frto(sk)) {
		// 可用F-RTO算法处理
		tcp_enter_frto(sk);
	} else {
		// 进入常规的RTO慢启动重传恢复阶段
		tcp_enter_loss(sk, 0);
	}

	// 如果发送重传队列上的第一个skb失败，则复位重传定时器，等待下次重传
	if (tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	// 发送成功后，递增指数回退算法指数icsk_backoff和累计重传次数icsk_retransmits
	icsk->icsk_backoff++;
	icsk->icsk_retransmits++;

// 完成重传之后，需要重新设置重传超时时间，然后复位重传定时器，等待下次重传
out_reset_timer:
	icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
	if (icsk->icsk_retransmits > sysctl_tcp_retries1)
		__sk_dst_reset(sk);

out:;
}

// 重传定时器的超时时间值是动态计算的，取决于tcp为该连接测量的往返时间以及该段被重传的次数
static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock*)data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later */
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}

	// tcp状态为CLOSE或未定义定时器事件，则无需作处理
	if (sk->sk_state == TCP_CLOSE || !icsk->icsk_pending)
		goto out;

	// 如果还未到定时器超时时间，则无需作处理，重新设置定时器的下次的超时时间
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

	// 由于重传定时器和持续定时器功能是共用了一个定时器实现的，因此需根据定时器事件来区分激活的是哪种定时器
	event = icsk->icsk_pending;
	icsk->icsk_pending = 0;

	switch (event) {
	case ICSK_TIME_RETRANS:
		// 重传处理
		tcp_retransmit_timer(sk);
		break;
	case ICSK_TIME_PROBE0:
		// 持续定时器的处理
		tcp_probe_timer(sk);
		break;
	}
	TCP_CHECK_TIMER(sk);

out:
	sk_stream_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */

static void tcp_synack_timer(struct sock *sk)
{
	inet_csk_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
				   TCP_TIMEOUT_INIT, TCP_RTO_MAX);
}

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}

// tcp_keepalive_timer()实现了tcp中的三个定时器：连接建立定时器、保活定时器和FIN_WAIT_2定时器
// 这是由于这三个定时器分别处于LISTEN、ESTABLISHED和FIN_WAIT_2三种状态，因此不必区分它们，只需简单
// 地通过当前的TCP状态就能判断当前执行的是何种定时器
// data：执行定时器对应的传输控制块
static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 elapsed;

	/* Only process if socket is not in use. */
	// 如果传输控制块被用户进程锁定，则重新设定定时时间，0.05秒后再次激活
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */ 
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

	// 如果当前tcp状态为LISTEN，则说明执行的是建立连接定时器，调用tcp_synack_timer处理
	if (sk->sk_state == TCP_LISTEN) {
		// tcp_synack_timer只是简单地调用inet_csk_reqsk_queue_prune，用来扫描半连接散列表
		// 然后再设定建立连接定时器，间隔时间为TCP_SYNQ_INERVAL
		tcp_synack_timer(sk);
		goto out;
	}

	// FIN_WAIT_2定时器并不是全部由tcp_keepalive_timer()来实现的，事实上，只有处在FIN_WAIT_2
	// 状态的时间超过60s时，才会将该传输控制块放到tcp_keepalive_timer()中处理
	// 在sk_timer定时器中延时超过60s以后的部分，由tcp_time_wait()继续处理

	// 加入FIN_WAIT_2这个定时器的原因是为了避免对端一直不发FIN，某个连接会用于滞留在FIN_WAIT_2状态

	// 处理FIN_WAIT_2状态定时器时，TCP状态必须为FIN_WAIT_2且套接口状态为DEAD
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		// 停留在FIN_WAIT_2状态的时间大于或等于0的情况下，如果FIN_WAIT_2定时器剩余时间大于0
		// 则调用tcp_time_wait()继续处理；否则给对端发送RST后关闭套接口
		if (tp->linger2 >= 0) {
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

	// 如果未开启保活功能或tcp状态为CLOSE，则不作处理返回
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

	// 如果有已输出未确认的段，或者发送队列中还存在未发送的段，则无需作处理，只需重新设定保活定时器的超时时间
	elapsed = keepalive_time_when(tp);

	/* It is alive without keepalive 8) */
	if (tp->packets_out || sk->sk_send_head)
		goto resched;

	// 获取最近一次收到段到目前为止的时间，即持续空闲时间
	elapsed = tcp_time_stamp - tp->rcv_tstamp;

	if (elapsed >= keepalive_time_when(tp)) {
		// 如果持续空闲时间超过了允许时间，并且在未设置保活探测次数时，已发送保活探测段数查过了系统默认的允许数
		// tcp_keepalive_probes；或者在已设置保活探测段的次数时，已发送次数超过了保活探测次数，则需要断开连接
		// 给对方发送RST段，并报告相应错误，关闭相应的传输控制块
		if ((!tp->keepalive_probes && icsk->icsk_probes_out >= sysctl_tcp_keepalive_probes) ||
		     (tp->keepalive_probes && icsk->icsk_probes_out >= tp->keepalive_probes)) {
			tcp_send_active_reset(sk, GFP_ATOMIC);
			tcp_write_err(sk);
			goto out;
		}
		// 发送保活段，并计算下次激活保活定时器的时间
		if (tcp_write_wakeup(sk) <= 0) {
			icsk->icsk_probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		// 如果持续空闲时间还未达到允许的持续空闲时间，则重新计算下次激活保活定时器的时间
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	TCP_CHECK_TIMER(sk);
	// 回收缓存
	sk_stream_mem_reclaim(sk);

resched:
	// 重新设置保活定时器下次超时时间
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:	
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}
