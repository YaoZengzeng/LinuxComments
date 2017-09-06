/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_ipv4.c,v 1.240 2002/02/01 22:01:04 davem Exp $
 *
 *		IPv4 specific functions
 *
 *
 *		code split from:
 *		linux/ipv4/tcp.c
 *		linux/ipv4/tcp_input.c
 *		linux/ipv4/tcp_output.c
 *
 *		See tcp.c for author information
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

/*
 * Changes:
 *		David S. Miller	:	New socket lookup architecture.
 *					This code is dedicated to John Dyson.
 *		David S. Miller :	Change semantics of established hash,
 *					half is devoted to TIME_WAIT sockets
 *					and the rest go in the other half.
 *		Andi Kleen :		Add support for syncookies and fixed
 *					some bugs: ip options weren't passed to
 *					the TCP layer, missed a check for an
 *					ACK bit.
 *		Andi Kleen :		Implemented fast path mtu discovery.
 *	     				Fixed many serious bugs in the
 *					request_sock handling and moved
 *					most of it into the af independent code.
 *					Added tail drop and some other bugfixes.
 *					Added new listen semantics.
 *		Mike McLagan	:	Routing by source
 *	Juan Jose Ciarlante:		ip_dynaddr bits
 *		Andi Kleen:		various fixes.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year
 *					coma.
 *	Andi Kleen		:	Fix new listen.
 *	Andi Kleen		:	Fix accept error reporting.
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 */


#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/times.h>

#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/timewait_sock.h>
#include <net/xfrm.h>
#include <net/netdma.h>

#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>

int sysctl_tcp_tw_reuse __read_mostly;
int sysctl_tcp_low_latency __read_mostly;

/* Check TCP sequence numbers in ICMP packets. */
#define ICMP_MIN_LENGTH 8

/* Socket used for sending RSTs */
static struct socket *tcp_socket;

void tcp_v4_send_check(struct sock *sk, int len, struct sk_buff *skb);

#ifdef CONFIG_TCP_MD5SIG
static struct tcp_md5sig_key *tcp_v4_md5_do_lookup(struct sock *sk,
						   __be32 addr);
static int tcp_v4_do_calc_md5_hash(char *md5_hash, struct tcp_md5sig_key *key,
				   __be32 saddr, __be32 daddr,
				   struct tcphdr *th, int protocol,
				   int tcplen);
#endif

struct inet_hashinfo __cacheline_aligned tcp_hashinfo = {
	.lhash_lock  = __RW_LOCK_UNLOCKED(tcp_hashinfo.lhash_lock),
	.lhash_users = ATOMIC_INIT(0),
	.lhash_wait  = __WAIT_QUEUE_HEAD_INITIALIZER(tcp_hashinfo.lhash_wait),
};

static int tcp_v4_get_port(struct sock *sk, unsigned short snum)
{
	return inet_csk_get_port(&tcp_hashinfo, sk, snum,
				 inet_csk_bind_conflict);
}

static void tcp_v4_hash(struct sock *sk)
{
	inet_hash(&tcp_hashinfo, sk);
}

void tcp_unhash(struct sock *sk)
{
	inet_unhash(&tcp_hashinfo, sk);
}

static inline __u32 tcp_v4_init_sequence(struct sk_buff *skb)
{
	return secure_tcp_sequence_number(skb->nh.iph->daddr,
					  skb->nh.iph->saddr,
					  skb->h.th->dest,
					  skb->h.th->source);
}

int tcp_twsk_unique(struct sock *sk, struct sock *sktw, void *twp)
{
	const struct tcp_timewait_sock *tcptw = tcp_twsk(sktw);
	struct tcp_sock *tp = tcp_sk(sk);

	/* With PAWS, it is safe from the viewpoint
	   of data integrity. Even without PAWS it is safe provided sequence
	   spaces do not overlap i.e. at data rates <= 80Mbit/sec.

	   Actually, the idea is close to VJ's one, only timestamp cache is
	   held not per host, but per port pair and TW bucket is used as state
	   holder.

	   If TW bucket has been already destroyed we fall back to VJ's scheme
	   and use initial timestamp retrieved from peer table.
	 */
	if (tcptw->tw_ts_recent_stamp &&
	    (twp == NULL || (sysctl_tcp_tw_reuse &&
			     xtime.tv_sec - tcptw->tw_ts_recent_stamp > 1))) {
		tp->write_seq = tcptw->tw_snd_nxt + 65535 + 2;
		if (tp->write_seq == 0)
			tp->write_seq = 1;
		tp->rx_opt.ts_recent	   = tcptw->tw_ts_recent;
		tp->rx_opt.ts_recent_stamp = tcptw->tw_ts_recent_stamp;
		sock_hold(sktw);
		return 1;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(tcp_twsk_unique);

/* This will initiate an outgoing connection. */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	__be32 daddr, nexthop;
	int tmp;
	int err;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	// 以用户给定的套接字初始化网关地址nexthop和目标地址daddr
	nexthop = daddr = usin->sin_addr.s_addr;
	if (inet->opt && inet->opt->srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}

	// 在确定了目标地址、网关地址等信息后，调用ip_route_connect函数来寻址目标路由
	// 寻址目标路由的依据源是：目标IP地址、网络设备接口、源端口号（inet->sport）
	// 目标端口号（usin->sin_port）等信息，寻址好的路由在路由表中的索引返回到rt变量中
	tmp = ip_route_connect(&rt, nexthop, inet->saddr,
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->sport, usin->sin_port, sk);
	if (tmp < 0)
		return tmp;

	// tcp连接必须建立在唯一主机地址上，所以如果在路由缓冲区中的路由是组传送地址（MULTICAST）
	// 或广播地址（BROADCAST），则返回错误
	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet->opt || !inet->opt->srr)		// 如果没有设置IP选项或IP源路由选项，使用路由表寻址的路由
		daddr = rt->rt_dst;

	if (!inet->saddr)
		inet->saddr = rt->rt_src;
	inet->rcv_saddr = inet->saddr;

	// 如果当前套接字建立连接的目标地址与套接字数据结构中保存的目标地址不一样，则复位原tcp继承的状态
	if (tp->rx_opt.ts_recent_stamp && inet->daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

	// 当套接字当前处于TIME_WAIT状态时，套接字最后一次使用时间存放在与路由入口
	// 相关的struct inet_peer数据结构中，这时如果用户发出了连接请求，最近套接字
	// 接收信息的时间，需写入struct tcp_sock数据结构的timestamp数据域，其值从
	// 存放在struct inet_peer数据结构中的值获取，一旦连接建立，这个方法是检测复制段的方法
	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer(rt);
		/*
		 * VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state
		 * TIME-WAIT * and initialize rx_opt.ts_recent from it,
		 * when trying new connection.
		 */
		if (peer != NULL &&
		    peer->tcp_ts_stamp + TCP_PAWS_MSL >= xtime.tv_sec) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	inet->dport = usin->sin_port;
	inet->daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet->opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;

	// 初始化mss为tcp允许接收的最大数据段536，虽然我们是在打开的套接字上进行了相应的处理，这时标示套接字
	// 的信息还不完整，例如套接字源端口好这时就还没有分配
	tp->rx_opt.mss_clamp = 536;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	// 将套接字状态设置为TCP_SYN_SENT，将套接字sk放入TCP连接管理哈希链表
	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet_hash_connect(&tcp_death_row, sk);
	if (err)
		goto failure;

	// 为连接分配一个临时端口号，以便于以后在哈希链表中查找套接字sk
	err = ip_route_newports(&rt, IPPROTO_TCP,
				inet->sport, inet->dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->u.dst);

	if (!tp->write_seq)
		// 初始化tcp数据段序列号
		tp->write_seq = secure_tcp_sequence_number(inet->saddr,
							   inet->daddr,
							   inet->sport,
							   usin->sin_port);

	inet->id = tp->write_seq ^ jiffies;

	// tcp_connect函数完成实际的连接建立工作
	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	// 如果连接建立处理失败，则将套接字从已连接的哈希链表中移除并释放本地端口号
	// 将tcp状态切换回CLOSED状态，并返回错误信息
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->dport = 0;
	return err;
}

/*
 * This routine does path mtu discovery as defined in RFC1191.
 */
static void do_pmtu_discovery(struct sock *sk, struct iphdr *iph, u32 mtu)
{
	struct dst_entry *dst;
	struct inet_sock *inet = inet_sk(sk);

	/* We are not interested in TCP_LISTEN and open_requests (SYN-ACKs
	 * send out by Linux are always <576bytes so they should go through
	 * unfragmented).
	 */
	if (sk->sk_state == TCP_LISTEN)
		return;

	/* We don't check in the destentry if pmtu discovery is forbidden
	 * on this route. We just assume that no packet_to_big packets
	 * are send back when pmtu discovery is not active.
     	 * There is a small race when the user changes this flag in the
	 * route, but I think that's acceptable.
	 */
	if ((dst = __sk_dst_check(sk, 0)) == NULL)
		return;

	dst->ops->update_pmtu(dst, mtu);

	/* Something is about to be wrong... Remember soft error
	 * for the case, if this connection will not able to recover.
	 */
	if (mtu < dst_mtu(dst) && ip_dont_fragment(sk, dst))
		sk->sk_err_soft = EMSGSIZE;

	mtu = dst_mtu(dst);

	if (inet->pmtudisc != IP_PMTUDISC_DONT &&
	    inet_csk(sk)->icsk_pmtu_cookie > mtu) {
		tcp_sync_mss(sk, mtu);

		/* Resend the TCP packet because it's
		 * clear that the old packet has been
		 * dropped. This is the new "fast" path mtu
		 * discovery.
		 */
		tcp_simple_retransmit(sk);
	} /* else let the usual retransmit timer handle it */
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.  After adjustment
 * header points to the first 8 bytes of the tcp header.  We need
 * to find the appropriate port.
 *
 * The locking strategy used here is very "optimistic". When
 * someone else accesses the socket the ICMP is just dropped
 * and for some paths there is no check at all.
 * A more general error queue to queue errors for later handling
 * is probably better.
 *
 */
// tcp_v4_err是tcp的差错处理函数，在icmp模块接收到差错报文后，如果传输层协议是tcp，就调用该函数
// 如果错误码小于零，则先关闭连接然后将错误返回给用户进程，大于零，则根据ICMP报文的类型及编码作相应处理
// skb：接收到的icmp差错报文
// info：辅助信息，因类型，代码而异，例如，对于目的不可达需要分片的差错报文，info为下一跳的mtu
void tcp_v4_err(struct sk_buff *skb, u32 info)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	struct tcphdr *th = (struct tcphdr *)(skb->data + (iph->ihl << 2));
	struct tcp_sock *tp;
	struct inet_sock *inet;
	int type = skb->h.icmph->type;
	int code = skb->h.icmph->code;
	struct sock *sk;
	__u32 seq;
	int err;

	// 检测icmp报文长度是否包含了原始ip首部和原始ip数据报中前8字节数据，如果不完整则返回
	if (skb->len < (iph->ihl << 2) + 8) {
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
		return;
	}

	// 通过从icmp报文数据中获取的原始tcp首部中源端口号和ip首部中源地址，得到发送该tcp报文的传输控制块
	sk = inet_lookup(&tcp_hashinfo, iph->daddr, th->dest, iph->saddr,
			 th->source, inet_iif(skb));
	// 如果获取失败，则说明icmp报文有误或该套接口已关闭
	if (!sk) {
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
		return;
	}
	// 如果获取传输控制块的tcp状态为TIME_WAIT，则说明套接口即将关闭，这两种情况都无需进一步处理
	if (sk->sk_state == TCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
		return;
	}

	bh_lock_sock(sk);
	/* If too many ICMPs get dropped on busy
	 * servers this needs to be solved differently.
	 */
	// 如果此时该传输控制块被用户进程锁定（如果用户进程正在调用send等系统调用），则需累计相关SNMP的统计量
	if (sock_owned_by_user(sk))
		NET_INC_STATS_BH(LINUX_MIB_LOCKDROPPEDICMPS);

	// 如果传输控制块的tcp状态为CLOSE，则说明该套接口已经关闭，无需进一步处理
	if (sk->sk_state == TCP_CLOSE)
		goto out;

	tp = tcp_sk(sk);
	seq = ntohl(th->seq);
	// 如果传输控制块不在侦听状态，且序号不在已发送未确认的区间内，则icmp报文异常，无需进一步处理
	if (sk->sk_state != TCP_LISTEN &&
	    !between(seq, tp->snd_una, tp->snd_nxt)) {
		NET_INC_STATS_BH(LINUX_MIB_OUTOFWINDOWICMPS);
		goto out;
	}

	// 根据icmp类型进行相应处理
	switch (type) {
	case ICMP_SOURCE_QUENCH:
		/* Just silently ignore these. */
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		break;
	case ICMP_DEST_UNREACH:
		if (code > NR_ICMP_UNREACH)
			goto out;

		if (code == ICMP_FRAG_NEEDED) { /* PMTU discovery (RFC1191) */
			// 如果需要分片而设置了不分片位，则调用do_pmtu_discovery()探测路径MTU
			if (!sock_owned_by_user(sk))
				do_pmtu_discovery(sk, iph, info);
			goto out;
		}

		err = icmp_err_convert[code].errno;
		break;
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	default:
		goto out;
	}

	switch (sk->sk_state) {
		struct request_sock *req, **prev;
	case TCP_LISTEN:
		// 如果传输控制块被用户进程锁定，则不作进一步处理
		if (sock_owned_by_user(sk))
			goto out;

		// 由于处于侦听状态，因此根据目的端口号，源地址和目的地址查找正在连接的对端套接口
		// 如果查找失败则不作进一步处理
		req = inet_csk_search_req(sk, &prev, th->dest,
					  iph->daddr, iph->saddr);
		if (!req)
			goto out;

		/* ICMPs are not backlogged, hence we cannot get
		   an established socket here.
		 */
		BUG_TRAP(!req->sk);

		// 如果发送出去tcp段的序号不等于对端套接口的发送序号，则说明序号有误，不作进一步处理
		if (seq != tcp_rsk(req)->snt_isn) {
			NET_INC_STATS_BH(LINUX_MIB_OUTOFWINDOWICMPS);
			goto out;
		}

		/*
		 * Still in SYN_RECV, just remove it silently.
		 * There is no good way to pass the error to the newly
		 * created socket, and POSIX does not want network
		 * errors returned from accept().
		 */
		// 删除并释放连接过程中的传输块
		inet_csk_reqsk_queue_drop(sk, req, prev);
		goto out;

	case TCP_SYN_SENT:
	case TCP_SYN_RECV:  /* Cannot happen.
			       It can f.e. if SYNs crossed.
			     */
		if (!sock_owned_by_user(sk)) {
			// 如果传输控制块没有被用户进程锁定，则将错误码设置到sk_err，调用该套接口的错误报告接口函数
			// 关闭套接口
			sk->sk_err = err;

			sk->sk_error_report(sk);

			tcp_done(sk);
		} else {
			// 否则将错误码设置到sk_err_soft，在这种情况下用户进程可使用SO_ERROR套接口选项获取错误码
			sk->sk_err_soft = err;
		}
		goto out;
	}

	/* If we've already connected we will keep trying
	 * until we time out, or the user gives up.
	 *
	 * rfc1122 4.2.3.9 allows to consider as hard errors
	 * only PROTO_UNREACH and PORT_UNREACH (well, FRAG_FAILED too,
	 * but it is obsoleted by pmtu discovery).
	 *
	 * Note, that in modern internet, where routing is unreliable
	 * and in each dark corner broken firewalls sit, sending random
	 * errors ordered by their masters even this two messages finally lose
	 * their original sense (even Linux sends invalid PORT_UNREACHs)
	 *
	 * Now we are in compliance with RFCs.
	 *							--ANK (980905)
	 */

	// 到这一步，则传输控制块一定不在LISTEN、SYN_SENT或SYN_RECV状态，此时如果控制块没有被用户进程锁定
	// 并且允许接收扩展的可靠错误消息，则设置得到的错误码，然后通知错误，否则将错误码设置到sk_err_soft
	inet = inet_sk(sk);
	if (!sock_owned_by_user(sk) && inet->recverr) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	} else	{ /* Only an error on timeout */
		sk->sk_err_soft = err;
	}

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* This routine computes an IPv4 TCP checksum. */
// tcp_v4_send_check基于tcp用户数据的中间累加和（如果存在数据），生成tcp包的校验和
void tcp_v4_send_check(struct sock *sk, int len, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcphdr *th = skb->h.th;

	// 如果tcp包本身的校验由硬件来完成，则只执行伪首部校验和
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~tcp_v4_check(th, len,
					  inet->saddr, inet->daddr, 0);
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		// 对于用软件完成校验和的操作，则基于tcp用户数据的中间累加和，生成tcp包的校验和
		th->check = tcp_v4_check(th, len, inet->saddr, inet->daddr,
					 csum_partial((char *)th,
						      th->doff << 2,
						      skb->csum));
	}
}

int tcp_v4_gso_send_check(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *th;

	if (!pskb_may_pull(skb, sizeof(*th)))
		return -EINVAL;

	iph = skb->nh.iph;
	th = skb->h.th;

	th->check = 0;
	th->check = ~tcp_v4_check(th, skb->len, iph->saddr, iph->daddr, 0);
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;
	return 0;
}

/*
 *	This routine will send an RST to the other tcp.
 *
 *	Someone asks: why I NEVER use socket parameters (TOS, TTL etc.)
 *		      for reset.
 *	Answer: if a packet caused RST, it is not for a socket
 *		existing in our system, if it is matched to a socket,
 *		it is just duplicate segment or bug in other side's TCP.
 *		So that we build reply only basing on parameters
 *		arrived with segment.
 *	Exception: precedence violation. We do not implement it in any case.
 */
// tcp_v4_send_reset()用来发送rst段
// 首先设置tcp首部中各字段，包括目的地址、源地址、tcp首部长度、rst标志、序号、确认序号
// 然后计算tcp校验和，为ip数据报的发送作准备
// 最后调用网络层函数ip_send_reply()发送该rst段
static void tcp_v4_send_reset(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	struct {
		struct tcphdr th;
#ifdef CONFIG_TCP_MD5SIG
		__be32 opt[(TCPOLEN_MD5SIG_ALIGNED >> 2)];
#endif
	} rep;
	struct ip_reply_arg arg;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif

	/* Never send a reset in response to a reset. */
	if (th->rst)
		return;

	if (((struct rtable *)skb->dst)->rt_type != RTN_LOCAL)
		return;

	/* Swap the send and the receive. */
	memset(&rep, 0, sizeof(rep));
	rep.th.dest   = th->source;
	rep.th.source = th->dest;
	rep.th.doff   = sizeof(struct tcphdr) / 4;
	rep.th.rst    = 1;

	if (th->ack) {
		rep.th.seq = th->ack_seq;
	} else {
		rep.th.ack = 1;
		rep.th.ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
				       skb->len - (th->doff << 2));
	}

	memset(&arg, 0, sizeof(arg));
	arg.iov[0].iov_base = (unsigned char *)&rep;
	arg.iov[0].iov_len  = sizeof(rep.th);

#ifdef CONFIG_TCP_MD5SIG
	key = sk ? tcp_v4_md5_do_lookup(sk, skb->nh.iph->daddr) : NULL;
	if (key) {
		rep.opt[0] = htonl((TCPOPT_NOP << 24) |
				   (TCPOPT_NOP << 16) |
				   (TCPOPT_MD5SIG << 8) |
				   TCPOLEN_MD5SIG);
		/* Update length and the length the header thinks exists */
		arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
		rep.th.doff = arg.iov[0].iov_len / 4;

		tcp_v4_do_calc_md5_hash((__u8 *)&rep.opt[1],
					key,
					skb->nh.iph->daddr,
					skb->nh.iph->saddr,
					&rep.th, IPPROTO_TCP,
					arg.iov[0].iov_len);
	}
#endif
	arg.csum = csum_tcpudp_nofold(skb->nh.iph->daddr,
				      skb->nh.iph->saddr, /* XXX */
				      sizeof(struct tcphdr), IPPROTO_TCP, 0);
	arg.csumoffset = offsetof(struct tcphdr, check) / 2;

	ip_send_reply(tcp_socket->sk, skb, &arg, arg.iov[0].iov_len);

	TCP_INC_STATS_BH(TCP_MIB_OUTSEGS);
	TCP_INC_STATS_BH(TCP_MIB_OUTRSTS);
}

/* The code following below sending ACKs in SYN-RECV and TIME-WAIT states
   outside socket context is ugly, certainly. What can I do?
 */
// 在SYN_RECV状态下，如果接收到的第三次握手段序号无效或者序号不在接收窗口内，且非rst段
// 则需向对端发送ack段
static void tcp_v4_send_ack(struct tcp_timewait_sock *twsk,
			    struct sk_buff *skb, u32 seq, u32 ack,
			    u32 win, u32 ts)
{
	struct tcphdr *th = skb->h.th;
	// 定义ack段的tcp首部，包括时间戳选项
	struct {
		struct tcphdr th;
		__be32 opt[(TCPOLEN_TSTAMP_ALIGNED >> 2)
#ifdef CONFIG_TCP_MD5SIG
			   + (TCPOLEN_MD5SIG_ALIGNED >> 2)
#endif
			];
	} rep;
	struct ip_reply_arg arg;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
	struct tcp_md5sig_key tw_key;
#endif

	memset(&rep.th, 0, sizeof(struct tcphdr));
	memset(&arg, 0, sizeof(arg));

	arg.iov[0].iov_base = (unsigned char *)&rep;
	arg.iov[0].iov_len  = sizeof(rep.th);
	// 设置ack段时间戳选项
	if (ts) {
		rep.opt[0] = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				   (TCPOPT_TIMESTAMP << 8) |
				   TCPOLEN_TIMESTAMP);
		rep.opt[1] = htonl(tcp_time_stamp);
		rep.opt[2] = htonl(ts);
		arg.iov[0].iov_len += TCPOLEN_TSTAMP_ALIGNED;
	}

	/* Swap the send and the receive. */
	// 设置tcp首部中各字段，包括目的地址、源地址、tcp首部长度、序号、确认序号、ack标志
	// 接收窗口大小等
	rep.th.dest    = th->source;
	rep.th.source  = th->dest;
	rep.th.doff    = arg.iov[0].iov_len / 4;
	rep.th.seq     = htonl(seq);
	rep.th.ack_seq = htonl(ack);
	rep.th.ack     = 1;
	rep.th.window  = htons(win);

#ifdef CONFIG_TCP_MD5SIG
	/*
	 * The SKB holds an imcoming packet, but may not have a valid ->sk
	 * pointer. This is especially the case when we're dealing with a
	 * TIME_WAIT ack, because the sk structure is long gone, and only
	 * the tcp_timewait_sock remains. So the md5 key is stashed in that
	 * structure, and we use it in preference.  I believe that (twsk ||
	 * skb->sk) holds true, but we program defensively.
	 */
	if (!twsk && skb->sk) {
		key = tcp_v4_md5_do_lookup(skb->sk, skb->nh.iph->daddr);
	} else if (twsk && twsk->tw_md5_keylen) {
		tw_key.key = twsk->tw_md5_key;
		tw_key.keylen = twsk->tw_md5_keylen;
		key = &tw_key;
	} else
		key = NULL;

	if (key) {
		int offset = (ts) ? 3 : 0;

		rep.opt[offset++] = htonl((TCPOPT_NOP << 24) |
					  (TCPOPT_NOP << 16) |
					  (TCPOPT_MD5SIG << 8) |
					  TCPOLEN_MD5SIG);
		arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
		rep.th.doff = arg.iov[0].iov_len/4;

		tcp_v4_do_calc_md5_hash((__u8 *)&rep.opt[offset],
					key,
					skb->nh.iph->daddr,
					skb->nh.iph->saddr,
					&rep.th, IPPROTO_TCP,
					arg.iov[0].iov_len);
	}
#endif
	// 计算tcp段的伪首部校验和，存放到ip_reply_arg结构中，为ip数据报的发送做准备
	arg.csum = csum_tcpudp_nofold(skb->nh.iph->daddr,
				      skb->nh.iph->saddr, /* XXX */
				      arg.iov[0].iov_len, IPPROTO_TCP, 0);
	arg.csumoffset = offsetof(struct tcphdr, check) / 2;

	// 调用网络层函数ip_send_reply()，发送此ack段
	ip_send_reply(tcp_socket->sk, skb, &arg, arg.iov[0].iov_len);

	TCP_INC_STATS_BH(TCP_MIB_OUTSEGS);
}

static void tcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{
	struct inet_timewait_sock *tw = inet_twsk(sk);
	struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

	tcp_v4_send_ack(tcptw, skb, tcptw->tw_snd_nxt, tcptw->tw_rcv_nxt,
			tcptw->tw_rcv_wnd >> tw->tw_rcv_wscale,
			tcptw->tw_ts_recent);

	inet_twsk_put(tw);
}

static void tcp_v4_reqsk_send_ack(struct sk_buff *skb,
				  struct request_sock *req)
{
	tcp_v4_send_ack(NULL, skb, tcp_rsk(req)->snt_isn + 1,
			tcp_rsk(req)->rcv_isn + 1, req->rcv_wnd,
			req->ts_recent);
}

/*
 *	Send a SYN-ACK after having received an ACK.
 *	This still operates on a request_sock only, not on a big
 *	socket.
 */
// tcp_v4_send_synack()用来为服务端构造回应客户端连接请求syn段的syn+ack段
// 并将其封装在ip数据包中发送给客户端
static int tcp_v4_send_synack(struct sock *sk, struct request_sock *req,
			      struct dst_entry *dst)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int err = -1;
	struct sk_buff * skb;

	/* First, grab a route. */
	// 根据连接请求块中的信息查询路由，如果失败，则直接退出，不再发送syn+ack段
	if (!dst && (dst = inet_csk_route_req(sk, req)) == NULL)
		goto out;

	// 根据当前的传输控制块、查询到的路由以及连接请求块中的相关信息构建syn+ack段
	skb = tcp_make_synack(sk, dst, req);

	if (skb) {
		// 如果构建syn+ack段成功，则生成tcp校验码，并调用ip_build_and_send_pkt()生成
		// ip数据报并将其发送出去
		struct tcphdr *th = skb->h.th;

		th->check = tcp_v4_check(th, skb->len,
					 ireq->loc_addr,
					 ireq->rmt_addr,
					 csum_partial((char *)th, skb->len,
						      skb->csum));

		err = ip_build_and_send_pkt(skb, sk, ireq->loc_addr,
					    ireq->rmt_addr,
					    ireq->opt);
		err = net_xmit_eval(err);
	}

	// 无论查询路由表是否成功，构建syn+ack段是否成功，发送段是否成功，最终都要从这返回，当然返回去需先更新
	// 路由表项的计数器
out:
	dst_release(dst);
	return err;
}

/*
 *	IPv4 request_sock destructor.
 */
static void tcp_v4_reqsk_destructor(struct request_sock *req)
{
	kfree(inet_rsk(req)->opt);
}

#ifdef CONFIG_SYN_COOKIES
static void syn_flood_warning(struct sk_buff *skb)
{
	static unsigned long warntime;

	if (time_after(jiffies, (warntime + HZ * 60))) {
		warntime = jiffies;
		printk(KERN_INFO
		       "possible SYN flooding on port %d. Sending cookies.\n",
		       ntohs(skb->h.th->dest));
	}
}
#endif

/*
 * Save and compile IPv4 options into the request_sock if needed.
 */
// tcp_v4_save_options()根据IP选项的长度分配ip_options结构的实例，然后调用ip_options_echo()
// 从skb的控制块中获取ip选项到该实例中
static struct ip_options *tcp_v4_save_options(struct sock *sk,
					      struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	struct ip_options *dopt = NULL;

	if (opt && opt->optlen) {
		int opt_size = optlength(opt);
		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt) {
			if (ip_options_echo(dopt, skb)) {
				kfree(dopt);
				dopt = NULL;
			}
		}
	}
	return dopt;
}

#ifdef CONFIG_TCP_MD5SIG
/*
 * RFC2385 MD5 checksumming requires a mapping of
 * IP address->MD5 Key.
 * We need to maintain these in the sk structure.
 */

/* Find the Key structure for an address.  */
static struct tcp_md5sig_key *
			tcp_v4_md5_do_lookup(struct sock *sk, __be32 addr)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i;

	if (!tp->md5sig_info || !tp->md5sig_info->entries4)
		return NULL;
	for (i = 0; i < tp->md5sig_info->entries4; i++) {
		if (tp->md5sig_info->keys4[i].addr == addr)
			return (struct tcp_md5sig_key *)
						&tp->md5sig_info->keys4[i];
	}
	return NULL;
}

struct tcp_md5sig_key *tcp_v4_md5_lookup(struct sock *sk,
					 struct sock *addr_sk)
{
	return tcp_v4_md5_do_lookup(sk, inet_sk(addr_sk)->daddr);
}

EXPORT_SYMBOL(tcp_v4_md5_lookup);

static struct tcp_md5sig_key *tcp_v4_reqsk_md5_lookup(struct sock *sk,
						      struct request_sock *req)
{
	return tcp_v4_md5_do_lookup(sk, inet_rsk(req)->rmt_addr);
}

/* This can be called on a newly created socket, from other files */
int tcp_v4_md5_do_add(struct sock *sk, __be32 addr,
		      u8 *newkey, u8 newkeylen)
{
	/* Add Key to the list */
	struct tcp4_md5sig_key *key;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp4_md5sig_key *keys;

	key = (struct tcp4_md5sig_key *)tcp_v4_md5_do_lookup(sk, addr);
	if (key) {
		/* Pre-existing entry - just update that one. */
		kfree(key->key);
		key->key = newkey;
		key->keylen = newkeylen;
	} else {
		struct tcp_md5sig_info *md5sig;

		if (!tp->md5sig_info) {
			tp->md5sig_info = kzalloc(sizeof(*tp->md5sig_info),
						  GFP_ATOMIC);
			if (!tp->md5sig_info) {
				kfree(newkey);
				return -ENOMEM;
			}
		}
		if (tcp_alloc_md5sig_pool() == NULL) {
			kfree(newkey);
			return -ENOMEM;
		}
		md5sig = tp->md5sig_info;

		if (md5sig->alloced4 == md5sig->entries4) {
			keys = kmalloc((sizeof(*keys) *
				        (md5sig->entries4 + 1)), GFP_ATOMIC);
			if (!keys) {
				kfree(newkey);
				tcp_free_md5sig_pool();
				return -ENOMEM;
			}

			if (md5sig->entries4)
				memcpy(keys, md5sig->keys4,
				       sizeof(*keys) * md5sig->entries4);

			/* Free old key list, and reference new one */
			if (md5sig->keys4)
				kfree(md5sig->keys4);
			md5sig->keys4 = keys;
			md5sig->alloced4++;
		}
		md5sig->entries4++;
		md5sig->keys4[md5sig->entries4 - 1].addr   = addr;
		md5sig->keys4[md5sig->entries4 - 1].key    = newkey;
		md5sig->keys4[md5sig->entries4 - 1].keylen = newkeylen;
	}
	return 0;
}

EXPORT_SYMBOL(tcp_v4_md5_do_add);

static int tcp_v4_md5_add_func(struct sock *sk, struct sock *addr_sk,
			       u8 *newkey, u8 newkeylen)
{
	return tcp_v4_md5_do_add(sk, inet_sk(addr_sk)->daddr,
				 newkey, newkeylen);
}

int tcp_v4_md5_do_del(struct sock *sk, __be32 addr)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i;

	for (i = 0; i < tp->md5sig_info->entries4; i++) {
		if (tp->md5sig_info->keys4[i].addr == addr) {
			/* Free the key */
			kfree(tp->md5sig_info->keys4[i].key);
			tp->md5sig_info->entries4--;

			if (tp->md5sig_info->entries4 == 0) {
				kfree(tp->md5sig_info->keys4);
				tp->md5sig_info->keys4 = NULL;
				tp->md5sig_info->alloced4 = 0;
			} else if (tp->md5sig_info->entries4 != i) {
				/* Need to do some manipulation */
				memcpy(&tp->md5sig_info->keys4[i],
				       &tp->md5sig_info->keys4[i+1],
				       (tp->md5sig_info->entries4 - i) *
				        sizeof(struct tcp4_md5sig_key));
			}
			tcp_free_md5sig_pool();
			return 0;
		}
	}
	return -ENOENT;
}

EXPORT_SYMBOL(tcp_v4_md5_do_del);

static void tcp_v4_clear_md5_list(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Free each key, then the set of key keys,
	 * the crypto element, and then decrement our
	 * hold on the last resort crypto.
	 */
	if (tp->md5sig_info->entries4) {
		int i;
		for (i = 0; i < tp->md5sig_info->entries4; i++)
			kfree(tp->md5sig_info->keys4[i].key);
		tp->md5sig_info->entries4 = 0;
		tcp_free_md5sig_pool();
	}
	if (tp->md5sig_info->keys4) {
		kfree(tp->md5sig_info->keys4);
		tp->md5sig_info->keys4 = NULL;
		tp->md5sig_info->alloced4  = 0;
	}
}

static int tcp_v4_parse_md5_keys(struct sock *sk, char __user *optval,
				 int optlen)
{
	struct tcp_md5sig cmd;
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.tcpm_addr;
	u8 *newkey;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin->sin_family != AF_INET)
		return -EINVAL;

	if (!cmd.tcpm_key || !cmd.tcpm_keylen) {
		if (!tcp_sk(sk)->md5sig_info)
			return -ENOENT;
		return tcp_v4_md5_do_del(sk, sin->sin_addr.s_addr);
	}

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	if (!tcp_sk(sk)->md5sig_info) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct tcp_md5sig_info *p = kzalloc(sizeof(*p), GFP_KERNEL);

		if (!p)
			return -EINVAL;

		tp->md5sig_info = p;

	}

	newkey = kmemdup(cmd.tcpm_key, cmd.tcpm_keylen, GFP_KERNEL);
	if (!newkey)
		return -ENOMEM;
	return tcp_v4_md5_do_add(sk, sin->sin_addr.s_addr,
				 newkey, cmd.tcpm_keylen);
}

static int tcp_v4_do_calc_md5_hash(char *md5_hash, struct tcp_md5sig_key *key,
				   __be32 saddr, __be32 daddr,
				   struct tcphdr *th, int protocol,
				   int tcplen)
{
	struct scatterlist sg[4];
	__u16 data_len;
	int block = 0;
	__sum16 old_checksum;
	struct tcp_md5sig_pool *hp;
	struct tcp4_pseudohdr *bp;
	struct hash_desc *desc;
	int err;
	unsigned int nbytes = 0;

	/*
	 * Okay, so RFC2385 is turned on for this connection,
	 * so we need to generate the MD5 hash for the packet now.
	 */

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;

	bp = &hp->md5_blk.ip4;
	desc = &hp->md5_desc;

	/*
	 * 1. the TCP pseudo-header (in the order: source IP address,
	 * destination IP address, zero-padded protocol number, and
	 * segment length)
	 */
	bp->saddr = saddr;
	bp->daddr = daddr;
	bp->pad = 0;
	bp->protocol = protocol;
	bp->len = htons(tcplen);
	sg_set_buf(&sg[block++], bp, sizeof(*bp));
	nbytes += sizeof(*bp);

	/* 2. the TCP header, excluding options, and assuming a
	 * checksum of zero/
	 */
	old_checksum = th->check;
	th->check = 0;
	sg_set_buf(&sg[block++], th, sizeof(struct tcphdr));
	nbytes += sizeof(struct tcphdr);

	/* 3. the TCP segment data (if any) */
	data_len = tcplen - (th->doff << 2);
	if (data_len > 0) {
		unsigned char *data = (unsigned char *)th + (th->doff << 2);
		sg_set_buf(&sg[block++], data, data_len);
		nbytes += data_len;
	}

	/* 4. an independently-specified key or password, known to both
	 * TCPs and presumably connection-specific
	 */
	sg_set_buf(&sg[block++], key->key, key->keylen);
	nbytes += key->keylen;

	/* Now store the Hash into the packet */
	err = crypto_hash_init(desc);
	if (err)
		goto clear_hash;
	err = crypto_hash_update(desc, sg, nbytes);
	if (err)
		goto clear_hash;
	err = crypto_hash_final(desc, md5_hash);
	if (err)
		goto clear_hash;

	/* Reset header, and free up the crypto */
	tcp_put_md5sig_pool();
	th->check = old_checksum;

out:
	return 0;
clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	goto out;
}

int tcp_v4_calc_md5_hash(char *md5_hash, struct tcp_md5sig_key *key,
			 struct sock *sk,
			 struct dst_entry *dst,
			 struct request_sock *req,
			 struct tcphdr *th, int protocol,
			 int tcplen)
{
	__be32 saddr, daddr;

	if (sk) {
		saddr = inet_sk(sk)->saddr;
		daddr = inet_sk(sk)->daddr;
	} else {
		struct rtable *rt = (struct rtable *)dst;
		BUG_ON(!rt);
		saddr = rt->rt_src;
		daddr = rt->rt_dst;
	}
	return tcp_v4_do_calc_md5_hash(md5_hash, key,
				       saddr, daddr,
				       th, protocol, tcplen);
}

EXPORT_SYMBOL(tcp_v4_calc_md5_hash);

static int tcp_v4_inbound_md5_hash(struct sock *sk, struct sk_buff *skb)
{
	/*
	 * This gets called for each TCP segment that arrives
	 * so we want to be efficient.
	 * We have 3 drop cases:
	 * o No MD5 hash and one expected.
	 * o MD5 hash and we're not expecting one.
	 * o MD5 hash and its wrong.
	 */
	__u8 *hash_location = NULL;
	struct tcp_md5sig_key *hash_expected;
	struct iphdr *iph = skb->nh.iph;
	struct tcphdr *th = skb->h.th;
	int length = (th->doff << 2) - sizeof(struct tcphdr);
	int genhash;
	unsigned char *ptr;
	unsigned char newhash[16];

	hash_expected = tcp_v4_md5_do_lookup(sk, iph->saddr);

	/*
	 * If the TCP option length is less than the TCP_MD5SIG
	 * option length, then we can shortcut
	 */
	if (length < TCPOLEN_MD5SIG) {
		if (hash_expected)
			return 1;
		else
			return 0;
	}

	/* Okay, we can't shortcut - we have to grub through the options */
	ptr = (unsigned char *)(th + 1);
	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			goto done_opts;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)
				goto done_opts;
			if (opsize > length)
				goto done_opts;

			if (opcode == TCPOPT_MD5SIG) {
				hash_location = ptr;
				goto done_opts;
			}
		}
		ptr += opsize-2;
		length -= opsize;
	}
done_opts:
	/* We've parsed the options - do we have a hash? */
	if (!hash_expected && !hash_location)
		return 0;

	if (hash_expected && !hash_location) {
		LIMIT_NETDEBUG(KERN_INFO "MD5 Hash expected but NOT found "
			       "(" NIPQUAD_FMT ", %d)->(" NIPQUAD_FMT ", %d)\n",
			       NIPQUAD(iph->saddr), ntohs(th->source),
			       NIPQUAD(iph->daddr), ntohs(th->dest));
		return 1;
	}

	if (!hash_expected && hash_location) {
		LIMIT_NETDEBUG(KERN_INFO "MD5 Hash NOT expected but found "
			       "(" NIPQUAD_FMT ", %d)->(" NIPQUAD_FMT ", %d)\n",
			       NIPQUAD(iph->saddr), ntohs(th->source),
			       NIPQUAD(iph->daddr), ntohs(th->dest));
		return 1;
	}

	/* Okay, so this is hash_expected and hash_location -
	 * so we need to calculate the checksum.
	 */
	genhash = tcp_v4_do_calc_md5_hash(newhash,
					  hash_expected,
					  iph->saddr, iph->daddr,
					  th, sk->sk_protocol,
					  skb->len);

	if (genhash || memcmp(hash_location, newhash, 16) != 0) {
		if (net_ratelimit()) {
			printk(KERN_INFO "MD5 Hash failed for "
			       "(" NIPQUAD_FMT ", %d)->(" NIPQUAD_FMT ", %d)%s\n",
			       NIPQUAD(iph->saddr), ntohs(th->source),
			       NIPQUAD(iph->daddr), ntohs(th->dest),
			       genhash ? " tcp_v4_calc_md5_hash failed" : "");
		}
		return 1;
	}
	return 0;
}

#endif

struct request_sock_ops tcp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct tcp_request_sock),
	.rtx_syn_ack	=	tcp_v4_send_synack,
	.send_ack	=	tcp_v4_reqsk_send_ack,
	.destructor	=	tcp_v4_reqsk_destructor,
	.send_reset	=	tcp_v4_send_reset,
};

#ifdef CONFIG_TCP_MD5SIG
static struct tcp_request_sock_ops tcp_request_sock_ipv4_ops = {
	.md5_lookup	=	tcp_v4_reqsk_md5_lookup,
};
#endif

static struct timewait_sock_ops tcp_timewait_sock_ops = {
	.twsk_obj_size	= sizeof(struct tcp_timewait_sock),
	.twsk_unique	= tcp_twsk_unique,
	.twsk_destructor= tcp_twsk_destructor,
};

// tcp_v4_conn_request函数中将初始化序列号，发送一个有SYN和ACK标志的回答数据段
// 并将tcp连接状态设置为TCP_SYN_RECV
int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct inet_request_sock *ireq;
	struct tcp_options_received tmp_opt;
	struct request_sock *req;
	__be32 saddr = skb->nh.iph->saddr;
	__be32 daddr = skb->nh.iph->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
	struct dst_entry *dst = NULL;
#ifdef CONFIG_SYN_COOKIES
	int want_cookie = 0;
#else
#define want_cookie 0 /* Argh, why doesn't gcc optimize this :( */
#endif

	/* Never answer to SYNs send to broadcast or multicast */
	// 如果SYN段发送到广播地址或组播地址，则直接返回不作处理
	if (((struct rtable *)skb->dst)->rt_flags &
	    (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	// 如果syn请求连接队列已满且isn为零，则需作特别处理，这里的isn就是TCP_SKB_CB(skb)->when
	// 而TCP_SKB_CB(skb)->when在tcp接收处理一开始就被清零，因此这里isn为零总成立
	if (inet_csk_reqsk_queue_is_full(sk) && !isn) {
#ifdef CONFIG_SYN_COOKIES
		// 如果启用了syncookie，则设置启用syncookies标志，以便在后续的处理中使用syncookies规则来处理
		if (sysctl_tcp_syncookies) {
			want_cookie = 1;
		} else
#endif
		// 如果没有启用syncookies，则此时不能再接收新的syn连接请求，只能丢弃
		goto drop;
	}

	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 */
	// 如果连接队列长度已达到上限且SYN请求队列中至少有一个握手过程中没有重传过段
	// 则丢弃当前连接请求
	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1)
		goto drop;

	// 可以接收并处理连接请求，调用reqsk_alloc()分配一个连接请求块，用于保存连接请求信息，同时初始化
	// 在建立连接过程中用来发送ACK,RST段的操作集合，以便在建立连接过程中能方便地调用这些接口
	req = reqsk_alloc(&tcp_request_sock_ops);
	if (!req)
		goto drop;

#ifdef CONFIG_TCP_MD5SIG
	// 通过tcp md5签名来保护bgp会话操作，本书不作讨论
	tcp_rsk(req)->af_specific = &tcp_request_sock_ipv4_ops;
#endif
	// 清除tcp选项后初始化mss_clamp和user_mss
	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = 536;
	tmp_opt.user_mss  = tcp_sk(sk)->rx_opt.user_mss;

	// 调用tcp_parse_options()解析syn段中的tcp选项
	tcp_parse_options(skb, &tmp_opt, 0);

	// 如果启动了syncookie，则清除已解析的tcp选项
	if (want_cookie) {
		tcp_clear_options(&tmp_opt);
		tmp_opt.saw_tstamp = 0;
	}

	// 如果tcp段存在时间戳选项，而时间戳又为空，则将有关标识清零
	if (tmp_opt.saw_tstamp && !tmp_opt.rcv_tsval) {
		/* Some OSes (unknown ones, but I see them on web server, which
		 * contains information interesting only for windows'
		 * users) do not send their stamp in SYN. It is easy case.
		 * We simply do not advertise TS support.
		 */
		tmp_opt.saw_tstamp = 0;
		tmp_opt.tstamp_ok  = 0;
	}
	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

	// 根据接收到syn段中的选项和序号来初始化连接请求块信息
	tcp_openreq_init(req, &tmp_opt, skb);

	// 如果安全检测失败，则丢弃该syn段
	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	// 初始化tcp层次的连接请求信息块，包括目的地址、源地址，并调用tcp_v4_save_options()
	// 从IP层私有控制块中获取IP选项保存到传输控制块的opt中，包括mss、窗口扩大因子，显示拥塞控制通知等
	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->opt = tcp_v4_save_options(sk, skb);
	if (!want_cookie)
		TCP_ECN_create_request(req, skb->h.th);

	if (want_cookie) {
		// 如果启动了syncookie，则每60s告警一次可能受到synflood攻击，同时由客户端ip地址
		// 客户端端口、服务端ip地址、服务端端口、客户端序列号等要素经hash运算后加密得到服务端
		// 初始序列号
#ifdef CONFIG_SYN_COOKIES
		syn_flood_warning(skb);
#endif
		isn = cookie_v4_init_sequence(sk, skb, &req->mss);
	} else if (!isn) {
		struct inet_peer *peer = NULL;

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		// 进入TIMEWAIT状态时，从对端信息块中获取时间戳，在新的连接请求之前检测PAWS
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet_csk_route_req(sk, req)) != NULL &&
		    (peer = rt_get_peer((struct rtable *)dst)) != NULL &&
		    peer->v4daddr == saddr) {
			if (xtime.tv_sec < peer->tcp_ts_stamp + TCP_PAWS_MSL &&
			    (s32)(peer->tcp_ts - req->ts_recent) >
							TCP_PAWS_WINDOW) {
				NET_INC_STATS_BH(LINUX_MIB_PAWSPASSIVEREJECTED);
				dst_release(dst);
				goto drop_and_free;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		// 在未启动syncookies的情况下受到synflood攻击，则丢弃接收到的段
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 (!peer || !peer->tcp_ts_stamp) &&
			 (!dst || !dst_metric(dst, RTAX_RTT))) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: drop open "
				       "request from %u.%u.%u.%u/%u\n",
				       NIPQUAD(saddr),
				       ntohs(skb->h.th->source));
			dst_release(dst);
			goto drop_and_free;
		}

		// 由源地址、源端口、目的地址以及目的端口计算出服务端初始序列号
		isn = tcp_v4_init_sequence(skb);
	}
	tcp_rsk(req)->snt_isn = isn;

	// 调用tcp_v4_send_synack()组织并发送syn+ack段给客户端
	if (tcp_v4_send_synack(sk, req, dst))
		goto drop_and_free;

	if (want_cookie) {
		// 如果启用了syncookies，则是根据序号来判断三次握手的，因此无需保存连接请求，直接将其释放
	   	reqsk_free(req);
	} else {
		// 如果未启用syncookies，则需要将连接请求块保存到其父传输控制块中的散列表中
		inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
	}
	return 0;

drop_and_free:
	reqsk_free(req);
drop:
	return 0;
}


/*
 * The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 */
// 完成三次握手后，为新连接创建一个传输控制块，并将其初始化。在创建传输控制块之前
// 需检测已经建立但未被accept的"子"传输控制块数量是否已经达到上限，并为"子"传输
// 控制块获取路由入口
struct sock *tcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif

	// 如果已经建立但未被accept的"子"传输控制块数量已经达到上限，则不能再创建新的传输控制块
	// 跳转到exit_overflow处统计后直接返回NULL
	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	// 在创建"子"传输控制块前，需根据目的地址、源地址、TOS等获取其目的路由缓存
	if (!dst && (dst = inet_csk_route_req(sk, req)) == NULL)
		goto exit;

	// 为对方创建"子"传输控制块，并进行一定的初始化
	newsk = tcp_create_openreq_child(sk, req, skb);
	if (!newsk)
		goto exit;

	// 设置"子"传输控制块的GSO类型、路由缓存项，同时确定输出网络接口的特性，包括是否支持GSO
	// 是否支持分散聚合IO，是否支持硬件执行校验和，需要说明的是，在决定发送是否进行GSO时
	// 不但需根据网络设备特性，还需根据传输控制块是否支持或支持何种GSO方式
	newsk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(newsk, dst);

	// 初始化传输控制块中的一些成员，包括目的地址、发送地址、ip选项、组播的网络接口、ttl、ip选项长度等
	newtp		      = tcp_sk(newsk);
	newinet		      = inet_sk(newsk);
	ireq		      = inet_rsk(req);
	newinet->daddr	      = ireq->rmt_addr;
	newinet->rcv_saddr    = ireq->loc_addr;
	newinet->saddr	      = ireq->loc_addr;
	newinet->opt	      = ireq->opt;
	ireq->opt	      = NULL;
	newinet->mc_index     = inet_iif(skb);
	newinet->mc_ttl	      = skb->nh.iph->ttl;
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (newinet->opt)
		inet_csk(newsk)->icsk_ext_hdr_len = newinet->opt->optlen;
	newinet->id = newtp->write_seq ^ jiffies;

	// 初始化有关路径mtu发现的信息，如是否启用路径mtu发现，路径mtu发现探测数据包的大小
	tcp_mtup_init(newsk);
	// 根据存储在路由项中的路径mtu来设置"子"传输控制块当前的mss
	tcp_sync_mss(newsk, dst_mtu(dst));
	// 根据存储在路由项中的mss来设置"子"传输控制块最大段长度
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
	// 初始化用于延时发送ack段控制数据块中的rcv_mss
	tcp_initialize_rcv_mss(newsk);

#ifdef CONFIG_TCP_MD5SIG
	/* Copy over the MD5 key from the original socket */
	if ((key = tcp_v4_md5_do_lookup(sk, newinet->daddr)) != NULL) {
		/*
		 * We're using one, so create a matching key
		 * on the newsk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		char *newkey = kmemdup(key->key, key->keylen, GFP_ATOMIC);
		if (newkey != NULL)
			tcp_v4_md5_do_add(newsk, inet_sk(sk)->daddr,
					  newkey, key->keylen);
	}
#endif

	// 将"子"传输控制块加入到ehash散列表中，这样就可以正常接收tcp段了
	__inet_hash(&tcp_hashinfo, newsk, 0);
	// 虽然"子"传输控制块没有显示与本地端口绑定，事实上已经进行了绑定，因此
	// 该"子"传输控制块需和本地端口信息作相应的绑定
	__inet_inherit_port(&tcp_hashinfo, sk, newsk);

	return newsk;

exit_overflow:
	NET_INC_STATS_BH(LINUX_MIB_LISTENOVERFLOWS);
exit:
	NET_INC_STATS_BH(LINUX_MIB_LISTENDROPS);
	dst_release(dst);
	return NULL;
}

// tcp_v4_hnd_req()用来处理作为建立连接三次握手中最后一次握手的ack段
static struct sock *tcp_v4_hnd_req(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	struct iphdr *iph = skb->nh.iph;
	struct sock *nsk;
	struct request_sock **prev;
	/* Find possible connection requests. */
	// 如果根据源端口、源地址、目的地址在"父"传输控制块的连接请求散列表中查找相应的连接请求块成功
	// 则说明三次握手中的前两次已经完成，接下来进行第三次握手的确认
	struct request_sock *req = inet_csk_search_req(sk, &prev, th->source,
						       iph->saddr, iph->daddr);
	if (req)
		return tcp_check_req(sk, skb, req, prev);

	// 如果传输控制块不在连接请求散列表中，则有可能在ehash散列表中，因此在ehash散列表中查找
	nsk = inet_lookup_established(&tcp_hashinfo, skb->nh.iph->saddr,
				      th->source, skb->nh.iph->daddr,
				      th->dest, inet_iif(skb));

	// 在ehash散列表中查找成功的情况下，如果该传输控制块不处于TIME_WAIT状态，返回该传输控制块
	// 否则说明接收到的段无效，返回NULL表示丢弃该段
	if (nsk) {
		if (nsk->sk_state != TCP_TIME_WAIT) {
			bh_lock_sock(nsk);
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	}

#ifdef CONFIG_SYN_COOKIES
	// 如果在编译时启用了SYN cookie，且接收到的段只有ack标志，则调用cookie_v4_check()进行第三次握手的检测
	// 服务器将客户端的ack序列号减去1，得到cookie比较值，并将客户端ip地址，客户端端口、服务器ip地址和服务器端口
	// 接收到的ip序列号以及其他一些安全数值等要素进行hash运算后，与该cookie比较值比较，如果相等，则直接完成三次握手
	// 此时不必查看该连接是否属于请求连接队列
	if (!th->rst && !th->syn && th->ack)
		sk = cookie_v4_check(sk, skb, &(IPCB(skb)->opt));
#endif
	return sk;
}

// tcp_v4_checksum_init()用于tcp段接收校验的初始化，主要是对伪首部进行校验和的计算
// 当然也有例外，如果校验和由硬件完成，则只对伪首部进行校验检测，对于全长不超过76B的tcp包
// 则直接进行伪首部和全包校验
static __sum16 tcp_v4_checksum_init(struct sk_buff *skb)
{
	// 如果tcp包本身的校验和已经由硬件完成，则只对伪首部进行校验
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!tcp_v4_check(skb->h.th, skb->len, skb->nh.iph->saddr,
				  skb->nh.iph->daddr, skb->csum)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			return 0;
		}
	}

	// 对于用软件完成校验和的操作，首先生成伪首部的部分累加和
	skb->csum = csum_tcpudp_nofold(skb->nh.iph->saddr, skb->nh.iph->daddr,
				       skb->len, IPPROTO_TCP, 0);

	// 对于全长不超过76B的tcp包直接进行全包校验，其他的包，在后续操作中完成全包校验和检测
	if (skb->len <= 76) {
		return __skb_checksum_complete(skb);
	}
	return 0;
}


/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
// 传输控制块接收处理的段都由tcp_v4_do_rcv()处理，在该函数中再根据不同的状态由不同的函数处理：
// ESTABLISHED状态的处理函数为tcp_rcv_established()，LISTEN状态且已建立半连接的处理函数为
// tcp_v4_hnd_req()，其他状态的处理函数均为tcp_rcv_state_process()
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct sock *rsk;
#ifdef CONFIG_TCP_MD5SIG
	/*
	 * We really want to reject the packet as early as possible
	 * if:
	 *  o We're expecting an MD5'd packet and this is no MD5 tcp option
	 *  o There is an MD5 option and we're not expecting one
	 */
	if (tcp_v4_inbound_md5_hash(sk, skb))
		goto discard;
#endif

	// 如果套接字当前状态为连接状态，缓冲区可能可以通过"Fast Path"路径处理，由tcp_rcv_established
	// 函数完成此功能
	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		TCP_CHECK_TIMER(sk);
		if (tcp_rcv_established(sk, skb, skb->h.th, skb->len)) {
			rsk = sk;
			goto reset;
		}
		TCP_CHECK_TIMER(sk);
		return 0;
	}

	// 通过查看tcp协议头的长度和数据包校验和的是否正确，以确认接收的数据包为完好的数据包
	if (skb->len < (skb->h.th->doff << 2) || tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		// 查看输入数据包skb是否为一个建立连接请求的syn数据包，如果收到的是一个有效的syn数据段
		// 则将套接字状态转变为接收状态，这个过程由tcp_v4_hnd_req完成，
		// 它使连接有效并返回建立连接的套接字数据结构地址struct sock *snk或NULL，返回的套接字
		// 就处于ESTABLISHED状态
		// tcp_v4_hnd_req()通常处理建立连接三次握手中最后一次握手的ack段，
		// 其他多数情况由tcp_rcv_state_process()处理
		struct sock *nsk = tcp_v4_hnd_req(sk, skb);
		if (!nsk)
			goto discard;

		// 原套接字sk继续侦听，调用tcp_child_process函数在子套接字nsk上处理接收
		// 如果接收处理成功，则函数tcp_child_process返回0，此后新的套接字就处于连接
		// 状态，可以传送和接收数据
		// 如果返回的传输控制块不是输入的侦听传输控制块，则说明建立连接成功，返回已建立连接的“子”控制块
		if (nsk != sk) {
			// 调用tcp_child_process()，初始化"子"传输控制块，如果初始化失败，则给客户端发送RST段进行复位
			if (tcp_child_process(sk, nsk, skb)) {
				rsk = nsk;
				goto reset;
			}
			return 0;
		}
	}

	TCP_CHECK_TIMER(sk);
	// 如果套接字当前不处于侦听状态，则调用tcp_rcv_state_process函数处理套接字的
	// 常规状态切换，如果返回0则说明处理成，如果返回非0则说明我们必须复位套接字连接
	if (tcp_rcv_state_process(sk, skb, skb->h.th, skb->len)) {
		rsk = sk;
		goto reset;
	}
	TCP_CHECK_TIMER(sk);
	return 0;

// 函数的3个退出标签：reset, discard和csumm_err分别处理复位套接字连接、扔掉数据包和
// 更新接收错误统计信息
reset:
	tcp_v4_send_reset(rsk, skb);
discard:
	kfree_skb(skb);
	/* Be careful here. If this function gets more complicated and
	 * gcc suffers from register pressure on the x86, sk (in %ebx)
	 * might be destroyed here. This current version compiles correctly,
	 * but you have been warned.
	 */
	return 0;

csum_err:
	TCP_INC_STATS_BH(TCP_MIB_INERRS);
	goto discard;
}

/*
 *	From tcp_input.c
 */

int tcp_v4_rcv(struct sk_buff *skb)
{
	struct tcphdr *th;
	struct sock *sk;
	int ret;

	// 指明数据包的目标地址不是本主机地址时，扔掉数据包，这种情况能发生于网络设备工作在混杂模式状态时
	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;

	/* Count it even if it's bad */
	TCP_INC_STATS_BH(TCP_MIB_INSEGS);

	// 是否能正确获取tcp协议头信息
	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		goto discard_it;

	// 读取tcp协议头信息，查看协议头中doff数据域的正确性
	th = skb->h.th;

	if (th->doff < sizeof(struct tcphdr) / 4)
		goto bad_packet;
	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

	/* An explanation is required here, I think.
	 * Packet length and doff are validated by header prediction,
	 * provided case of th->doff==0 is eliminated.
	 * So, we defer the checks. */
	// 查看数据包校验和的正确性
	if ((skb->ip_summed != CHECKSUM_UNNECESSARY &&
	     tcp_v4_checksum_init(skb)))
		goto bad_packet;

	// 将tcp协议头的某些数据域保存在skb的控制缓冲区中，以便于以后访问
	th = skb->h.th;
	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->when	 = 0;
	TCP_SKB_CB(skb)->flags	 = skb->nh.iph->tos;
	TCP_SKB_CB(skb)->sacked	 = 0;

	// 查看接收到的数据包是否属于某个打开的套接字，查看的依据是接收数据包的网络接口
	// 源端口和目的端口号，
	sk = __inet_lookup(&tcp_hashinfo, skb->nh.iph->saddr, th->source,
			   skb->nh.iph->daddr, th->dest,
			   inet_iif(skb));

	if (!sk)
		goto no_tcp_socket;

// 数据段的处理
process:
	// 一旦获取数据段所属的套接字，就查看套接字的连接状态，如果连接状态为TIME_WAIT
	// 则必须以特殊方式立即处理数据包
	if (sk->sk_state == TCP_TIME_WAIT)
		goto do_time_wait;

	// IPSec策略检查和网络过滤，如果内核配置使用了IPsec协议栈，则对数据包进行IPsec策略检查
	// 此项检查由网络过滤子系统完成，如果未通过检查，则扔掉数据包
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_relse;
	nf_reset(skb);

	if (sk_filter(sk, skb))
		goto discard_and_relse;

	skb->dev = NULL;

	bh_lock_sock_nested(sk);
	ret = 0;
	// 锁定数据包所属套接字
	if (!sock_owned_by_user(sk)) {
	// 如果配置了dma传送，则以dma方式在设备缓冲区与用户缓冲区之间复制数据
#ifdef CONFIG_NET_DMA
		struct tcp_sock *tp = tcp_sk(sk);
		if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
			tp->ucopy.dma_chan = get_softnet_dma();
		if (tp->ucopy.dma_chan)
			ret = tcp_v4_do_rcv(sk, skb);
		else
#endif
		{
			// 将数据段放入prequeue队列，数据段按"Fast Path"路径处理，不成功调用tcp_v4_do_rcv
			// 将数据段按"Slow Path"路径处理
			if (!tcp_prequeue(sk, skb))
			ret = tcp_v4_do_rcv(sk, skb);
		}
	} else
		// 如果锁定套接字不成功，则将数据放入backlog queue队列中
		sk_add_backlog(sk, skb);
	bh_unlock_sock(sk);

	sock_put(sk);

	return ret;

no_tcp_socket:
	// 如果程序执行到no_tcp_socket标签，则表明接收过程将在当前tcp套接字没有打开的情况下
	// 结束，这时仍需要完成对数据包校验和的校验，看数据包是否为一个损坏的数据包，如果数据包
	// 不正确，则更新接收错误消息，如果数据包完好无损，则意味着程序试图发送一个数据段给一个
	// 未打开的套接字，函数需要对外发送一个复位请求来关闭连接，然后扔掉数据包，释放缓存
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;

	if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
bad_packet:
		TCP_INC_STATS_BH(TCP_MIB_INERRS);
	} else {
		tcp_v4_send_reset(NULL, skb);
	}

discard_it:
	/* Discard frame. */
	kfree_skb(skb);
  	return 0;

discard_and_relse:
	sock_put(sk);
	goto discard_it;

do_time_wait:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
		inet_twsk_put(inet_twsk(sk));
		goto discard_it;
	}

	if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
		TCP_INC_STATS_BH(TCP_MIB_INERRS);
		inet_twsk_put(inet_twsk(sk));
		goto discard_it;
	}
	// 当套接字状态为TIME_WAIT时对数据段的处理，根据tcp_timewait_state_process函数返回的
	// 数据段类型做相应处理
	switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
	// 如果接收到的数据段为同步请求SYN数据段，则打开套接字连接
	case TCP_TW_SYN: {
		struct sock *sk2 = inet_lookup_listener(&tcp_hashinfo,
							skb->nh.iph->daddr,
							th->dest,
							inet_iif(skb));
		if (sk2) {
			inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
			inet_twsk_put(inet_twsk(sk));
			sk = sk2;
			goto process;
		}
		/* Fall through to ACK */
	}
	// 收到最后一个数据段为ack数据段
	case TCP_TW_ACK:
		tcp_v4_timewait_ack(sk, skb);
		break;
	case TCP_TW_RST:
		goto no_tcp_socket;
	case TCP_TW_SUCCESS:;
	}
	goto discard_it;
}

/* VJ's idea. Save last timestamp seen from this destination
 * and hold it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter synchronized
 * state.
 */

int tcp_v4_remember_stamp(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_get(sk);
	struct inet_peer *peer = NULL;
	int release_it = 0;

	if (!rt || rt->rt_dst != inet->daddr) {
		peer = inet_getpeer(inet->daddr, 1);
		release_it = 1;
	} else {
		if (!rt->peer)
			rt_bind_peer(rt, 1);
		peer = rt->peer;
	}

	if (peer) {
		if ((s32)(peer->tcp_ts - tp->rx_opt.ts_recent) <= 0 ||
		    (peer->tcp_ts_stamp + TCP_PAWS_MSL < xtime.tv_sec &&
		     peer->tcp_ts_stamp <= tp->rx_opt.ts_recent_stamp)) {
			peer->tcp_ts_stamp = tp->rx_opt.ts_recent_stamp;
			peer->tcp_ts = tp->rx_opt.ts_recent;
		}
		if (release_it)
			inet_putpeer(peer);
		return 1;
	}

	return 0;
}

int tcp_v4_tw_remember_stamp(struct inet_timewait_sock *tw)
{
	struct inet_peer *peer = inet_getpeer(tw->tw_daddr, 1);

	if (peer) {
		const struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);

		if ((s32)(peer->tcp_ts - tcptw->tw_ts_recent) <= 0 ||
		    (peer->tcp_ts_stamp + TCP_PAWS_MSL < xtime.tv_sec &&
		     peer->tcp_ts_stamp <= tcptw->tw_ts_recent_stamp)) {
			peer->tcp_ts_stamp = tcptw->tw_ts_recent_stamp;
			peer->tcp_ts	   = tcptw->tw_ts_recent;
		}
		inet_putpeer(peer);
		return 1;
	}

	return 0;
}

// 定义tcp的struct inet_connection_sock_af_ops数据结构类型的变量实例
// 并对其数据域赋初值
struct inet_connection_sock_af_ops ipv4_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.remember_stamp	   = tcp_v4_remember_stamp,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
};

#ifdef CONFIG_TCP_MD5SIG
static struct tcp_sock_af_ops tcp_sock_ipv4_specific = {
	.md5_lookup		= tcp_v4_md5_lookup,
	.calc_md5_hash		= tcp_v4_calc_md5_hash,
	.md5_add		= tcp_v4_md5_add_func,
	.md5_parse		= tcp_v4_parse_md5_keys,
};
#endif

/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
static int tcp_v4_init_sock(struct sock *sk)
{
	// 获取套接字指针
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	// 初始化out_of_order_queue队列：初始化tcp输入队列，该队列只由tcp使用
	skb_queue_head_init(&tp->out_of_order_queue);
	// 初始化传送超时时钟
	tcp_init_xmit_timers(sk);
	// 初始化prequeue输入队列，该队列用"Fast Path"接收
	tcp_prequeue_init(tp);

	// 初始化数据包重传时间，rto，介质偏差时间mdev，mdev用于衡量rtt，设置为3秒
	icsk->icsk_rto = TCP_TIMEOUT_INIT;
	tp->mdev = TCP_TIMEOUT_INIT;

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	// 初始化发送拥塞窗口的大小(send congestion window, cwnd) = 2
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	// 设置send slow start threshold为最大值
	tp->snd_ssthresh = 0x7fffffff;	/* Infinity */
	// 设置发送拥塞窗口声明snd_cwnd_clamp为最大值
	tp->snd_cwnd_clamp = ~0;
	// mms_cache是tcp最小段大小为536
	tp->mss_cache = 536;

	// 按系统配置控制值初始化tcp选项结构的重排序域reordering, 套接字的状态state
	// 目前保持关闭，初始化inet连接套接字阻塞管理操作的函数为tcp_init_congestion_ops
	tp->reordering = sysctl_tcp_reordering;
	icsk->icsk_ca_ops = &tcp_init_congestion_ops;

	sk->sk_state = TCP_CLOSE;

	// 套接字sk->sk_write_space指针，指向套接字的回调函数，当套接字的写缓冲区有效时调用该函数
	// 它指向sk_stream_write_space
	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	// 注册传输层各协议实例的struct inet_connection_sock_af_ops数据结构的变量实例
	icsk->icsk_af_ops = &ipv4_specific;
	icsk->icsk_sync_mss = tcp_sync_mss;
#ifdef CONFIG_TCP_MD5SIG
	tp->af_specific = &tcp_sock_ipv4_specific;
#endif

	// 将套接字的发送缓冲区sk_sndbuf和接收缓冲区sk_rcvbuf大小初始化为系统配置控制值
	// 可以用系统调用setsockopt来改变它们的大小
	sk->sk_sndbuf = sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_tcp_rmem[1];

	// tcp_sockets_allocated是TCP的一个全局计数器，保存了打开的tcp套接字的数量，这里对该值加1
	atomic_inc(&tcp_sockets_allocated);

	return 0;
}

int tcp_v4_destroy_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_clear_xmit_timers(sk);

	tcp_cleanup_congestion_control(sk);

	/* Cleanup up the write buffer. */
  	sk_stream_writequeue_purge(sk);

	/* Cleans up our, hopefully empty, out_of_order_queue. */
  	__skb_queue_purge(&tp->out_of_order_queue);

#ifdef CONFIG_TCP_MD5SIG
	/* Clean up the MD5 key list, if any */
	if (tp->md5sig_info) {
		tcp_v4_clear_md5_list(sk);
		kfree(tp->md5sig_info);
		tp->md5sig_info = NULL;
	}
#endif

#ifdef CONFIG_NET_DMA
	/* Cleans up our sk_async_wait_queue */
  	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif

	/* Clean prequeue, it must be empty really */
	__skb_queue_purge(&tp->ucopy.prequeue);

	/* Clean up a referenced TCP bind bucket. */
	if (inet_csk(sk)->icsk_bind_hash)
		inet_put_port(&tcp_hashinfo, sk);

	/*
	 * If sendmsg cached page exists, toss it.
	 */
	if (sk->sk_sndmsg_page) {
		__free_page(sk->sk_sndmsg_page);
		sk->sk_sndmsg_page = NULL;
	}

	atomic_dec(&tcp_sockets_allocated);

	return 0;
}

EXPORT_SYMBOL(tcp_v4_destroy_sock);

#ifdef CONFIG_PROC_FS
/* Proc filesystem TCP sock list dumping. */

static inline struct inet_timewait_sock *tw_head(struct hlist_head *head)
{
	return hlist_empty(head) ? NULL :
		list_entry(head->first, struct inet_timewait_sock, tw_node);
}

static inline struct inet_timewait_sock *tw_next(struct inet_timewait_sock *tw)
{
	return tw->tw_node.next ?
		hlist_entry(tw->tw_node.next, typeof(*tw), tw_node) : NULL;
}

static void *listening_get_next(struct seq_file *seq, void *cur)
{
	struct inet_connection_sock *icsk;
	struct hlist_node *node;
	struct sock *sk = cur;
	struct tcp_iter_state* st = seq->private;

	if (!sk) {
		st->bucket = 0;
		sk = sk_head(&tcp_hashinfo.listening_hash[0]);
		goto get_sk;
	}

	++st->num;

	if (st->state == TCP_SEQ_STATE_OPENREQ) {
		struct request_sock *req = cur;

		icsk = inet_csk(st->syn_wait_sk);
		req = req->dl_next;
		while (1) {
			while (req) {
				if (req->rsk_ops->family == st->family) {
					cur = req;
					goto out;
				}
				req = req->dl_next;
			}
			if (++st->sbucket >= icsk->icsk_accept_queue.listen_opt->nr_table_entries)
				break;
get_req:
			req = icsk->icsk_accept_queue.listen_opt->syn_table[st->sbucket];
		}
		sk	  = sk_next(st->syn_wait_sk);
		st->state = TCP_SEQ_STATE_LISTENING;
		read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
	} else {
	       	icsk = inet_csk(sk);
		read_lock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		if (reqsk_queue_len(&icsk->icsk_accept_queue))
			goto start_req;
		read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		sk = sk_next(sk);
	}
get_sk:
	sk_for_each_from(sk, node) {
		if (sk->sk_family == st->family) {
			cur = sk;
			goto out;
		}
	       	icsk = inet_csk(sk);
		read_lock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		if (reqsk_queue_len(&icsk->icsk_accept_queue)) {
start_req:
			st->uid		= sock_i_uid(sk);
			st->syn_wait_sk = sk;
			st->state	= TCP_SEQ_STATE_OPENREQ;
			st->sbucket	= 0;
			goto get_req;
		}
		read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
	}
	if (++st->bucket < INET_LHTABLE_SIZE) {
		sk = sk_head(&tcp_hashinfo.listening_hash[st->bucket]);
		goto get_sk;
	}
	cur = NULL;
out:
	return cur;
}

static void *listening_get_idx(struct seq_file *seq, loff_t *pos)
{
	void *rc = listening_get_next(seq, NULL);

	while (rc && *pos) {
		rc = listening_get_next(seq, rc);
		--*pos;
	}
	return rc;
}

static void *established_get_first(struct seq_file *seq)
{
	struct tcp_iter_state* st = seq->private;
	void *rc = NULL;

	for (st->bucket = 0; st->bucket < tcp_hashinfo.ehash_size; ++st->bucket) {
		struct sock *sk;
		struct hlist_node *node;
		struct inet_timewait_sock *tw;

		/* We can reschedule _before_ having picked the target: */
		cond_resched_softirq();

		read_lock(&tcp_hashinfo.ehash[st->bucket].lock);
		sk_for_each(sk, node, &tcp_hashinfo.ehash[st->bucket].chain) {
			if (sk->sk_family != st->family) {
				continue;
			}
			rc = sk;
			goto out;
		}
		st->state = TCP_SEQ_STATE_TIME_WAIT;
		inet_twsk_for_each(tw, node,
				   &tcp_hashinfo.ehash[st->bucket + tcp_hashinfo.ehash_size].chain) {
			if (tw->tw_family != st->family) {
				continue;
			}
			rc = tw;
			goto out;
		}
		read_unlock(&tcp_hashinfo.ehash[st->bucket].lock);
		st->state = TCP_SEQ_STATE_ESTABLISHED;
	}
out:
	return rc;
}

static void *established_get_next(struct seq_file *seq, void *cur)
{
	struct sock *sk = cur;
	struct inet_timewait_sock *tw;
	struct hlist_node *node;
	struct tcp_iter_state* st = seq->private;

	++st->num;

	if (st->state == TCP_SEQ_STATE_TIME_WAIT) {
		tw = cur;
		tw = tw_next(tw);
get_tw:
		while (tw && tw->tw_family != st->family) {
			tw = tw_next(tw);
		}
		if (tw) {
			cur = tw;
			goto out;
		}
		read_unlock(&tcp_hashinfo.ehash[st->bucket].lock);
		st->state = TCP_SEQ_STATE_ESTABLISHED;

		/* We can reschedule between buckets: */
		cond_resched_softirq();

		if (++st->bucket < tcp_hashinfo.ehash_size) {
			read_lock(&tcp_hashinfo.ehash[st->bucket].lock);
			sk = sk_head(&tcp_hashinfo.ehash[st->bucket].chain);
		} else {
			cur = NULL;
			goto out;
		}
	} else
		sk = sk_next(sk);

	sk_for_each_from(sk, node) {
		if (sk->sk_family == st->family)
			goto found;
	}

	st->state = TCP_SEQ_STATE_TIME_WAIT;
	tw = tw_head(&tcp_hashinfo.ehash[st->bucket + tcp_hashinfo.ehash_size].chain);
	goto get_tw;
found:
	cur = sk;
out:
	return cur;
}

static void *established_get_idx(struct seq_file *seq, loff_t pos)
{
	void *rc = established_get_first(seq);

	while (rc && pos) {
		rc = established_get_next(seq, rc);
		--pos;
	}
	return rc;
}

static void *tcp_get_idx(struct seq_file *seq, loff_t pos)
{
	void *rc;
	struct tcp_iter_state* st = seq->private;

	inet_listen_lock(&tcp_hashinfo);
	st->state = TCP_SEQ_STATE_LISTENING;
	rc	  = listening_get_idx(seq, &pos);

	if (!rc) {
		inet_listen_unlock(&tcp_hashinfo);
		local_bh_disable();
		st->state = TCP_SEQ_STATE_ESTABLISHED;
		rc	  = established_get_idx(seq, pos);
	}

	return rc;
}

static void *tcp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct tcp_iter_state* st = seq->private;
	st->state = TCP_SEQ_STATE_LISTENING;
	st->num = 0;
	return *pos ? tcp_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *tcp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	void *rc = NULL;
	struct tcp_iter_state* st;

	if (v == SEQ_START_TOKEN) {
		rc = tcp_get_idx(seq, 0);
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_OPENREQ:
	case TCP_SEQ_STATE_LISTENING:
		rc = listening_get_next(seq, v);
		if (!rc) {
			inet_listen_unlock(&tcp_hashinfo);
			local_bh_disable();
			st->state = TCP_SEQ_STATE_ESTABLISHED;
			rc	  = established_get_first(seq);
		}
		break;
	case TCP_SEQ_STATE_ESTABLISHED:
	case TCP_SEQ_STATE_TIME_WAIT:
		rc = established_get_next(seq, v);
		break;
	}
out:
	++*pos;
	return rc;
}

static void tcp_seq_stop(struct seq_file *seq, void *v)
{
	struct tcp_iter_state* st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_OPENREQ:
		if (v) {
			struct inet_connection_sock *icsk = inet_csk(st->syn_wait_sk);
			read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		}
	case TCP_SEQ_STATE_LISTENING:
		if (v != SEQ_START_TOKEN)
			inet_listen_unlock(&tcp_hashinfo);
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
	case TCP_SEQ_STATE_ESTABLISHED:
		if (v)
			read_unlock(&tcp_hashinfo.ehash[st->bucket].lock);
		local_bh_enable();
		break;
	}
}

static int tcp_seq_open(struct inode *inode, struct file *file)
{
	struct tcp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	struct tcp_iter_state *s;
	int rc;

	if (unlikely(afinfo == NULL))
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->family		= afinfo->family;
	s->seq_ops.start	= tcp_seq_start;
	s->seq_ops.next		= tcp_seq_next;
	s->seq_ops.show		= afinfo->seq_show;
	s->seq_ops.stop		= tcp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;
	seq	     = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

int tcp_proc_register(struct tcp_seq_afinfo *afinfo)
{
	int rc = 0;
	struct proc_dir_entry *p;

	if (!afinfo)
		return -EINVAL;
	afinfo->seq_fops->owner		= afinfo->owner;
	afinfo->seq_fops->open		= tcp_seq_open;
	afinfo->seq_fops->read		= seq_read;
	afinfo->seq_fops->llseek	= seq_lseek;
	afinfo->seq_fops->release	= seq_release_private;

	p = proc_net_fops_create(afinfo->name, S_IRUGO, afinfo->seq_fops);
	if (p)
		p->data = afinfo;
	else
		rc = -ENOMEM;
	return rc;
}

void tcp_proc_unregister(struct tcp_seq_afinfo *afinfo)
{
	if (!afinfo)
		return;
	proc_net_remove(afinfo->name);
	memset(afinfo->seq_fops, 0, sizeof(*afinfo->seq_fops));
}

static void get_openreq4(struct sock *sk, struct request_sock *req,
			 char *tmpbuf, int i, int uid)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int ttd = req->expires - jiffies;

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req);
}

static void get_tcp4_sock(struct sock *sp, char *tmpbuf, int i)
{
	int timer_active;
	unsigned long timer_expires;
	struct tcp_sock *tp = tcp_sk(sp);
	const struct inet_connection_sock *icsk = inet_csk(sp);
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->daddr;
	__be32 src = inet->rcv_saddr;
	__u16 destp = ntohs(inet->dport);
	__u16 srcp = ntohs(inet->sport);

	if (icsk->icsk_pending == ICSK_TIME_RETRANS) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= icsk->icsk_timeout;
	} else if (timer_pending(&sp->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sp->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5d %8d %lu %d %p %u %u %u %u %d",
		i, src, srcp, dest, destp, sp->sk_state,
		tp->write_seq - tp->snd_una,
		sp->sk_state == TCP_LISTEN ? sp->sk_ack_backlog :
					     (tp->rcv_nxt - tp->copied_seq),
		timer_active,
		jiffies_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		sock_i_uid(sp),
		icsk->icsk_probes_out,
		sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp,
		icsk->icsk_rto,
		icsk->icsk_ack.ato,
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		tp->snd_ssthresh >= 0xFFFF ? -1 : tp->snd_ssthresh);
}

static void get_timewait4_sock(struct inet_timewait_sock *tw,
			       char *tmpbuf, int i)
{
	__be32 dest, src;
	__u16 destp, srcp;
	int ttd = tw->tw_ttd - jiffies;

	if (ttd < 0)
		ttd = 0;

	dest  = tw->tw_daddr;
	src   = tw->tw_rcv_saddr;
	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %p",
		i, src, srcp, dest, destp, tw->tw_substate, 0, 0,
		3, jiffies_to_clock_t(ttd), 0, 0, 0, 0,
		atomic_read(&tw->tw_refcnt), tw);
}

#define TMPSZ 150

static int tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state* st;
	char tmpbuf[TMPSZ + 1];

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_LISTENING:
	case TCP_SEQ_STATE_ESTABLISHED:
		get_tcp4_sock(v, tmpbuf, st->num);
		break;
	case TCP_SEQ_STATE_OPENREQ:
		get_openreq4(st->syn_wait_sk, v, tmpbuf, st->num, st->uid);
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
		get_timewait4_sock(v, tmpbuf, st->num);
		break;
	}
	seq_printf(seq, "%-*s\n", TMPSZ - 1, tmpbuf);
out:
	return 0;
}

static struct file_operations tcp4_seq_fops;
static struct tcp_seq_afinfo tcp4_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "tcp",
	.family		= AF_INET,
	.seq_show	= tcp4_seq_show,
	.seq_fops	= &tcp4_seq_fops,
};

int __init tcp4_proc_init(void)
{
	return tcp_proc_register(&tcp4_seq_afinfo);
}

void tcp4_proc_exit(void)
{
	tcp_proc_unregister(&tcp4_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

// 协议实例通过int proto_register(struct proto *prot, int alloc_slab)函数注册到tcp/ip协议栈中
// tcp协议实例与套接字之间的接口函数在inet_init中注册并初始化
struct proto tcp_prot = {
	.name			= "TCP",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= tcp_ioctl,
	// init钩子在inet_create中被调用
	.init			= tcp_v4_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.sendmsg		= tcp_sendmsg,
	.recvmsg		= tcp_recvmsg,
	.backlog_rcv		= tcp_v4_do_rcv,
	.hash			= tcp_v4_hash,
	.unhash			= tcp_unhash,
	.get_port		= tcp_v4_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcp_sock),
	.twsk_prot		= &tcp_timewait_sock_ops,
	.rsk_prot		= &tcp_request_sock_ops,
#ifdef CONFIG_COMPAT
	.compat_setsockopt	= compat_tcp_setsockopt,
	.compat_getsockopt	= compat_tcp_getsockopt,
#endif
};

void __init tcp_v4_init(struct net_proto_family *ops)
{
	if (inet_csk_ctl_sock_create(&tcp_socket, PF_INET, SOCK_RAW,
				     IPPROTO_TCP) < 0)
		panic("Failed to create the TCP control socket.\n");
}

EXPORT_SYMBOL(ipv4_specific);
EXPORT_SYMBOL(tcp_hashinfo);
EXPORT_SYMBOL(tcp_prot);
EXPORT_SYMBOL(tcp_unhash);
EXPORT_SYMBOL(tcp_v4_conn_request);
EXPORT_SYMBOL(tcp_v4_connect);
EXPORT_SYMBOL(tcp_v4_do_rcv);
EXPORT_SYMBOL(tcp_v4_remember_stamp);
EXPORT_SYMBOL(tcp_v4_send_check);
EXPORT_SYMBOL(tcp_v4_syn_recv_sock);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(tcp_proc_register);
EXPORT_SYMBOL(tcp_proc_unregister);
#endif
EXPORT_SYMBOL(sysctl_local_port_range);
EXPORT_SYMBOL(sysctl_tcp_low_latency);

