/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The User Datagram Protocol (UDP).
 *
 * Version:	$Id: udp.c,v 1.102 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 * Fixes:
 *		Alan Cox	:	verify_area() calls
 *		Alan Cox	: 	stopped close while in use off icmp
 *					messages. Not a fix but a botch that
 *					for udp at least is 'valid'.
 *		Alan Cox	:	Fixed icmp handling properly
 *		Alan Cox	: 	Correct error for oversized datagrams
 *		Alan Cox	:	Tidied select() semantics. 
 *		Alan Cox	:	udp_err() fixed properly, also now 
 *					select and read wake correctly on errors
 *		Alan Cox	:	udp_send verify_area moved to avoid mem leak
 *		Alan Cox	:	UDP can count its memory
 *		Alan Cox	:	send to an unknown connection causes
 *					an ECONNREFUSED off the icmp, but
 *					does NOT close.
 *		Alan Cox	:	Switched to new sk_buff handlers. No more backlog!
 *		Alan Cox	:	Using generic datagram code. Even smaller and the PEEK
 *					bug no longer crashes it.
 *		Fred Van Kempen	: 	Net2e support for sk->broadcast.
 *		Alan Cox	:	Uses skb_free_datagram
 *		Alan Cox	:	Added get/set sockopt support.
 *		Alan Cox	:	Broadcasting without option set returns EACCES.
 *		Alan Cox	:	No wakeup calls. Instead we now use the callbacks.
 *		Alan Cox	:	Use ip_tos and ip_ttl
 *		Alan Cox	:	SNMP Mibs
 *		Alan Cox	:	MSG_DONTROUTE, and 0.0.0.0 support.
 *		Matt Dillon	:	UDP length checks.
 *		Alan Cox	:	Smarter af_inet used properly.
 *		Alan Cox	:	Use new kernel side addressing.
 *		Alan Cox	:	Incorrect return on truncated datagram receive.
 *	Arnt Gulbrandsen 	:	New udp_send and stuff
 *		Alan Cox	:	Cache last socket
 *		Alan Cox	:	Route cache
 *		Jon Peatfield	:	Minor efficiency fix to sendto().
 *		Mike Shaver	:	RFC1122 checks.
 *		Alan Cox	:	Nonblocking error fix.
 *	Willy Konynenberg	:	Transparent proxying support.
 *		Mike McLagan	:	Routing by source
 *		David S. Miller	:	New socket lookup architecture.
 *					Last socket cache retained as it
 *					does have a high hit rate.
 *		Olaf Kirch	:	Don't linearise iovec on sendmsg.
 *		Andi Kleen	:	Some cleanups, cache destination entry
 *					for connect. 
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Melvin Smith	:	Check msg_name not msg_namelen in sendto(),
 *					return ENOTCONN for unconnected sockets (POSIX)
 *		Janos Farkas	:	don't deliver multi/broadcasts to a different
 *					bound-to-device socket
 *	Hirokazu Takahashi	:	HW checksumming for outgoing UDP
 *					datagrams.
 *	Hirokazu Takahashi	:	sendfile() on UDP works now.
 *		Arnaldo C. Melo :	convert /proc/net/udp to seq_file
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov:		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *	Derek Atkins <derek@ihtfp.com>: Add Encapulation Support
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
 
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include "udp_impl.h"

/*
 *	Snmp MIB for the UDP layer
 */

DEFINE_SNMP_STAT(struct udp_mib, udp_statistics) __read_mostly;

struct hlist_head udp_hash[UDP_HTABLE_SIZE];
DEFINE_RWLOCK(udp_hash_lock);

static int udp_port_rover;

static inline int __udp_lib_lport_inuse(__u16 num, struct hlist_head udptable[])
{
	struct sock *sk;
	struct hlist_node *node;

	sk_for_each(sk, node, &udptable[num & (UDP_HTABLE_SIZE - 1)])
		if (inet_sk(sk)->num == num)
			return 1;
	return 0;
}

/**
 *  __udp_lib_get_port  -  UDP/-Lite port lookup for IPv4 and IPv6
 *
 *  @sk:          socket struct in question // 待绑定的传输控制块
 *  @snum:        port number to look up // 绑定的端口号
 *  @udptable:    hash list table, must be of UDP_HTABLE_SIZE　// 管理UDP传输控制块的散列表
 *  @port_rover:  pointer to record of last unallocated port　// 最近一次自动绑定的端口号
 *  @saddr_comp:  AF-dependent comparison of bound local IP addresses　// 用于比较两个传输
　*  控制块的接收地址是否相等	
 */
int __udp_lib_get_port(struct sock *sk, unsigned short snum,
		       struct hlist_head udptable[], int *port_rover,
		       int (*saddr_comp)(const struct sock *sk1,
					 const struct sock *sk2 )    )
{
	struct hlist_node *node;
	struct hlist_head *head;
	struct sock *sk2;
	int    error = 1;

	write_lock_bh(&udp_hash_lock);
	if (snum == 0) {
		int best_size_so_far, best, result, i;
		// 当udp_port_rover不在指定范围内，则被强制设定为指定范围的最小值
		if (*port_rover > sysctl_local_port_range[1] ||
		    *port_rover < sysctl_local_port_range[0])
			*port_rover = sysctl_local_port_range[0];
		// 为了使UDP传输控制块在udp_hash散列表中的分布比较均匀，选择如下方法查找端口号
		best_size_so_far = 32767;
		best = result = *port_rover;
		for (i = 0; i < UDP_HTABLE_SIZE; i++, result++) {
			int size;

			head = &udptable[result & (UDP_HTABLE_SIZE - 1)];
			if (hlist_empty(head)) {
				if (result > sysctl_local_port_range[1])
					result = sysctl_local_port_range[0] +
						((result - sysctl_local_port_range[0]) &
						 (UDP_HTABLE_SIZE - 1));
				goto gotit;
			}
			size = 0;
			sk_for_each(sk2, node, head) {
				if (++size >= best_size_so_far)
					goto next;
			}
			best_size_so_far = size;
			best = result;
		next:
			;
		}
		result = best;
		for(i = 0; i < (1 << 16) / UDP_HTABLE_SIZE; i++, result += UDP_HTABLE_SIZE) {
			if (result > sysctl_local_port_range[1])
				result = sysctl_local_port_range[0]
					+ ((result - sysctl_local_port_range[0]) &
					   (UDP_HTABLE_SIZE - 1));
			if (! __udp_lib_lport_inuse(result, udptable))
				break;
		}
		if (i >= (1 << 16) / UDP_HTABLE_SIZE)
			goto fail;
gotit:
		// 如果查找到可用的端口号，则保存该端口号，同时更新全局变量udp_port_rover
		// 下次再次自动绑定端口号时，再从udp_port_rover的值起开始查找
		*port_rover = snum = result;
	} else {
		// 如果指定了端口，则根据端口号得到该散列表的入口，并遍历该链表检测该端口
		// 是否可用，一旦检测到该指定端口不能使用，则返回相应的错误
		head = &udptable[snum & (UDP_HTABLE_SIZE - 1)];

		sk_for_each(sk2, node, head)
			if (inet_sk(sk2)->num == snum                        &&
			    sk2 != sk                                        &&
			    (!sk2->sk_reuse        || !sk->sk_reuse)         &&
			    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if
			     || sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
			    (*saddr_comp)(sk, sk2)                             )
				goto fail;
	}
	// 确定端口可用后，则将端口号设置到传输控制块中，并将该传输控制块添加到udp_hash散列表中
	inet_sk(sk)->num = snum;
	if (sk_unhashed(sk)) {
		head = &udptable[snum & (UDP_HTABLE_SIZE - 1)];
		sk_add_node(sk, head);
		sock_prot_inc_use(sk->sk_prot);
	}
	error = 0;
fail:
	write_unlock_bh(&udp_hash_lock);
	return error;
}

__inline__ int udp_get_port(struct sock *sk, unsigned short snum,
			int (*scmp)(const struct sock *, const struct sock *))
{
	return  __udp_lib_get_port(sk, snum, udp_hash, &udp_port_rover, scmp);
}

inline int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return 	( !ipv6_only_sock(sk2)  &&
		  (!inet1->rcv_saddr || !inet2->rcv_saddr ||
		   inet1->rcv_saddr == inet2->rcv_saddr      ));
}

static inline int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	return udp_get_port(sk, snum, ipv4_rcv_saddr_equal);
}

/* UDP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 */
static struct sock *__udp4_lib_lookup(__be32 saddr, __be16 sport,
				      __be32 daddr, __be16 dport,
				      int dif, struct hlist_head udptable[])
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

	read_lock(&udp_hash_lock);
	sk_for_each(sk, node, &udptable[hnum & (UDP_HTABLE_SIZE - 1)]) {
		struct inet_sock *inet = inet_sk(sk);

		if (inet->num == hnum && !ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);
			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score+=2;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score+=2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			if(score == 9) {
				result = sk;
				break;
			} else if(score > badness) {
				result = sk;
				badness = score;
			}
		}
	}
	if (result)
		sock_hold(result);
	read_unlock(&udp_hash_lock);
	return result;
}

static inline struct sock *udp_v4_mcast_next(struct sock *sk,
					     __be16 loc_port, __be32 loc_addr,
					     __be16 rmt_port, __be32 rmt_addr,
					     int dif)
{
	struct hlist_node *node;
	struct sock *s = sk;
	unsigned short hnum = ntohs(loc_port);

	sk_for_each_from(s, node) {
		struct inet_sock *inet = inet_sk(s);

		if (inet->num != hnum					||
		    (inet->daddr && inet->daddr != rmt_addr)		||
		    (inet->dport != rmt_port && inet->dport)		||
		    (inet->rcv_saddr && inet->rcv_saddr != loc_addr)	||
		    ipv6_only_sock(s)					||
		    (s->sk_bound_dev_if && s->sk_bound_dev_if != dif))
			continue;
		if (!ip_mc_sf_allow(s, loc_addr, rmt_addr, dif))
			continue;
		goto found;
  	}
	s = NULL;
found:
  	return s;
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.  
 * Header points to the ip header of the error packet. We move
 * on past this. Then (as it used to claim before adjustment)
 * header points to the first 8 bytes of the udp header.  We need
 * to find the appropriate port.
 */

void __udp4_lib_err(struct sk_buff *skb, u32 info, struct hlist_head udptable[])
{
	struct inet_sock *inet;
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct udphdr *uh = (struct udphdr*)(skb->data+(iph->ihl<<2));
	int type = skb->h.icmph->type;
	int code = skb->h.icmph->code;
	struct sock *sk;
	int harderr;
	int err;

	sk = __udp4_lib_lookup(iph->daddr, uh->dest, iph->saddr, uh->source,
			       skb->dev->ifindex, udptable		    );
	if (sk == NULL) {
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
    	  	return;	/* No socket for error */
	}

	err = 0;
	harderr = 0;
	inet = inet_sk(sk);

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
			if (inet->pmtudisc != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	}

	/*
	 *      RFC1122: OK.  Passes ICMP errors back to application, as per 
	 *	4.1.3.3.
	 */
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else {
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8*)(uh+1));
	}
	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

__inline__ void udp_err(struct sk_buff *skb, u32 info)
{
	return __udp4_lib_err(skb, info, udp_hash);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}

/**
 * 	udp4_hwcsum_outgoing  -  handle outgoing HW checksumming
 * 	@sk: 	socket we are sending on
 * 	@skb: 	sk_buff containing the filled-in UDP header
 * 	        (checksum field must be zeroed out)
 */
static void udp4_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
				 __be32 src, __be32 dst, int len      )
{
	unsigned int offset;
	struct udphdr *uh = skb->h.uh;
	__wsum csum = 0;

	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/*
		 * Only one fragment on the socket.
		 */
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, 0);
	} else {
		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		offset = skb->h.raw - skb->data;
		skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);

		skb->ip_summed = CHECKSUM_NONE;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			csum = csum_add(csum, skb->csum);
		}

		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}

/*
 * Push out all pending data as one UDP datagram. Socket is locked.
 */
// 将待发送数据打包成一个UDP数据报输出，该函数的逻辑比较简单，在设置了传输层源端口
// 目的端口和数据长度等字段，准备了校验和之后，即交由ip_push_pending_frames()
// 作进一步处理
static int udp_push_pending_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi *fl = &inet->cork.fl;
	struct sk_buff *skb;
	struct udphdr *uh;
	int err = 0;
	__wsum csum = 0;

	/* Grab the skbuff where UDP header space exists. */
	// 如果发送队列中没有报文，则无需再作发送操作
	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	/*
	 * Create a UDP header
	 */
	// 设置待发送数据报的源、目的端口和长度
	uh = skb->h.uh;
	uh->source = fl->fl_ip_sport;
	uh->dest = fl->fl_ip_dport;
	uh->len = htons(up->len);
	uh->check = 0;

	if (up->pcflag)  				 /*     UDP-Lite      */
		// 如果是轻量级UDP，则需要对数据报的前cscov个字节进行校验和的计算
		csum  = udplite_csum_outgoing(sk, skb);

	else if (sk->sk_no_check == UDP_CSUM_NOXMIT) {   /* UDP csum disabled */
		// 如果禁止UDP数据报校验和，则设置SKB中的校验标志为CHECKSUM_NONE
		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
		// 如果是由硬件作校验和计算，则为硬件指针校验和作准备
		udp4_hwcsum_outgoing(sk, skb, fl->fl4_src,fl->fl4_dst, up->len);
		goto send;

	} else						 /*   `normal' UDP    */
		// 其他情况则进行普通的校验和计算
		csum = udp_csum_outgoing(sk, skb);

	/* add protocol-dependent pseudo-header */
	// 将计算得到的校验和设置到UDP首部中
	uh->check = csum_tcpudp_magic(fl->fl4_src, fl->fl4_dst, up->len,
				      sk->sk_protocol, csum             );
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	// 完成校验和的设置后，调用IP层接口输出UDP数据报
	err = ip_push_pending_frames(sk);
out:
	// 复位待发送数据的长度和发送状态
	up->len = 0;
	up->pending = 0;
	return err;
}

// udp_sendmsg()完成的功能是从用户地址空间接收发送数据，复制到内核地址空间
// udp_sendmsg()实现了UDP数据报的组织和发送，首先获取发送的目的地址和目的端口
// 然后处理控制信息，接着选路，最后将数据分片并组成UDP数据报发送出去
// iocb: 异步IO控制块，用于提高对用户地址空间操作效率的数据结构
// sk: 指向打开的套接字的数据结构，其中包含了该套接字的所有设置和选项信息
// msg: 存放和管理来自用户地址空间的数据
// len: 从用户地址空间复制数据的总长度
int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
	// 用输入参数初始化函数局部变量
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	int ulen = len;
	// ipc中存放从IP层的ICMP协议返回的控制消息值
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	// connected存放数据包目标路由是否已经缓存的标志
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	// 获取pcflag标志确定该套接口是普通的UDP套接口还是轻量级UDP套接口
	int err, is_udplite = up->pcflag;
	// 由UDP_CORK选项值，或发送标志中的MSG_MORE标志来确定发送者是否还有更多的数据需要判断
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);

	// 由于IP数据报的限制，UDP数据报最长为64KB，在此检测UDP数据报长度是否达到64KB
	// 如果达到，则UDP数据报长度无效
	if (len > 0xFFFF)
		return -EMSGSIZE;

	/* 
	 *	Check the flags.
	 */

	// 用户程序是否对udp套接字设置了非法标志，udp不支持发送带外数据
	if (msg->msg_flags&MSG_OOB)	/* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;

	if (up->pending) {		// 套接字中有挂起的数据帧等待发送
		/*
		 * There are pending frames.
	 	 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);		// 获取套接字
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				// 如果pending值非0亦非AF_INET，则说明该值无效，返回错误码
				release_sock(sk);
				return -EINVAL;
			}
			// 如果UDP正在输出数据过程中，则跳转到do_apppend_data处直接处理UDP数据
 			goto do_append_data;
		}
		release_sock(sk);
	}
	// 累计UDP数据报长度，数据长度加上UDP首部长度
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address. 
	 */
	if (msg->msg_name) {
		// 处理msg中带有目的地址的情况，通常调用sendto发送UDP数据
		// 对目标地址做正确性检查
		struct sockaddr_in * usin = (struct sockaddr_in*)msg->msg_name;
		if (msg->msg_namelen < sizeof(*usin))	// 地址长度是否正确
			return -EINVAL;
		// 校验目的地址所属地址族，必须为AF_INET
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		// 将目的地址和端口缓存到临时变量daddr、dport中，同时校验目的端口不能为0
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		// 处理msg中没有目的地址的情况，通常调用send发送UDP数据前调用了connect

		// UDP套接口调用connect()后，UDP传输控制块状态为TCP_ESTABLISHED
		// 因此在发送UDP数据报时，如果未指明目的地址又没有调用connect()连接
		// 则返回EDESTADDRREQ错误，即未指明套接口的目的地址
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		// 如果套接字已连接，则用连接信息初始化目标IP地址和端口号
		daddr = inet->daddr;
		dport = inet->dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		// 如果是"已连接"的UDP套接口，则设置connected标志，在后续查找路由的过程中
		// 可以作快速处理
		connected = 1;
  	}
  	// 在处理待发送的控制信息之前，先由传输控制块中的信息初始化ipc的源地址和输出网络设备索引
	ipc.addr = inet->saddr;

	ipc.oif = sk->sk_bound_dev_if;
	if (msg->msg_controllen) {
		// 有控制信息要处理

		// 控制信息长度不为空，套接字设置的是IP层控制信息，将IP层选项设置在ipc变量中
		err = ip_cmsg_send(msg, &ipc);
		if (err)
			return err;
		// 如果存在IP选项，则设置free标志，表示ipc中opt指向的IP选项信息是在
		// ip_cmsg_send()中分配的，处理完成后需释放
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	// 如果发送的数据中没有IP选项控制信息，则从inet_sock结构的opt中获取IP选项信息
	if (!ipc.opt)
		ipc.opt = inet->opt;

	// 由于控制信息需保存目的地址，因此将源地址保存到saddr中
	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	// 如果存在宽松或严格源站路由IP选项，则不能根据目的地址选路，而应将选项的下一站地址
	// 作为目的地址来选路，因此在此将下一站地址保存到临时变量中，供后续的选路作为目的地址
	// 同时，因为后续需要重新选路，因此复位connected标志
	if (ipc.opt && ipc.opt->srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->faddr;
		connected = 0;
	}
	tos = RT_TOS(inet->tos);
	// 如果设置了SOCK_LOCALROUTE选项，或发送时设置了MSG_DONTROUTE标志
	// 再或者在IP选项中存在严格源站路由，则说明目的地址或下一跳必定位于本地子网
	// 因此在tos变量中设置RTO_ONLINK标志，后续查找路由时表示与目的地直连
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) || 
	    (ipc.opt && ipc.opt->is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	// 处理目的地址为组播地址的情况
	if (MULTICAST(daddr)) {
		// 如果发送的是组播报文，且在控制信息中没有指定组播输出网络设备
		// 或组播源地址，则使用IP_MULTICAST_IF选项设置默认的输出网络
		// 设备和组播源地址
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		// 由于是组播报文，因此需要在路由表中查找
		connected = 0;
	}

	// 获取相应路由缓存项
	if (connected)
		// 对于已建立连接又没有发送控制信息的UDP套接口，直接从套接口中
		// 获取路由缓存项
		rt = (struct rtable*)sk_dst_check(sk, 0);

	// 对于未建立"连接"的UDP套接口，或者发送了控制信息，或者是组播报文，
	// 则需在路由表中查找路由，此外如果通过优化方式没有获得路由，则也只能在
	// 路由表中查找路由项
	if (rt == NULL) {
		struct flowi fl = { .oif = ipc.oif,
				    .nl_u = { .ip4_u =
					      { .daddr = faddr,
						.saddr = saddr,
						.tos = tos } },
				    .proto = sk->sk_protocol,
				    .uli_u = { .ports =
					       { .sport = inet->sport,
						 .dport = dport } } };
		security_sk_classify_flow(sk, &fl);
		// 在路由表中搜索路由
		err = ip_route_output_flow(&rt, &fl, sk, !(msg->msg_flags&MSG_DONTWAIT));
		if (err)
			goto out;

		// 如果得到的路由的目的地址是一个广播地址，但套接口本身又是不支持发送广播报文
		// 则禁止发送，返回EACCES错误
		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			// 对于已建立"连接"的UDP套接口，在路由表中查找到路由后，需将路由缓存项
			// 缓存到套接口中，以便下次发送时快速获取
			sk_dst_set(sk, dst_clone(&rt->u.dst));
	}

	// 如果发送数据时设置了MSG_CONFIRM标志，则说明应用层知道网关有效并可达，跳转到
	// do_confirm处对目的路由缓存项进行确认
	// 函数dst_confirm向应用程序返回路由确认信息
	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:
	// 预处理发送的数据

	// 从获取到的路由中获取源地址和目的地址，事实上，在发送UDP数据报时可以不指定
	// 目的地址，而在发送的控制信息中加入严格或宽松源站选路选项，因此如果此时还没有
	// 获取目的地址，则需要从路由缓存项中获取
	saddr = rt->rt_src;
	if (!ipc.addr)
		daddr = ipc.addr = rt->rt_dst;

	lock_sock(sk);
	// 再次确定UDP发送状态，如果UDP还处于上次的发送过程中，则说明处理过程中存在bug
	// 因为按逻辑，如果UDP还处于上次的发送过程中，应该已经直接跳转到do_append_data
	// 处理UDP数据报了
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	// 到此处为止需要校验的都已经完成，目的路由缓存项也已获取，此时需要缓存目的
	// 地址、目的端口、源地址和源端口信息，以便在发送处理时方便获取信息，最后
	// 设置pending标志，表示正在处理数据
	inet->cork.fl.fl4_dst = daddr;
	inet->cork.fl.fl_ip_dport = dport;
	inet->cork.fl.fl4_src = saddr;
	inet->cork.fl.fl_ip_sport = inet->sport;
	up->pending = AF_INET;

do_append_data:
	// 处理数据并发送

	// 累计在从UDP套接口发送数据到IP层时待发送数据的长度
	up->len += ulen;
	// 根据is_udplite标志来获取"复制数据到UDP分片"函数
	getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
	//　调用IP层接口函数ip_append_data()，按输出路由查询得到的输出网络设备接口的MTU
	// 将数据分割开，并创建对应的SKB，添加到传输控制块的发送队列
	err = ip_append_data(sk, getfrag, msg->msg_iov, ulen,
			sizeof(struct udphdr), &ipc, rt,
			corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	// 如果ip_append_data()在处理过程中发生错误，则需要清空套接字中等待传送的队列sk_write_queue
	// 并复位pending标志
	if (err)
		udp_flush_pending_frames(sk);
	else if (!corkreq)
		// 如果ip_append_data()处理数据成功，且无需等待组成64KB大小的UDP数据报后
		// 再发送，则立刻调用udp_push_pending_frames()生成UDP数据报，并通过IP层
		// 接口发送出去
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		// 如果发送队列为空，则说明没有数据需要发送，复位pending标志
		up->pending = 0;
	release_sock(sk);

out:
	// 发送数据完成后返回

	// 发送完成，不再需要路由，因此递减对路由的引用
	ip_rt_put(rt);
	// 如果控制信息中有IP选项，则需要在此将它释放
	if (free)
		kfree(ipc.opt);
	// 如果发送数据成功，则返回发送数据的字节数
	if (!err) {
		UDP_INC_STATS_USER(UDP_MIB_OUTDATAGRAMS, is_udplite);
		return len;
	}
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	// 否则返回相应错误码
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	// 处理发送数据时设置了MSG_CONFIRM标志的情况

	// 应用层知道网关可达，因此直接对目的路由缓存项进行确认
	dst_confirm(&rt->u.dst);
	// MSG_PROBE标志只是用来发现路径的，而并不真正发送数据，在网关确认可达后
	// 还需检测MSG_PROBE标志，从处理逻辑上可以看出，MSG_PROBE标志必须和
	// MSG_CONFIRM标志一起使用，否则没有意义
	if (!(msg->msg_flags&MSG_PROBE) || len)
		// 如果在发送时并没有设置MSG_PROBE，却有数据需要作探测，则跳转到
		// back_from_confirm处，否则处理完MSG_CONFIRM标志后，即跳转
		// 到out准备返回
		goto back_from_confirm;
	err = 0;
	goto out;
}

int udp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	struct udp_sock *up = udp_sk(sk);
	int ret;

	if (!up->pending) {
		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

		/* Call udp_sendmsg to specify destination address which
		 * sendpage interface can't pass.
		 * This will succeed only when the socket is connected.
		 */
		ret = udp_sendmsg(NULL, sk, &msg, 0);
		if (ret < 0)
			return ret;
	}

	lock_sock(sk);

	if (unlikely(!up->pending)) {
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 3\n");
		return -EINVAL;
	}

	ret = ip_append_page(sk, page, offset, size, flags);
	if (ret == -EOPNOTSUPP) {
		release_sock(sk);
		return sock_no_sendpage(sk->sk_socket, page, offset,
					size, flags);
	}
	if (ret < 0) {
		udp_flush_pending_frames(sk);
		goto out;
	}

	up->len += size;
	if (!(up->corkflag || (flags&MSG_MORE)))
		ret = udp_push_pending_frames(sk);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}

/*
 *	IOCTL requests applicable to the UDP protocol
 */
 
int udp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch(cmd) 
	{
		case SIOCOUTQ:
		{
			int amount = atomic_read(&sk->sk_wmem_alloc);
			return put_user(amount, (int __user *)arg);
		}

		case SIOCINQ:
		{
			struct sk_buff *skb;
			unsigned long amount;

			amount = 0;
			spin_lock_bh(&sk->sk_receive_queue.lock);
			skb = skb_peek(&sk->sk_receive_queue);
			if (skb != NULL) {
				/*
				 * We will only return the amount
				 * of this packet since that is all
				 * that will be read.
				 */
				amount = skb->len - sizeof(struct udphdr);
			}
			spin_unlock_bh(&sk->sk_receive_queue.lock);
			return put_user(amount, (int __user *)arg);
		}

		default:
			return -ENOIOCTLCMD;
	}
	return(0);
}

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */
// udp_recvmsg()实现了主动从传输控制块的接收队列中读取数据到用户空间的缓冲区中
// iocb: 应用层IO控制缓冲区
// sk: 指向接收数据包的套接字结构
// msg: 接收数据包应用层缓冲块及处理函数
// len: 数据信息长度
// noblock: 当没有数据接收时，应用程序是否阻塞的标志
// flag: 套接字接收队列中的数据包信息标志
// addr_len: 应用层存放发送方地址长度
int udp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
	        size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
  	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
  	struct sk_buff *skb;
	int copied, err, copy_only, is_udplite = IS_UDPLITE(sk);

	/*
	 *	Check any passed addresses
	 */
	// 通过输出参数返回发送方地址长度
	if (addr_len)
		*addr_len=sizeof(*sin);

	// 如果读取标志中存在MSG_ERRQUEUE标志，则说明需要读取错误信息，因此调用
	// ip_recv_error()从传输控制块的错误队列中读取错误信息后返回
	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len);

try_again:
	// 调用skb_recv_datagram()从接收队列sk_receive_queue中获取UDP数据报
	// 如果没有获取，说明接收队列为空，或是发生了错误，因此返回相应的错误码
	// skb_recv_datagram()获取UDP数据报，接收队列中可能没有数据，如果是阻塞
	// 则需要一直睡眠等待，直到超时或队列中有数据而被唤醒。如果接收标志中存在
	// MSG_PEEK，则说明只是查看当前数据，数据将被复制到缓冲区中，但并不从接收
	// 队列中删除
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	// 计算出需要复制数据的长度(不包含UDP首部)，如果用户提供的缓冲区长度不够
	// 则只复制用户需要的长度，并设置截短数据标志
  	copied = skb->len - sizeof(struct udphdr);
	if (copied > len) {
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	/*
	 * 	Decide whether to checksum and/or copy data.
	 *
	 * 	UDP:      checksum may have been computed in HW,
	 * 	          (re-)compute it if message is truncated.
	 * 	UDP-Lite: always needs to checksum, no HW support.
	 */
	// 复制数据至用户空间

	// 根据SKB中的ip_summed标志来判断UDP数据报是否需要进行校验和检测
	copy_only = (skb->ip_summed==CHECKSUM_UNNECESSARY);

	// 如果是轻量级UDP，或者既需要校验和检测又要截断数据，则需要在复制之前就进行
	// 校验和的检测
	if (is_udplite  ||  (!copy_only  &&  msg->msg_flags&MSG_TRUNC)) {
		if (__udp_lib_checksum_complete(skb))
			goto csum_copy_err;
		// 设置copy_only标志，在后续的复制过程中就无需再作校验和的检测
		copy_only = 1;
	}

	//　将数据复制到用户空间，但需根据copy_only标志调用不同的复制函数
	if (copy_only)
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr),
					      msg->msg_iov, copied       );
	else {
		// skb_copy_and_csum_datagram_iovec()在复制的同时还进行校验和检测
		err = skb_copy_and_csum_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov);

		if (err == -EINVAL)
			goto csum_copy_err;
	}

	if (err)
		goto out_free;

	// 更新传输控制块中最后一个数据包接收的时间戳，如果设置了SO_RCVTSTAMP选项
	// 则还需爆发接收时间戳作为控制信息复制给用户进程
	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address. */
	// 复制地址信息
	// 如果应用程序提供了缓冲区sin，来存放数据发送端的源IP和源端口号，则将数据包发送地址复制到sin中
	if (sin)
	{
		sin->sin_family = AF_INET;
		sin->sin_port = skb->h.uh->source;
		sin->sin_addr.s_addr = skb->nh.iph->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
  	}
  	// 根据控制信息标志位(通过套接口选项设置)，将相应的控制信息复制到用户空间
  	// 例如，设置了IP_TOS选项，则把IP首部中的TOS域复制到用户空间
	if (inet->cmsg_flags)
		// 如果IP协议头中设置了任何控制标志，则调用ip_cmsg_recv完成对IP选项值的提取
		ip_cmsg_recv(msg, skb);

	// 设置复制的字节数，如果数据段已经被截短，则返回原始的实际长度
	err = copied;
	if (flags & MSG_TRUNC)
		err = skb->len - sizeof(struct udphdr);
  
out_free:
	// 完成数据复制，或者复制数据时发生错误，会到此作处理，释放当前SKB并返回
  	skb_free_datagram(sk, skb);
out:
  	return err;

csum_copy_err:
	// 当校验和检测失败时会到此作处理，如果支持查看数据，但校验和检测失败
	// 则必须调用skb_kill_datagram()将其删除并释放，如果是非阻塞读取，
	// 因为没有读取到数据，则返回-EAGAIN错误，如果是阻塞读取，则跳转到
	// try_again处获取下一个数据报
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_udplite);

	skb_kill_datagram(sk, skb, flags);

	if (noblock)
		return -EAGAIN;	
	goto try_again;
}


int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
	 *	1003.1g - break association.
	 */
	 
	sk->sk_state = TCP_CLOSE;
	inet->daddr = 0;
	inet->dport = 0;
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}

/* return:
 * 	1  if the the UDP system should process it
 *	0  if we should drop this packet
 * 	-1 if it should get processed by xfrm4_rcv_encap
 */
static int udp_encap_rcv(struct sock * sk, struct sk_buff *skb)
{
#ifndef CONFIG_XFRM
	return 1; 
#else
	struct udp_sock *up = udp_sk(sk);
  	struct udphdr *uh;
	struct iphdr *iph;
	int iphlen, len;
  
	__u8 *udpdata;
	__be32 *udpdata32;
	__u16 encap_type = up->encap_type;

	/* if we're overly short, let UDP handle it */
	len = skb->len - sizeof(struct udphdr);
	if (len <= 0)
		return 1;

	/* if this is not encapsulated socket, then just return now */
	if (!encap_type)
		return 1;

	/* If this is a paged skb, make sure we pull up
	 * whatever data we need to look at. */
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + min(len, 8)))
		return 1;

	/* Now we can get the pointers */
	uh = skb->h.uh;
	udpdata = (__u8 *)uh + sizeof(struct udphdr);
	udpdata32 = (__be32 *)udpdata;

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
		/* Check if this is a keepalive packet.  If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			return 0;
		} else if (len > sizeof(struct ip_esp_hdr) && udpdata32[0] != 0 ) {
			/* ESP Packet without Non-ESP header */
			len = sizeof(struct udphdr);
		} else
			/* Must be an IKE packet.. pass it through */
			return 1;
		break;
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		/* Check if this is a keepalive packet.  If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			return 0;
		} else if (len > 2 * sizeof(u32) + sizeof(struct ip_esp_hdr) &&
			   udpdata32[0] == 0 && udpdata32[1] == 0) {
			
			/* ESP Packet with Non-IKE marker */
			len = sizeof(struct udphdr) + 2 * sizeof(u32);
		} else
			/* Must be an IKE packet.. pass it through */
			return 1;
		break;
	}

	/* At this point we are sure that this is an ESPinUDP packet,
	 * so we need to remove 'len' bytes from the packet (the UDP
	 * header and optional ESP marker bytes) and then modify the
	 * protocol to ESP, and then call into the transform receiver.
	 */
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return 0;

	/* Now we can update and verify the packet length... */
	iph = skb->nh.iph;
	iphlen = iph->ihl << 2;
	iph->tot_len = htons(ntohs(iph->tot_len) - len);
	if (skb->len < iphlen + len) {
		/* packet is too small!?! */
		return 0;
	}

	/* pull the data buffer up to the ESP header and set the
	 * transport header to point to ESP.  Keep UDP on the stack
	 * for later.
	 */
	skb->h.raw = skb_pull(skb, len);

	/* modify the protocol (it's ESP!) */
	iph->protocol = IPPROTO_ESP;

	/* and let the caller know to send this into the ESP processor... */
	return -1;
#endif
}

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
// 将UDP数据报添加到所属传输控制块的接收队列
// 在添加到接收队列之前，必须先进行数据报类型检测，因为不同类型数据报，如IPSEC
// 协议的封装报文，组播广播数据报、单播数据报，各自的接收处理方式不尽相同，此外
// 还需进行一些相关的校验，如安全策略检测、校验和检查等
int udp_queue_rcv_skb(struct sock * sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	// 对接收到的UDP数据报进行安全策略检查，若检查失败则丢弃
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	// 复位接收到的SKB中与netfilter相关的数据
	nf_reset(skb);

	// 如果输入的是一个通过IPSEC协议封装的报文
	// 输入的数据一定被封装在IPSec协议的数据包中，则要将数据包从封装的数据包中
	// 解析出来并接收，并调用up->encap_rcv函数来处理该数据包
	if (up->encap_type) {
		/*
		 * This is an encapsulation socket, so let's see if this is
		 * an encapsulated packet.
		 * If it's a keepalive packet, then just eat it.
		 * If it's an encapsulateed packet, then pass it to the
		 * IPsec xfrm input and return the response
		 * appropriately.  Otherwise, just fall through and
		 * pass this up the UDP socket.
		 */
		int ret;

		ret = udp_encap_rcv(sk, skb);
		if (ret == 0) {
			/* Eat the packet .. */
			kfree_skb(skb);
			return 0;
		}
		if (ret < 0) {
			/* process the ESP packet */
			ret = xfrm4_rcv_encap(skb, up->encap_type);
			UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS, up->pcflag);
			return -ret;
		}
		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 */
	// 如果接收的是轻量级UDP数据报，则校验该数据报需校验的字节是否有效
	if ((up->pcflag & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			LIMIT_NETDEBUG(KERN_WARNING "UDPLITE: partial coverage "
				"%d while full coverage %d requested\n",
				UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			LIMIT_NETDEBUG(KERN_WARNING
				"UDPLITE: coverage %d too small, need min %d\n",
				UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	// 如果安装了套接口过滤器且报文需校验，则检测UDP数据报校验和，若校验失败，则丢弃报文
	if (sk->sk_filter && skb->ip_summed != CHECKSUM_UNNECESSARY) {
		if (__udp_lib_checksum_complete(skb))
			goto drop;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	// 将接收到的数据报添加到传输控制块的接收队列中
	if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(UDP_MIB_RCVBUFERRORS, up->pcflag);
		goto drop;
	}

	UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS, up->pcflag);
	return 0;

drop:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, up->pcflag);
	kfree_skb(skb);
	return -1;
}

/*
 *	Multicasts and broadcasts go to each listener.
 *
 *	Note: called only from the BH handler context,
 *	so we don't need to lock the hashes.
 */
static int __udp4_lib_mcast_deliver(struct sk_buff *skb,
				    struct udphdr  *uh,
				    __be32 saddr, __be32 daddr,
				    struct hlist_head udptable[])
{
	struct sock *sk;
	int dif;

	read_lock(&udp_hash_lock);
	sk = sk_head(&udptable[ntohs(uh->dest) & (UDP_HTABLE_SIZE - 1)]);
	dif = skb->dev->ifindex;
	sk = udp_v4_mcast_next(sk, uh->dest, daddr, uh->source, saddr, dif);
	if (sk) {
		struct sock *sknext = NULL;

		do {
			struct sk_buff *skb1 = skb;

			sknext = udp_v4_mcast_next(sk_next(sk), uh->dest, daddr,
						   uh->source, saddr, dif);
			if(sknext)
				skb1 = skb_clone(skb, GFP_ATOMIC);

			if(skb1) {
				int ret = udp_queue_rcv_skb(sk, skb1);
				if (ret > 0)
					/* we should probably re-process instead
					 * of dropping packets here. */
					kfree_skb(skb1);
			}
			sk = sknext;
		} while(sknext);
	} else
		kfree_skb(skb);
	read_unlock(&udp_hash_lock);
	return 0;
}

/* Initialize UDP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires chacksumming packet body,
 * including udp header and folding it to skb->csum.
 */
static inline void udp4_csum_init(struct sk_buff *skb, struct udphdr *uh)
{
	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
	       if (!csum_tcpudp_magic(skb->nh.iph->saddr, skb->nh.iph->daddr,
				      skb->len, IPPROTO_UDP, skb->csum       ))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (skb->ip_summed != CHECKSUM_UNNECESSARY)
		skb->csum = csum_tcpudp_nofold(skb->nh.iph->saddr,
					       skb->nh.iph->daddr,
					       skb->len, IPPROTO_UDP, 0);
	/* Probably, we should checksum udp header (it should be in cache
	 * in any case) and data in tiny packets (< rx copybreak).
	 */

	/* UDP = UDP-Lite with a non-partial checksum coverage */
	UDP_SKB_CB(skb)->partial_cov = 0;
}

/*
 *	All we need to do is get the socket, and then do a checksum. 
 */
// __udp4_lib_rcv完成的主要功能是对接收到的数据包进行正确性检查，地址类型分析
// 调用相应的函数处理输入过程
int __udp4_lib_rcv(struct sk_buff *skb, struct hlist_head udptable[],
		   int is_udplite)
{
  	struct sock *sk;
  	struct udphdr *uh = skb->h.uh;
	unsigned short ulen;
	struct rtable *rt = (struct rtable*)skb->dst;
	__be32 saddr = skb->nh.iph->saddr;
	__be32 daddr = skb->nh.iph->daddr;

	/*
	 *  Validate the packet.
	 */
	// 校验UDP数据报
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */

	// 检测数据报的长度，不能小于UDP首部长度，否则丢弃
	ulen = ntohs(uh->len);
	// 如果UDP首部中标识的数据长度大于实际SKB中UDP数据报的长度，则封包
	// 可能出现错误，但这种情况比较少见
	if (ulen > skb->len)
		goto short_packet;

	// 初始化UDP的校验和
	if(! is_udplite ) {		/* UDP validates ulen. */

		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;

		udp4_csum_init(skb, uh);

	} else 	{			/* UDP-Lite validates cscov. */
		if (udplite4_csum_init(skb, uh))
			goto csum_error;
	}

	// 如果接收到的UDP数据报是广播或组播报文，则调用__udp4_lib_mcast_deliver()作输入处理
	// 将会多次克隆接收到的数据报，并将克隆数据报添加到接收该组播报文的各传输控制块的接收队列中
	if(rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __udp4_lib_mcast_deliver(skb, uh, saddr, daddr, udptable);

	// 根据源地址、源端口、目的地址和目的端口，在udptable散列表中查找所属传输控制块
	sk = __udp4_lib_lookup(saddr, uh->source, daddr, uh->dest,
			       skb->dev->ifindex, udptable        );

	if (sk != NULL) {
		// 如果找到所属传输控制块，则将UDP数据报添加到所属传输控制块的接收队列中
		int ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		// 当udp_queue_rcv_skb函数的返回值大于0时，__udp4_lib_rcv函数需要告诉
		// 调用程序重新提交输入数据包
		if (ret > 0)
			return -ret;
		return 0;
	}

	// 处理找不到所属传输控制块的数据报

	// 检查IPSEC包策略是否合法，对普通数据报则返回合法
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	// 复位接收到的SKB中与netfilter相关的数据
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	// 检测UDP数据报的校验和是否正确，如果不正确，则认为它是一个错误的包
	// 统计后将其丢弃
	if (udp_lib_checksum_complete(skb))
		goto csum_error;

	UDP_INC_STATS_BH(UDP_MIB_NOPORTS, is_udplite);
	// 通过校验和检测但又找不到所属传输控制块的包，则向发送端发送目的不可达ICMP报文
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return(0);

short_packet:
	// 如果接收到UDP数据报太短而无效，则记录一些调试信息后返回
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: short packet: From %u.%u.%u.%u:%u %d/%d to %u.%u.%u.%u:%u\n",
		       is_udplite? "-Lite" : "",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       ulen,
		       skb->len,
		       NIPQUAD(daddr),
		       ntohs(uh->dest));
	goto drop;

csum_error:
	// 如果接收到的UDP数据报校验和异常，则记录一些调试信息后丢弃
	/* 
	 * RFC1122: OK.  Discards the bad packet silently (as far as 
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST). 
	 */
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: bad checksum. From %d.%d.%d.%d:%d to %d.%d.%d.%d:%d ulen %d\n",
		       is_udplite? "-Lite" : "",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       NIPQUAD(daddr),
		       ntohs(uh->dest),
		       ulen);
drop:
	// 记录UDP_MIB_INERRORS统计值后丢弃UDP数据报
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_udplite);
	kfree_skb(skb);
	return(0);
}

__inline__ int udp_rcv(struct sk_buff *skb)
{
	return __udp4_lib_rcv(skb, udp_hash, 0);
}

int udp_destroy_sock(struct sock *sk)
{
	lock_sock(sk);
	// 将未发送的数据发送出去，如果有等待该传输控制块的进程，则将它们唤醒
	udp_flush_pending_frames(sk);
	release_sock(sk);
	return 0;
}

/*
 *	Socket option code for UDP
 */
int udp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int optlen,
		       int (*push_pending_frames)(struct sock *))
{
	struct udp_sock *up = udp_sk(sk);
	int val;
	int err = 0;

	if(optlen<sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch(optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			(*push_pending_frames)(sk);
			release_sock(sk);
		}
		break;
		
	case UDP_ENCAP:
		switch (val) {
		case 0:
		case UDP_ENCAP_ESPINUDP:
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			up->encap_type = val;
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	/*
	 * 	UDP-Lite's partial checksum coverage (RFC 3828).
	 */
	/* The sender sets actual checksum coverage length via this option.
	 * The case coverage > packet length is handled by send module. */
	case UDPLITE_SEND_CSCOV:
		if (!up->pcflag)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Illegal coverage: use default (8) */
			val = 8;
		up->pcslen = val;
		up->pcflag |= UDPLITE_SEND_CC;
		break;

        /* The receiver specifies a minimum checksum coverage value. To make
         * sense, this should be set to at least 8 (as done below). If zero is
	 * used, this again means full checksum coverage.                     */
	case UDPLITE_RECV_CSCOV:
		if (!up->pcflag)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Avoid silly minimal values.       */
			val = 8;
		up->pcrlen = val;
		up->pcflag |= UDPLITE_RECV_CC;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	};

	return err;
}

int udp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int udp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if(get_user(len,optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));
	
	if(len < 0)
		return -EINVAL;

	switch(optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	/* The following two cannot be changed on UDP sockets, the return is
	 * always 0 (which corresponds to the full checksum coverage of UDP). */
	case UDPLITE_SEND_CSCOV:
		val = up->pcslen;
		break;

	case UDPLITE_RECV_CSCOV:
		val = up->pcrlen;
		break;

	default:
		return -ENOPROTOOPT;
	};

  	if(put_user(len, optlen))
  		return -EFAULT;
	if(copy_to_user(optval, &val,len))
		return -EFAULT;
  	return 0;
}

int udp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif
/**
 * 	udp_poll - wait for a UDP event.
 *	@file - file struct
 *	@sock - socket
 *	@wait - poll table
 *
 *	This is same as datagram poll, except for the special case of 
 *	blocking sockets. If application is using a blocking fd
 *	and a packet with checksum error is in the queue;
 *	then it could get return from select indicating data available
 *	but then block when reading it. Add special case code
 *	to work around these arguably broken applications.
 */
unsigned int udp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask = datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;
	int 	is_lite = IS_UDPLITE(sk);

	/* Check for false positives due to checksum errors */
	if ( (mask & POLLRDNORM) &&
	     !(file->f_flags & O_NONBLOCK) &&
	     !(sk->sk_shutdown & RCV_SHUTDOWN)){
		struct sk_buff_head *rcvq = &sk->sk_receive_queue;
		struct sk_buff *skb;

		spin_lock_bh(&rcvq->lock);
		while ((skb = skb_peek(rcvq)) != NULL) {
			if (udp_lib_checksum_complete(skb)) {
				UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_lite);
				__skb_unlink(skb, rcvq);
				kfree_skb(skb);
			} else {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				break;
			}
		}
		spin_unlock_bh(&rcvq->lock);

		/* nothing to see, move along */
		if (skb == NULL)
			mask &= ~(POLLIN | POLLRDNORM);
	}

	return mask;
	
}

// udp_prot为套接字与传输层之间的接口
// udp协议通过int proto_register(struct proto *prot, int alloc_slab)
// 将udp_prot注册到TCP/IP协议栈中
struct proto udp_prot = {
 	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	// udp协议支持connect系统调用的主要目的是建立到达目的地址的路由，并把该路由放入
	// 路由高速缓冲存储器中，一旦路由建立起来，接下来在通过udp套接字发送数据包时就可以
	// 使用高速缓冲区中的信息了，这种方式称之为在连接套接字上的快速路径"fast path"
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = udp_queue_rcv_skb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.get_port	   = udp_v4_get_port,
	.obj_size	   = sizeof(struct udp_sock),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
};

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static struct sock *udp_get_first(struct seq_file *seq)
{
	struct sock *sk;
	struct udp_iter_state *state = seq->private;

	for (state->bucket = 0; state->bucket < UDP_HTABLE_SIZE; ++state->bucket) {
		struct hlist_node *node;
		sk_for_each(sk, node, state->hashtable + state->bucket) {
			if (sk->sk_family == state->family)
				goto found;
		}
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *udp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct udp_iter_state *state = seq->private;

	do {
		sk = sk_next(sk);
try_again:
		;
	} while (sk && sk->sk_family != state->family);

	if (!sk && ++state->bucket < UDP_HTABLE_SIZE) {
		sk = sk_head(state->hashtable + state->bucket);
		goto try_again;
	}
	return sk;
}

static struct sock *udp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = udp_get_first(seq);

	if (sk)
		while(pos && (sk = udp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

static void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock(&udp_hash_lock);
	return *pos ? udp_get_idx(seq, *pos-1) : (void *)1;
}

static void *udp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == (void *)1)
		sk = udp_get_idx(seq, 0);
	else
		sk = udp_get_next(seq, v);

	++*pos;
	return sk;
}

static void udp_seq_stop(struct seq_file *seq, void *v)
{
	read_unlock(&udp_hash_lock);
}

static int udp_seq_open(struct inode *inode, struct file *file)
{
	struct udp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct udp_iter_state *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		goto out;
	s->family		= afinfo->family;
	s->hashtable		= afinfo->hashtable;
	s->seq_ops.start	= udp_seq_start;
	s->seq_ops.next		= udp_seq_next;
	s->seq_ops.show		= afinfo->seq_show;
	s->seq_ops.stop		= udp_seq_stop;

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

/* ------------------------------------------------------------------------ */
int udp_proc_register(struct udp_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	if (!afinfo)
		return -EINVAL;
	afinfo->seq_fops->owner		= afinfo->owner;
	afinfo->seq_fops->open		= udp_seq_open;
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

void udp_proc_unregister(struct udp_seq_afinfo *afinfo)
{
	if (!afinfo)
		return;
	proc_net_remove(afinfo->name);
	memset(afinfo->seq_fops, 0, sizeof(*afinfo->seq_fops));
}

/* ------------------------------------------------------------------------ */
static void udp4_format_sock(struct sock *sp, char *tmpbuf, int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->daddr;
	__be32 src  = inet->rcv_saddr;
	__u16 destp	  = ntohs(inet->dport);
	__u16 srcp	  = ntohs(inet->sport);

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %p",
		bucket, src, srcp, dest, destp, sp->sk_state, 
		atomic_read(&sp->sk_wmem_alloc),
		atomic_read(&sp->sk_rmem_alloc),
		0, 0L, 0, sock_i_uid(sp), 0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp);
}

int udp4_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
	else {
		char tmpbuf[129];
		struct udp_iter_state *state = seq->private;

		udp4_format_sock(v, tmpbuf, state->bucket);
		seq_printf(seq, "%-127s\n", tmpbuf);
	}
	return 0;
}

/* ------------------------------------------------------------------------ */
static struct file_operations udp4_seq_fops;
static struct udp_seq_afinfo udp4_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "udp",
	.family		= AF_INET,
	.hashtable	= udp_hash,
	.seq_show	= udp4_seq_show,
	.seq_fops	= &udp4_seq_fops,
};

int __init udp4_proc_init(void)
{
	return udp_proc_register(&udp4_seq_afinfo);
}

void udp4_proc_exit(void)
{
	udp_proc_unregister(&udp4_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(udp_disconnect);
EXPORT_SYMBOL(udp_hash);
EXPORT_SYMBOL(udp_hash_lock);
EXPORT_SYMBOL(udp_ioctl);
EXPORT_SYMBOL(udp_get_port);
EXPORT_SYMBOL(udp_prot);
EXPORT_SYMBOL(udp_sendmsg);
EXPORT_SYMBOL(udp_lib_getsockopt);
EXPORT_SYMBOL(udp_lib_setsockopt);
EXPORT_SYMBOL(udp_poll);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(udp_proc_register);
EXPORT_SYMBOL(udp_proc_unregister);
#endif
