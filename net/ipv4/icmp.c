/*
 *	NET3:	Implementation of the ICMP protocol layer.
 *
 *		Alan Cox, <alan@redhat.com>
 *
 *	Version: $Id: icmp.c,v 1.85 2002/02/01 22:01:03 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *	Some of the function names and the icmp unreach table for this
 *	module were derived from [icmp.c 1.0.11 06/02/93] by
 *	Ross Biro, Fred N. van Kempen, Mark Evans, Alan Cox, Gerhard Koerting.
 *	Other than that this module is a complete rewrite.
 *
 *	Fixes:
 *	Clemens Fruhwirth	:	introduce global icmp rate limiting
 *					with icmp type masking ability instead
 *					of broken per type icmp timeouts.
 *		Mike Shaver	:	RFC1122 checks.
 *		Alan Cox	:	Multicast ping reply as self.
 *		Alan Cox	:	Fix atomicity lockup in ip_build_xmit
 *					call.
 *		Alan Cox	:	Added 216,128 byte paths to the MTU
 *					code.
 *		Martin Mares	:	RFC1812 checks.
 *		Martin Mares	:	Can be configured to follow redirects
 *					if acting as a router _without_ a
 *					routing protocol (RFC 1812).
 *		Martin Mares	:	Echo requests may be configured to
 *					be ignored (RFC 1812).
 *		Martin Mares	:	Limitation of ICMP error message
 *					transmit rate (RFC 1812).
 *		Martin Mares	:	TOS and Precedence set correctly
 *					(RFC 1812).
 *		Martin Mares	:	Now copying as much data from the
 *					original packet as we can without
 *					exceeding 576 bytes (RFC 1812).
 *	Willy Konynenberg	:	Transparent proxying support.
 *		Keith Owens	:	RFC1191 correction for 4.2BSD based
 *					path MTU bug.
 *		Thomas Quinot	:	ICMP Dest Unreach codes up to 15 are
 *					valid (RFC 1812).
 *		Andi Kleen	:	Check all packet lengths properly
 *					and moved all kfree_skb() up to
 *					icmp_rcv.
 *		Andi Kleen	:	Move the rate limit bookkeeping
 *					into the dest entry and use a token
 *					bucket filter (thanks to ANK). Make
 *					the rates sysctl configurable.
 *		Yu Tianli	:	Fixed two ugly bugs in icmp_send
 *					- IP option length was accounted wrongly
 *					- ICMP header length was not accounted
 *					  at all.
 *              Tristan Greaves :       Added sysctl option to ignore bogus
 *              			broadcast responses from broken routers.
 *
 * To Fix:
 *
 *	- Should use skb_pull() instead of all the manual checking.
 *	  This would also greatly simply some upper layer error handlers. --AK
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/raw.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/init.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <net/checksum.h>

/*
 *	Build xmit assembly blocks
 */
// icmp_bxm结构是ICMP报文的一组信息，在处理ICMP报文时经常使用
// 此结构作为参数在函数间传递 
struct icmp_bxm {
	// 指向ICMP报文的SKB
	struct sk_buff *skb;
	// 当输出ICMP差错报文时，offset为IP首部在导致差错报文中的偏移量
	// 当输出回显应答和时间戳应答报文时，offset为选项数据在请求回显的ICMP
	// 报文中的偏移
	int offset;
	// 需要复制到输出ICMP报文的数据长度
	int data_len;

	struct {
		// icmph为ICMP报文的ICMP首部
		struct icmphdr icmph;
		// 当输出时间戳应答时，times用来存储相应的时间戳
		// times[0]从时间戳请求报文中获得，times[1]和
		// times[2]取当前时间为接收请求和发送应答时间
		__be32	       times[3];
	} data;
	// ICMP首部的长度
	int head_len;
	// 临时存储引发ICMP报文的输入报文的IP选项，用于构成待输出ICMP应答报文
	// 的IP选项等操作
	struct ip_options replyopts;
	unsigned char  optbuf[40];
};

/*
 *	Statistics
 */
DEFINE_SNMP_STAT(struct icmp_mib, icmp_statistics) __read_mostly;

/* An array of errno for error messages from dest unreach. */
/* RFC 1122: 3.2.2.1 States that NET_UNREACH, HOST_UNREACH and SR_FAILED MUST be considered 'transient errs'. */

struct icmp_err icmp_err_convert[] = {
	{
		.errno = ENETUNREACH,	/* ICMP_NET_UNREACH */
		.fatal = 0,
	},
	{
		.errno = EHOSTUNREACH,	/* ICMP_HOST_UNREACH */
		.fatal = 0,
	},
	{
		.errno = ENOPROTOOPT	/* ICMP_PROT_UNREACH */,
		.fatal = 1,
	},
	{
		.errno = ECONNREFUSED,	/* ICMP_PORT_UNREACH */
		.fatal = 1,
	},
	{
		.errno = EMSGSIZE,	/* ICMP_FRAG_NEEDED */
		.fatal = 0,
	},
	{
		.errno = EOPNOTSUPP,	/* ICMP_SR_FAILED */
		.fatal = 0,
	},
	{
		.errno = ENETUNREACH,	/* ICMP_NET_UNKNOWN */
		.fatal = 1,
	},
	{
		.errno = EHOSTDOWN,	/* ICMP_HOST_UNKNOWN */
		.fatal = 1,
	},
	{
		.errno = ENONET,	/* ICMP_HOST_ISOLATED */
		.fatal = 1,
	},
	{
		.errno = ENETUNREACH,	/* ICMP_NET_ANO	*/
		.fatal = 1,
	},
	{
		.errno = EHOSTUNREACH,	/* ICMP_HOST_ANO */
		.fatal = 1,
	},
	{
		.errno = ENETUNREACH,	/* ICMP_NET_UNR_TOS */
		.fatal = 0,
	},
	{
		.errno = EHOSTUNREACH,	/* ICMP_HOST_UNR_TOS */
		.fatal = 0,
	},
	{
		.errno = EHOSTUNREACH,	/* ICMP_PKT_FILTERED */
		.fatal = 1,
	},
	{
		.errno = EHOSTUNREACH,	/* ICMP_PREC_VIOLATION */
		.fatal = 1,
	},
	{
		.errno = EHOSTUNREACH,	/* ICMP_PREC_CUTOFF */
		.fatal = 1,
	},
};

/* Control parameters for ECHO replies. */
int sysctl_icmp_echo_ignore_all __read_mostly;
int sysctl_icmp_echo_ignore_broadcasts __read_mostly = 1;

/* Control parameter - ignore bogus broadcast responses? */
int sysctl_icmp_ignore_bogus_error_responses __read_mostly = 1;

/*
 * 	Configurable global rate limit.
 *
 *	ratelimit defines tokens/packet consumed for dst->rate_token bucket
 *	ratemask defines which icmp types are ratelimited by setting
 * 	it's bit position.
 *
 *	default:
 *	dest unreachable (3), source quench (4),
 *	time exceeded (11), parameter problem (12)
 */

int sysctl_icmp_ratelimit __read_mostly = 1 * HZ;
int sysctl_icmp_ratemask __read_mostly = 0x1818;
int sysctl_icmp_errors_use_inbound_ifaddr __read_mostly;

/*
 *	ICMP control array. This specifies what to do with each ICMP.
 */
// 一种类型的ICMP报文对应一个icmp_control结构，在内核中定义了一个该类型的数组
// icmp_pointers[NR_ICMP_TYPE + 1]用来管理ICMP报文
struct icmp_control {
	// ICMP报文统计值，每输出/输入一个相应类型的ICMP报文，output_entry和
	// input_entry递增1
	int output_entry;	/* Field for increment on output */
	int input_entry;	/* Field for increment on input */
	// 对输入该类型ICMP报文的处理函数
	void (*handler)(struct sk_buff *skb);
	// error值为1表示是一个差错ICMP报文，为0则是一个查询报文
	short   error;		/* This ICMP is classed as an error message */
};

static const struct icmp_control icmp_pointers[NR_ICMP_TYPES+1];

/*
 *	The ICMP socket(s). This is the most convenient way to flow control
 *	our ICMP output as well as maintain a clean interface throughout
 *	all layers. All Socketless IP sends will soon be gone.
 *
 *	On SMP we have one ICMP socket per-cpu.
 */
static DEFINE_PER_CPU(struct socket *, __icmp_socket) = NULL;
#define icmp_socket	__get_cpu_var(__icmp_socket)

static __inline__ int icmp_xmit_lock(void)
{
	local_bh_disable();

	if (unlikely(!spin_trylock(&icmp_socket->sk->sk_lock.slock))) {
		/* This can happen if the output path signals a
		 * dst_link_failure() for an outgoing ICMP packet.
		 */
		local_bh_enable();
		return 1;
	}
	return 0;
}

static void icmp_xmit_unlock(void)
{
	spin_unlock_bh(&icmp_socket->sk->sk_lock.slock);
}

/*
 *	Send an ICMP frame.
 */

/*
 *	Check transmit rate limitation for given message.
 *	The rate information is held in the destination cache now.
 *	This function is generic and could be used for other purposes
 *	too. It uses a Token bucket filter as suggested by Alexey Kuznetsov.
 *
 *	Note that the same dst_entry fields are modified by functions in
 *	route.c too, but these work for packet destinations while xrlim_allow
 *	works for icmp destinations. This means the rate limiting information
 *	for one "ip object" is shared - and these ICMPs are twice limited:
 *	by source and by destination.
 *
 *	RFC 1812: 4.3.2.8 SHOULD be able to limit error message rate
 *			  SHOULD allow setting of rate limits
 *
 * 	Shared between ICMPv4 and ICMPv6.
 */
#define XRLIM_BURST_FACTOR 6
int xrlim_allow(struct dst_entry *dst, int timeout)
{
	unsigned long now;
	int rc = 0;

	now = jiffies;
	dst->rate_tokens += now - dst->rate_last;
	dst->rate_last = now;
	if (dst->rate_tokens > XRLIM_BURST_FACTOR * timeout)
		dst->rate_tokens = XRLIM_BURST_FACTOR * timeout;
	if (dst->rate_tokens >= timeout) {
		dst->rate_tokens -= timeout;
		rc = 1;
	}
	return rc;
}

static inline int icmpv4_xrlim_allow(struct rtable *rt, int type, int code)
{
	struct dst_entry *dst = &rt->u.dst;
	int rc = 1;

	if (type > NR_ICMP_TYPES)
		goto out;

	/* Don't limit PMTU discovery. */
	if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED)
		goto out;

	/* No rate limit on loopback */
	if (dst->dev && (dst->dev->flags&IFF_LOOPBACK))
 		goto out;

	/* Limit if icmp type is enabled in ratemask. */
	if ((1 << type) & sysctl_icmp_ratemask)
		rc = xrlim_allow(dst, sysctl_icmp_ratelimit);
out:
	return rc;
}

/*
 *	Maintain the counters used in the SNMP statistics for outgoing ICMP
 */
static void icmp_out_count(int type)
{
	if (type <= NR_ICMP_TYPES) {
		ICMP_INC_STATS(icmp_pointers[type].output_entry);
		ICMP_INC_STATS(ICMP_MIB_OUTMSGS);
	}
}

/*
 *	Checksum each fragment, and on the first include the headers and final
 *	checksum.
 */
static int icmp_glue_bits(void *from, char *to, int offset, int len, int odd,
			  struct sk_buff *skb)
{
	struct icmp_bxm *icmp_param = (struct icmp_bxm *)from;
	__wsum csum;

	csum = skb_copy_and_csum_bits(icmp_param->skb,
				      icmp_param->offset + offset,
				      to, len, 0);

	skb->csum = csum_block_add(skb->csum, csum, odd);
	if (icmp_pointers[icmp_param->data.icmph.type].error)
		nf_ct_attach(skb, icmp_param->skb);
	return 0;
}

// 该函数用来创建待发送ICMP报文，然后将其添加到传输控制块的发送缓存队列中，完成后
// 如果套接口的输出队列上还有未输出的报文，则计算ICMP报文的校验和并将其输出
// icmp_param:待输出ICMP报文的icmp_bxm结构
// ipc:待输出ICMP报文的ipcm_cookie结构，包括目的地址、输出网络设备号以及IP选项
// rt:带输出ICMP报文的路由缓存
static void icmp_push_reply(struct icmp_bxm *icmp_param,
			    struct ipcm_cookie *ipc, struct rtable *rt)
{
	struct sk_buff *skb;

	// IP层接口函数ip_append_data()，创建待发送ICMP报文的SKB，并将其添加到
	// 传输控制块的发送缓存队列中
	if (ip_append_data(icmp_socket->sk, icmp_glue_bits, icmp_param,
		           icmp_param->data_len+icmp_param->head_len,
		           icmp_param->head_len,
		           ipc, rt, MSG_DONTWAIT) < 0)
		// 如果函数ip_append_data()处理失败，则调用ip_flush_pending_frames()释放一些资源
		// 如未输出的ICMP报文，临时IP选项、路由等
		ip_flush_pending_frames(icmp_socket->sk);
	else if ((skb = skb_peek(&icmp_socket->sk->sk_write_queue)) != NULL) {
		// 如果ip_append_data()处理成功，并且套接口的输出队列上还有未输出的报文
		// 则计算ICMP报文的校验和并将其输出
		struct icmphdr *icmph = skb->h.icmph;
		__wsum csum = 0;
		struct sk_buff *skb1;

		skb_queue_walk(&icmp_socket->sk->sk_write_queue, skb1) {
			csum = csum_add(csum, skb1->csum);
		}
		csum = csum_partial_copy_nocheck((void *)&icmp_param->data,
						 (char *)icmph,
						 icmp_param->head_len, csum);
		icmph->checksum = csum_fold(csum);
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(icmp_socket->sk);
	}
}

/*
 *	Driving logic for building and sending ICMP messages.
 */
// 一般的差错和请求ICMP报文是通过icmp_send()来发送的，而回显应答和时间戳应答报文
// 则是通过icmp_reply()来输出的 
static void icmp_reply(struct icmp_bxm *icmp_param, struct sk_buff *skb)
{
	struct sock *sk = icmp_socket->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ipcm_cookie ipc;
	// 从输入报文中获得输入路由，用于获取该报文的发送方等信息
	struct rtable *rt = (struct rtable *)skb->dst;
	__be32 daddr;

	// 解析并获取输入报文的IP选项到icmp_param中
	if (ip_options_echo(&icmp_param->replyopts, skb))
		return;

	// 需确保同时只发送一个ICMP报文，因为icmp_send()也能发送ICMP报文
	if (icmp_xmit_lock())
		return;

	// 初始化ICMP报文的校验值为0，然后更新该类型ICMP报文统计计数
	icmp_param->data.icmph.checksum = 0;
	icmp_out_count(icmp_param->data.icmph.type);

	inet->tos = skb->nh.iph->tos;
	// 从输入路由中获得发送方地址，作为应答报文的目的地址
	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;
	if (icmp_param->replyopts.optlen) {
		ipc.opt = &icmp_param->replyopts;
		// 如果输入的请求报文中存在IP选项，并启用了源站路由，则将源站选路的
		// 下一站的IP地址作为目的地址
		if (ipc.opt->srr)
			daddr = icmp_param->replyopts.faddr;
	}
	{
		// 根据目的地址、源地址等信息得到待输出ICMP报文的路由项
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(skb->nh.iph->tos) } },
				    .proto = IPPROTO_ICMP };
		security_skb_classify_flow(skb, &fl);
		if (ip_route_output_key(&rt, &fl))
			goto out_unlock;
	}
	// 检测输出ICMP报文的类型和编码检验，对自定义类型报文、目的不可达需要分片
	// 差错报文以及从回环设备上输出的报文始终允许输出，而其他情况，则需通过
	// icmp_ratelimit()和icmp_ratemask()来判断当前能否输出，如果允许输出
	// 则调用icmp_push_reply()输出该ICMP报文
	if (icmpv4_xrlim_allow(rt, icmp_param->data.icmph.type,
			       icmp_param->data.icmph.code))
		icmp_push_reply(icmp_param, &ipc, rt);
	ip_rt_put(rt);
out_unlock:
	icmp_xmit_unlock();
}


/*
 *	Send an ICMP message in response to a situation
 *
 *	RFC 1122: 3.2.2	MUST send at least the IP header and 8 bytes of header.
 *		  MAY send more (we do).
 *			MUST NOT change this header information.
 *			MUST NOT reply to a multicast/broadcast IP address.
 *			MUST NOT reply to a multicast/broadcast MAC address.
 *			MUST reply to only the first fragment.
 */
// icmp_send()用于输出各种指定类型和编码的ICMP报文，但用该函数不能应答目的地址为组播
// 或广播的硬件地址或IP地址的报文
// skb_in:引发差错的报文，由该报文可获得输入路由缓存，以及作为输出ICMP报文数据的原始IP首部
// type:待输出ICMP报文的类型
// code:待输出ICMP报文的编码
// info:ICMP报文的具体信息，因类型，编码而异，如：对于目的不可达差错报文为下一跳的MTU
// 对于重定向差错报文为优选路由器IP地址 
void icmp_send(struct sk_buff *skb_in, int type, int code, __be32 info)
{
	struct iphdr *iph;
	int room;
	struct icmp_bxm icmp_param;
	struct rtable *rt = (struct rtable *)skb_in->dst;
	struct ipcm_cookie ipc;
	__be32 saddr;
	u8  tos;

	// 校验待输出ICMP报文的输出路由缓存是否有效
	if (!rt)
		goto out;

	/*
	 *	Find the original header. It is expected to be valid, of course.
	 *	Check this, icmp_send is called from the most obscure devices
	 *	sometimes.
	 */
	// 获得引发差错报文的IP首部，并通过检测其长度来判断是否有效 
	iph = skb_in->nh.iph;


	if ((u8 *)iph < skb_in->head || (u8 *)(iph + 1) > skb_in->tail)
		goto out;

	/*
	 *	No replies to physical multicast/broadcast
	 */
	// 函数只能用单播方式来发送ICMP报文
	if (skb_in->pkt_type != PACKET_HOST)
		goto out;

	/*
	 *	Now check at the protocol level
	 */
	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto out;

	/*
	 *	Only reply to fragment 0. We byte re-order the constant
	 *	mask for efficiency.
	 */
	// 输出的ICMP报文不支持分片，一旦IP首部中分片偏移量不为零，即禁止输出
	if (iph->frag_off & htons(IP_OFFSET))
		goto out;

	/*
	 *	If we send an ICMP error to an ICMP error a mess would result..
	 */
	// 如果输入报文是ICMP差错报文，并由此引发输出ICMP报文，则需要检测该输入ICMP
	//　差错报文的类型 
	if (icmp_pointers[type].error) {
		/*
		 *	We are an error, check if we are replying to an
		 *	ICMP error
		 */
		if (iph->protocol == IPPROTO_ICMP) {
			u8 _inner_type, *itp;

			itp = skb_header_pointer(skb_in,
						 skb_in->nh.raw +
						 (iph->ihl << 2) +
						 offsetof(struct icmphdr,
							  type) -
						 skb_in->data,
						 sizeof(_inner_type),
						 &_inner_type);
			if (itp == NULL)
				goto out;

			/*
			 *	Assume any unknown ICMP type is an error. This
			 *	isn't specified by the RFC, but think about it..
			 */
			if (*itp > NR_ICMP_TYPES ||
			    icmp_pointers[*itp].error)
				goto out;
		}
	}

	// icmp_reply()也会发送ICMP报文，在此需确保同时只能发送一个ICMP报文
	if (icmp_xmit_lock())
		return;

	/*
	 *	Construct source address and options.
	 */
	// 如果输入报文的目的地址是本机，则将该地址作为输出ICMP报文的源地址
	saddr = iph->daddr;
	if (!(rt->rt_flags & RTCF_LOCAL)) {
		// 否则根据icmp_errors_use_inbound_ifaddr，获取现有网络设备上首选地址
		// 或获取根据引发输出这个ICMP错误报文的输入接口的首选地址作为源地址
		if (sysctl_icmp_errors_use_inbound_ifaddr)
			saddr = inet_select_addr(skb_in->dev, 0, RT_SCOPE_LINK);
		else
			saddr = 0;
	}

	// 根据输入报文IP首部tos字段获得输出ICMP报文IP首部tos字段
	tos = icmp_pointers[type].error ? ((iph->tos & IPTOS_TOS_MASK) |
					   IPTOS_PREC_INTERNETCONTROL) :
					  iph->tos;

	// 解析并存储输入报文中的IP选项
	if (ip_options_echo(&icmp_param.replyopts, skb_in))
		goto out_unlock;


	/*
	 *	Prepare data for ICMP header.
	 */
	// 设置待输出ICMP报文的类型、编码、附加信息、源地址、IP选项等
	icmp_param.data.icmph.type	 = type;
	icmp_param.data.icmph.code	 = code;
	icmp_param.data.icmph.un.gateway = info;
	icmp_param.data.icmph.checksum	 = 0;
	icmp_param.skb	  = skb_in;
	icmp_param.offset = skb_in->nh.raw - skb_in->data;
	icmp_out_count(icmp_param.data.icmph.type);
	inet_sk(icmp_socket->sk)->tos = tos;
	ipc.addr = iph->saddr;
	ipc.opt = &icmp_param.replyopts;

	// 根据源地址、TOS、协议以及ICMP报文的类型和编码，获取输出路由缓存
	{
		struct flowi fl = {
			.nl_u = {
				.ip4_u = {
					.daddr = icmp_param.replyopts.srr ?
						icmp_param.replyopts.faddr :
						iph->saddr,
					.saddr = saddr,
					.tos = RT_TOS(tos)
				}
			},
			.proto = IPPROTO_ICMP,
			.uli_u = {
				.icmpt = {
					.type = type,
					.code = code
				}
			}
		};
		security_skb_classify_flow(skb_in, &fl);
		if (ip_route_output_key(&rt, &fl))
			goto out_unlock;
	}

	// 检测输出ICMP报文的类型和编码检验，对自定义类型报文、目的不可达需要分片差错报文
	// 以及从回环设备上输出的报文始终允许输出，而其他情况，则需要通过icmp_ratelimit()
	// 和icmp_ratemask()来判断当前能否输出
	if (!icmpv4_xrlim_allow(rt, type, code))
		goto ende;

	/* RFC says return as much as we can without exceeding 576 bytes. */
	// 完成计算待输出ICMP报文ICMP首部长度，以及ICMP报文中原始IP报文的长度后
	// 输出该ICMP报文
	room = dst_mtu(&rt->u.dst);
	if (room > 576)
		room = 576;
	room -= sizeof(struct iphdr) + icmp_param.replyopts.optlen;
	room -= sizeof(struct icmphdr);

	icmp_param.data_len = skb_in->len - icmp_param.offset;
	if (icmp_param.data_len > room)
		icmp_param.data_len = room;
	icmp_param.head_len = sizeof(struct icmphdr);

	icmp_push_reply(&icmp_param, &ipc, rt);
ende:
	ip_rt_put(rt);
out_unlock:
	icmp_xmit_unlock();
out:;
}


/*
 *	Handle ICMP_DEST_UNREACH, ICMP_TIME_EXCEED, and ICMP_QUENCH.
 */
// 目的不可达，源端被关闭，超时，参数错误这四种类型的差错ICMP报文，都是由同一个函数
// icmp_unreach()来处理的，对其中目的不可达、源端被关闭这两种类型ICMP报文要提取某些
// 信息而需作一些特殊的处理，而另外一些则不需要，根据差错报文中的信息直接调用传输层的
// 错误处理例程 
static void icmp_unreach(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct icmphdr *icmph;
	int hash, protocol;
	struct net_protocol *ipprot;
	struct sock *raw_sk;
	u32 info = 0;

	/*
	 *	Incomplete header ?
	 * 	Only checks for the IP header, there should be an
	 *	additional check for longer headers in upper levels.
	 */
	// 检测ICMP报文的IP首部是否正常 
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto out_err;

	// 获取ICMP报文的ICMP首部指针以及导致差错的数据报中的IP首部指针，并通过该IP首部
	// 的首部长度字段校验该IP首部是否正常，ICMP报文中导致差错的数据报中的IP首部应该
	// 不少于20B
	icmph = skb->h.icmph;
	iph   = (struct iphdr *)skb->data;

	if (iph->ihl < 5) /* Mangled header, drop. */
		goto out_err;

	if (icmph->type == ICMP_DEST_UNREACH) {
		// 按其code不同分别处理各种目的不可达ICMP报文
		switch (icmph->code & 15) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_PROT_UNREACH:
		case ICMP_PORT_UNREACH:
		// 其中网络不可达、主机不可达、协议不可达、端口不可达四种目的不可达ICMP
		// 报文无需特殊处理
			break;
		// 处理目的不可达需要分片的差错报文	
		case ICMP_FRAG_NEEDED:
			// 如果系统禁止使用路径MTU发现功能，则只是打印些信息
			if (ipv4_config.no_pmtu_disc) {
				LIMIT_NETDEBUG(KERN_INFO "ICMP: %u.%u.%u.%u: "
							 "fragmentation needed "
							 "and DF set.\n",
					       NIPQUAD(iph->daddr));
			} else {
				// 否则，调用ip_rt_frag_needed()更新路由缓存项并获取有效的PMTU
				info = ip_rt_frag_needed(iph,
						     ntohs(icmph->un.frag.mtu));
				if (!info)
					goto out;
			}
			break;
		// 处理源站选路失败报文，打印相关信息	
		case ICMP_SR_FAILED:
			LIMIT_NETDEBUG(KERN_INFO "ICMP: %u.%u.%u.%u: Source "
						 "Route Failed.\n",
				       NIPQUAD(iph->daddr));
			break;
		default:
			break;
		}
		// 如果目的不可达报文的代码超过最大值，则该报文无效，直接返回
		if (icmph->code > NR_ICMP_UNREACH)
			goto out;
	} else if (icmph->type == ICMP_PARAMETERPROB)
		// 处理参数问题的差错报文，获取ICMP首部中的指针值，指针值存储在ICMP报文第二个32位
		// 字的高8位，因此获得该值后需右移24位
		info = ntohl(icmph->un.gateway) >> 24;

	/*
	 *	Throw it at our lower layers
	 *
	 *	RFC 1122: 3.2.2 MUST extract the protocol ID from the passed
	 *		  header.
	 *	RFC 1122: 3.2.2.1 MUST pass ICMP unreach messages to the
	 *		  transport layer.
	 *	RFC 1122: 3.2.2.2 MUST pass ICMP time expired messages to
	 *		  transport layer.
	 */

	/*
	 *	Check the other end isnt violating RFC 1122. Some routers send
	 *	bogus responses to broadcast frames. If you see this message
	 *	first check your netmask matches at both ends, if it does then
	 *	get the other vendor to fix their kit.
	 */
	// 根据系统参数icmp_ignore_bogus_error_responses来确定接收或忽略"目的不可达
	// 并且目的IP地址为广播地址"这样无效的ICMP报文，如果忽略，则在接收到这样的ICMP
	// 报文后，会记录相应的告警信息
	if (!sysctl_icmp_ignore_bogus_error_responses &&
	    inet_addr_type(iph->daddr) == RTN_BROADCAST) {
		// net_ratelimit()是内核打印限速函数，返回TRUE时可打印调试信息
		if (net_ratelimit())
			printk(KERN_WARNING "%u.%u.%u.%u sent an invalid ICMP "
					    "type %u, code %u "
					    "error to a broadcast: %u.%u.%u.%u on %s\n",
			       NIPQUAD(skb->nh.iph->saddr),
			       icmph->type, icmph->code,
			       NIPQUAD(iph->daddr),
			       skb->dev->name);
		goto out;
	}

	/* Checkin full IP header plus 8 bytes of protocol to
	 * avoid additional coding at protocol handlers.
	 */
	// 检测ICMP报文中导致差错报文的(IP首部(包括选项)　+ 原始IP数据报中数据的前8字节)内容
	// 长度是否正常 
	if (!pskb_may_pull(skb, iph->ihl * 4 + 8))
		goto out;

	// 接着获取ICMP报文中导致差错报文的IP首部和上层协议号
	iph = (struct iphdr *)skb->data;
	protocol = iph->protocol;

	/*
	 *	Deliver ICMP message to raw sockets. Pretty useless feature?
	 */

	/* Note: See raw.c and net/raw.h, RAWV4_HTABLE_SIZE==MAX_INET_PROTOS */
	// 通过传输层协议号，首先在raw_v4_htable散列表中查找是否有对应的原始套接口传输控制块
	// 由于原始套接口传输控制块的存在，应用程序可以组装各种协议的数据报，如TCP段、UDP数据报等
	// 这里判断不了到底是原始套接口的报文导致的差错，还是由TCP或UDP套接口发送报文导致的差错
	// 因此只能先把差错发送给原始套接口(如果存在) ，然后再发给TCP或UDP套接口
	hash = protocol & (MAX_INET_PROTOS - 1);
	read_lock(&raw_v4_lock);
	if ((raw_sk = sk_head(&raw_v4_htable[hash])) != NULL) {
		while ((raw_sk = __raw_v4_lookup(raw_sk, protocol, iph->daddr,
						 iph->saddr,
						 skb->dev->ifindex)) != NULL) {
			// 如果有对应的原始套接口传输控制块，则调用raw_err()将差错报文传递上去
			raw_err(raw_sk, skb, info);
			raw_sk = sk_next(raw_sk);
			iph = (struct iphdr *)skb->data;
		}
	}
	read_unlock(&raw_v4_lock);

	rcu_read_lock();
	// 通过传输层协议号，在inet_protos数组中找到相应传输层协议的net_protocol结构实例
	// 然后调用该实例中定义的传输层差错处理例程
	ipprot = rcu_dereference(inet_protos[hash]);
	if (ipprot && ipprot->err_handler)
		ipprot->err_handler(skb, info);
	rcu_read_unlock();

out:
	return;
out_err:
	ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
	goto out;
}


/*
 *	Handle ICMP_REDIRECT.
 */
// 当一个路由器发现一个主机使用的是非优化路由时，会发送一个ICMP报文给该主机，请求
// 其改变路由，这样的ICMP报文就是重定向报文，因此，这种类型的ICMP报文只能由路由器生成，为主机使用
// icmp_redirect()用来处理重定向报文 
static void icmp_redirect(struct sk_buff *skb)
{
	struct iphdr *iph;

	// 通过报文的长度检测重定向ICMP报文是否正常
	if (skb->len < sizeof(struct iphdr))
		goto out_err;

	/*
	 *	Get the copied header of the packet that caused the redirect
	 */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto out;

	iph = (struct iphdr *)skb->data;

	switch (skb->h.icmph->code & 7) {
	case ICMP_REDIR_NET:
	case ICMP_REDIR_NETTOS:
		/*
		 * As per RFC recommendations now handle it as a host redirect.
		 */
	case ICMP_REDIR_HOST:
	case ICMP_REDIR_HOSTTOS:
		// 通过对报文代码的过滤之后，使用ip_rt_redirect()处理正常的重定向ICMP报文
		ip_rt_redirect(skb->nh.iph->saddr, iph->daddr,
			       skb->h.icmph->un.gateway,
			       iph->saddr, skb->dev);
		break;
  	}
out:
	return;
out_err:
	ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
	goto out;
}

/*
 *	Handle ICMP_ECHO ("ping") requests.
 *
 *	RFC 1122: 3.2.2.6 MUST have an echo server that answers ICMP echo
 *		  requests.
 *	RFC 1122: 3.2.2.6 Data received in the ICMP_ECHO request MUST be
 *		  included in the reply.
 *	RFC 1812: 4.3.3.6 SHOULD have a config option for silently ignoring
 *		  echo requests, MUST have default=NOT.
 *	See also WRT handling of options once they are done and working.
 */
// icmp_echo()用来处理回显请求报文，输出回显应答报文
static void icmp_echo(struct sk_buff *skb)
{
	// 如果设置了忽略回显请求报文的系统参数sysctl_icmp_echo_ignore_all
	// 则直接返回
	if (!sysctl_icmp_echo_ignore_all) {
		// 否则根据请求ICMP报文设置icmp_bxm结构，然后将该结构传递给icmp_reply()
		// 创建并发送回显应答ICMP报文
		struct icmp_bxm icmp_param;

		icmp_param.data.icmph	   = *skb->h.icmph;
		icmp_param.data.icmph.type = ICMP_ECHOREPLY;
		icmp_param.skb		   = skb;
		icmp_param.offset	   = 0;
		icmp_param.data_len	   = skb->len;
		icmp_param.head_len	   = sizeof(struct icmphdr);
		icmp_reply(&icmp_param, skb);
	}
}

/*
 *	Handle ICMP Timestamp requests.
 *	RFC 1122: 3.2.2.8 MAY implement ICMP timestamp requests.
 *		  SHOULD be in the kernel for minimum random latency.
 *		  MUST be accurate to a few minutes.
 *		  MUST be updated at least at 15Hz.
 */
// icmp_timestamp() 处理时间戳请求报文
static void icmp_timestamp(struct sk_buff *skb)
{
	struct timeval tv;
	struct icmp_bxm icmp_param;
	/*
	 *	Too short.
	 */
	if (skb->len < 4)
		goto out_err;

	/*
	 *	Fill in the current time as ms since midnight UT:
	 */
	// 调用do_gettimeofday()获取系统当前的时间作为接收请求和发送应答时间
	// 设置到icmp_bxm结构的时间戳数组中，然后根据请求报文进一步设置该结构
	// 最后调用icmp_reply()创建并发送时间戳应答ICMP报文 
	do_gettimeofday(&tv);
	icmp_param.data.times[1] = htonl((tv.tv_sec % 86400) * 1000 +
					 tv.tv_usec / 1000);
	icmp_param.data.times[2] = icmp_param.data.times[1];
	if (skb_copy_bits(skb, 0, &icmp_param.data.times[0], 4))
		BUG();
	icmp_param.data.icmph	   = *skb->h.icmph;
	icmp_param.data.icmph.type = ICMP_TIMESTAMPREPLY;
	icmp_param.data.icmph.code = 0;
	icmp_param.skb		   = skb;
	icmp_param.offset	   = 0;
	icmp_param.data_len	   = 0;
	icmp_param.head_len	   = sizeof(struct icmphdr) + 12;
	icmp_reply(&icmp_param, skb);
out:
	return;
out_err:
	ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
	goto out;
}


/*
 *	Handle ICMP_ADDRESS_MASK requests.  (RFC950)
 *
 * RFC1122 (3.2.2.9).  A host MUST only send replies to
 * ADDRESS_MASK requests if it's been configured as an address mask
 * agent.  Receiving a request doesn't constitute implicit permission to
 * act as one. Of course, implementing this correctly requires (SHOULD)
 * a way to turn the functionality on and off.  Another one for sysctl(),
 * I guess. -- MS
 *
 * RFC1812 (4.3.3.9).	A router MUST implement it.
 *			A router SHOULD have switch turning it on/off.
 *		      	This switch MUST be ON by default.
 *
 * Gratuitous replies, zero-source replies are not implemented,
 * that complies with RFC. DO NOT implement them!!! All the idea
 * of broadcast addrmask replies as specified in RFC950 is broken.
 * The problem is that it is not uncommon to have several prefixes
 * on one physical interface. Moreover, addrmask agent can even be
 * not aware of existing another prefixes.
 * If source is zero, addrmask agent cannot choose correct prefix.
 * Gratuitous mask announcements suffer from the same problem.
 * RFC1812 explains it, but still allows to use ADDRMASK,
 * that is pretty silly. --ANK
 *
 * All these rules are so bizarre, that I removed kernel addrmask
 * support at all. It is wrong, it is obsolete, nobody uses it in
 * any case. --ANK
 *
 * Furthermore you can do it with a usermode address agent program
 * anyway...
 */

static void icmp_address(struct sk_buff *skb)
{
#if 0
	if (net_ratelimit())
		printk(KERN_DEBUG "a guy asks for address mask. Who is it?\n");
#endif
}

/*
 * RFC1812 (4.3.3.9).	A router SHOULD listen all replies, and complain
 *			loudly if an inconsistency is found.
 */

static void icmp_address_reply(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable *)skb->dst;
	struct net_device *dev = skb->dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;

	if (skb->len < 4 || !(rt->rt_flags&RTCF_DIRECTSRC))
		goto out;

	in_dev = in_dev_get(dev);
	if (!in_dev)
		goto out;
	rcu_read_lock();
	if (in_dev->ifa_list &&
	    IN_DEV_LOG_MARTIANS(in_dev) &&
	    IN_DEV_FORWARD(in_dev)) {
		__be32 _mask, *mp;

		mp = skb_header_pointer(skb, 0, sizeof(_mask), &_mask);
		BUG_ON(mp == NULL);
		for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
			if (*mp == ifa->ifa_mask &&
			    inet_ifa_match(rt->rt_src, ifa))
				break;
		}
		if (!ifa && net_ratelimit()) {
			printk(KERN_INFO "Wrong address mask %u.%u.%u.%u from "
					 "%s/%u.%u.%u.%u\n",
			       NIPQUAD(*mp), dev->name, NIPQUAD(rt->rt_src));
		}
	}
	rcu_read_unlock();
	in_dev_put(in_dev);
out:;
}

static void icmp_discard(struct sk_buff *skb)
{
}

/*
 *	Deal with incoming ICMP packets.
 */
int icmp_rcv(struct sk_buff *skb)
{
	struct icmphdr *icmph;
	struct rtable *rt = (struct rtable *)skb->dst;

	ICMP_INC_STATS_BH(ICMP_MIB_INMSGS);

	// 检测ICMP报文的校验和，如果此报文已经经过了校验操作，则需要对得到的
	// 校验和进行验证，如果由软件来执行校验和，则调用__skb_checksum_complete()
	// 进行校验和检测
	switch (skb->ip_summed) {
	case CHECKSUM_COMPLETE:
		if (!csum_fold(skb->csum))
			break;
		/* fall through */
	case CHECKSUM_NONE:
		skb->csum = 0;
		if (__skb_checksum_complete(skb))
			goto error;
	}

	// 丢弃ICMP首部，获得ICMP报文内容，如果报文有异常，则跳转到error出错处理
	if (!pskb_pull(skb, sizeof(struct icmphdr)))
		goto error;

	icmph = skb->h.icmph;

	/*
	 *	18 is the highest 'known' ICMP type. Anything else is a mystery
	 *
	 *	RFC 1122: 3.2.2  Unknown ICMP messages types MUST be silently
	 *		  discarded.
	 */
	// 检测ICMP报文的类型，如果其值超过了现有类型的最大值，此ICMP报文类型无效
	// 跳转到error出错处理 
	if (icmph->type > NR_ICMP_TYPES)
		goto error;


	/*
	 *	Parse the ICMP message
	 */
	// 处理通过组播或者广播方式发送的ICMP报文
 	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
		/*
		 *	RFC 1122: 3.2.2.6 An ICMP_ECHO to broadcast MAY be
		 *	  silently ignored (we let user decide with a sysctl).
		 *	RFC 1122: 3.2.2.8 An ICMP_TIMESTAMP MAY be silently
		 *	  discarded if to broadcast/multicast.
		 */
		// 在开启了icmp_echo_ignore_broadcasts的情况下，如果组播或广播报文是请求
		// 回显或时间戳请求类型的ICMP报文应该被忽略，因此跳转到error出错处理 
		if ((icmph->type == ICMP_ECHO ||
		     icmph->type == ICMP_TIMESTAMP) &&
		    sysctl_icmp_echo_ignore_broadcasts) {
			goto error;
		}
		// 除了请求回显，时间戳请求，地址掩码请求和地址掩码应答类型的ICMP报文可以接收之外
		// 其他类型的ICMP报文都不支持组播或广播，当然前两种类型要在不开启icmp_echo_ignore_broadcasts
		// 的情况下才能被接收
		if (icmph->type != ICMP_ECHO &&
		    icmph->type != ICMP_TIMESTAMP &&
		    icmph->type != ICMP_ADDRESS &&
		    icmph->type != ICMP_ADDRESSREPLY) {
			goto error;
  		}
	}

	// 由ICMP报文的类型，在icmp_pointers数组中找到该类型的icmp_control结构实例
	// 先更新统计值input_entry，然后调用处理函数处理接收到的ICMP报文
	ICMP_INC_STATS_BH(icmp_pointers[icmph->type].input_entry);
	icmp_pointers[icmph->type].handler(skb);

// 出错处理代码，在处理过程中发现有异常的报文，都会跳转到这里，更新统计值ICMP_MIB_INERRORS
// 后丢弃报文
drop:
	kfree_skb(skb);
	return 0;
error:
	ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
	goto drop;
}

/*
 *	This table is the definition of how we handle ICMP.
 */
static const struct icmp_control icmp_pointers[NR_ICMP_TYPES + 1] = {
	[ICMP_ECHOREPLY] = {
		.output_entry = ICMP_MIB_OUTECHOREPS,
		.input_entry = ICMP_MIB_INECHOREPS,
		.handler = icmp_discard,
	},
	[1] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_INERRORS,
		.handler = icmp_discard,
		.error = 1,
	},
	[2] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_INERRORS,
		.handler = icmp_discard,
		.error = 1,
	},
	// 目的不可达
	[ICMP_DEST_UNREACH] = {
		.output_entry = ICMP_MIB_OUTDESTUNREACHS,
		.input_entry = ICMP_MIB_INDESTUNREACHS,
		.handler = icmp_unreach,
		.error = 1,
	},
	// 源端被关闭
	[ICMP_SOURCE_QUENCH] = {
		.output_entry = ICMP_MIB_OUTSRCQUENCHS,
		.input_entry = ICMP_MIB_INSRCQUENCHS,
		.handler = icmp_unreach,
		.error = 1,
	},
	// 重定向
	[ICMP_REDIRECT] = {
		.output_entry = ICMP_MIB_OUTREDIRECTS,
		.input_entry = ICMP_MIB_INREDIRECTS,
		.handler = icmp_redirect,
		.error = 1,
	},
	[6] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_INERRORS,
		.handler = icmp_discard,
		.error = 1,
	},
	[7] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_INERRORS,
		.handler = icmp_discard,
		.error = 1,
	},
	// 请求回显
	[ICMP_ECHO] = {
		.output_entry = ICMP_MIB_OUTECHOS,
		.input_entry = ICMP_MIB_INECHOS,
		.handler = icmp_echo,
	},
	[9] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_INERRORS,
		.handler = icmp_discard,
		.error = 1,
	},
	[10] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_INERRORS,
		.handler = icmp_discard,
		.error = 1,
	},
	// 超时
	[ICMP_TIME_EXCEEDED] = {
		.output_entry = ICMP_MIB_OUTTIMEEXCDS,
		.input_entry = ICMP_MIB_INTIMEEXCDS,
		.handler = icmp_unreach,
		.error = 1,
	},
	// 参数问题
	[ICMP_PARAMETERPROB] = {
		.output_entry = ICMP_MIB_OUTPARMPROBS,
		.input_entry = ICMP_MIB_INPARMPROBS,
		.handler = icmp_unreach,
		.error = 1,
	},
	// 时间戳请求
	[ICMP_TIMESTAMP] = {
		.output_entry = ICMP_MIB_OUTTIMESTAMPS,
		.input_entry = ICMP_MIB_INTIMESTAMPS,
		.handler = icmp_timestamp,
	},
	[ICMP_TIMESTAMPREPLY] = {
		.output_entry = ICMP_MIB_OUTTIMESTAMPREPS,
		.input_entry = ICMP_MIB_INTIMESTAMPREPS,
		.handler = icmp_discard,
	},
	[ICMP_INFO_REQUEST] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_DUMMY,
		.handler = icmp_discard,
	},
 	[ICMP_INFO_REPLY] = {
		.output_entry = ICMP_MIB_DUMMY,
		.input_entry = ICMP_MIB_DUMMY,
		.handler = icmp_discard,
	},
	// 地址掩码请求
	[ICMP_ADDRESS] = {
		.output_entry = ICMP_MIB_OUTADDRMASKS,
		.input_entry = ICMP_MIB_INADDRMASKS,
		.handler = icmp_address,
	},
	// 地址掩码应答
	[ICMP_ADDRESSREPLY] = {
		.output_entry = ICMP_MIB_OUTADDRMASKREPS,
		.input_entry = ICMP_MIB_INADDRMASKREPS,
		.handler = icmp_address_reply,
	},
};

// ICMP初始化函数是icmp_init()，在inet_init()中被调用，其主要功能是为每个CPU创建一个
// 基于原始流、IPPROTO_ICMP协议类型的套接口供内核使用
void __init icmp_init(struct net_proto_family *ops)
{
	struct inet_sock *inet;
	int i;

	for_each_possible_cpu(i) {
		// 针对每个CPU做以下操作
		int err;

		// 为每个CPU创建一个基于原始流、IPPROTO_ICMP协议类型的套接口
		err = sock_create_kern(PF_INET, SOCK_RAW, IPPROTO_ICMP,
				       &per_cpu(__icmp_socket, i));

		if (err < 0)
			panic("Failed to create the ICMP control socket.\n");

		// 设置基于该传输控制块的内存分配方式为GFP_ATOMIC
		per_cpu(__icmp_socket, i)->sk->sk_allocation = GFP_ATOMIC;

		/* Enough space for 2 64K ICMP packets, including
		 * sk_buff struct overhead.
		 */
		// 设置传输控制块发送缓存的大小 
		per_cpu(__icmp_socket, i)->sk->sk_sndbuf =
			(2 * ((64 * 1024) + sizeof(struct sk_buff)));

		// 初始化单播报文的TTL值为-1，表示从目的路由缓存项的度量值中获取，默认值为64
		inet = inet_sk(per_cpu(__icmp_socket, i)->sk);
		inet->uc_ttl = -1;
		// 初始化pmtudisc为IP_PMTUDISC_DONT，即不执行路径MTU发现
		inet->pmtudisc = IP_PMTUDISC_DONT;

		/* Unhash it so that IP input processing does not even
		 * see it, we do not wish this socket to see incoming
		 * packets.
		 */
		// 为了避免ICMP套接口接收到报文，因此调用传输层接口上的unhash(参见raw_v4_unhash())
		// 将套接口从原始流套接口散列表raw_v4_htable中取下
		per_cpu(__icmp_socket, i)->sk->sk_prot->unhash(per_cpu(__icmp_socket, i)->sk);
	}
}

EXPORT_SYMBOL(icmp_err_convert);
EXPORT_SYMBOL(icmp_send);
EXPORT_SYMBOL(icmp_statistics);
EXPORT_SYMBOL(xrlim_allow);
