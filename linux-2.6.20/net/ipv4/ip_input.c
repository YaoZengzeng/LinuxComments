/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Version:	$Id: ip_input.c,v 1.55 2002/01/12 07:39:45 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *  
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single 
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *	SNMP management statistics
 */

DEFINE_SNMP_STAT(struct ipstats_mib, ip_statistics) __read_mostly;

/*
 *	Process Router Attention IP option
 */ 
int ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = skb->nh.iph->protocol;
	struct sock *last = NULL;

	read_lock(&ip_ra_lock);
	for (ra = ip_ra_chain; ra; ra = ra->next) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == skb->dev->ifindex)) {
			if (skb->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
				skb = ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN);
				if (skb == NULL) {
					read_unlock(&ip_ra_lock);
					return 1;
				}
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		read_unlock(&ip_ra_lock);
		return 1;
	}
	read_unlock(&ip_ra_lock);
	return 0;
}

// 该函数将输入数据报从网络层传递到传输层
// 除了内核要处理网络数据包以外，应用程序也可以处理数据包，因此，无论协议是否在内核中
// 注册了协议处理函数，ip_local_deliver_finish都要查看是否有应用程序创建了裸套接字
// 来处理协议相关的数据包，如果有，就复制一个数据包给应用程序
static inline int ip_local_deliver_finish(struct sk_buff *skb)
{
	int ihl = skb->nh.iph->ihl*4;

	// 去掉IP首部
	__skb_pull(skb, ihl);

        /* Point into the IP datagram, just past the header. */
        skb->h.raw = skb->data;

	rcu_read_lock();
	{
		/* Note: See raw.c and net/raw.h, RAWV4_HTABLE_SIZE==MAX_INET_PROTOS */
		int protocol = skb->nh.iph->protocol;
		int hash;
		struct sock *raw_sk;
		struct net_protocol *ipprot;

	resubmit:
		hash = protocol & (MAX_INET_PROTOS - 1);
		// 处理RAW套接口，查看raw_v4_htable散列表中以该值为关键字的哈希桶是否为空
		// 如果不为空，则说明创建了RAW套接口，复制该数据报的副本到输入到注册到该桶中
		// 的所有套接口
		raw_sk = sk_head(&raw_v4_htable[hash]);

		/* If there maybe a raw socket we must check - if not we
		 * don't care less
		 */
		if (raw_sk && !raw_v4_input(skb, skb->nh.iph, hash))
			raw_sk = NULL;

		// 查找inet_protos数组，确定是否注册了与IP首部中传输协议号一致的传输层协议
		if ((ipprot = rcu_dereference(inet_protos[hash])) != NULL) {
			int ret;

			// 如果配置了IPsec策略路由，则调用IPsec策略检查函数
			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			// 执行对应的传输层接收例程
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(IPSTATS_MIB_INDELIVERS);
		} else {
			// 如果是RAW套接口没有接收或接收异常，还需要产生一个目的不可达ICMP报文给对方
			if (!raw_sk) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
			} else
				IP_INC_STATS_BH(IPSTATS_MIB_INDELIVERS);
			kfree_skb(skb);
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
// 发送至本地的一个重要任务就是重组分了片的数据包，除了某些特殊情况，
// 例如网络过滤子系统重组了数据包来查看其内容，这时分过片数据包已完成重组
// 与此相反，在大多数情况下，转发操作不需要关系数据包的重组，转发操作可以
// 独立转发每个分片数据包
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	// 若是分片，则需要将分片重组
	if (skb->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		// 重组数据包的功能通过ip_defrag函数完成
		skb = ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER);
		// 返回0，则表示IP数据报分片尚未到齐，重组没有完成，直接返回
		if (!skb)
			return 0;
	}

	return NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline int ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	// 如果skb由多个进程贡献，则先产生一个skb头的拷贝，
	// 因为在处理IP选项时，可能会对skb头的数据做修改，　若拷贝不成功，则将数据包丢掉
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = skb->nh.iph;

	// ip_options_compile用于解析ip选项
	if (ip_options_compile(NULL, skb)) {
		IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	// 控制缓冲区用IPCB宏访问
	opt = &(IPCB(skb)->opt);
	// 如果ip选项中设置了源路由选项，将路由信息设置给skb->dst
	if (unlikely(opt->srr)) {
		struct in_device *in_dev = in_dev_get(dev);
		if (in_dev) {
			// 如果系统禁止使用源路由选项，扔掉数据包
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev) &&
				    net_ratelimit())
					printk(KERN_INFO "source route option "
					       "%u.%u.%u.%u -> %u.%u.%u.%u\n",
					       NIPQUAD(iph->saddr),
					       NIPQUAD(iph->daddr));
				in_dev_put(in_dev);
				goto drop;
			}

			in_dev_put(in_dev);
		}

		// 如果系统设置中允许使用源路由，调用ip_options_rcv_srr函数将路由设置
		// 在skb->dst中，并确定使用哪个设备将数据包发送到源路由列表中指定的下一跳
		// 通常要求下一站点是另一主机，则函数只设置opt->srr.is_hit，指明发现了地址
		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return 0;
drop:
	return -1;
}

// 在ip_rcv_finish()中，根据数据报的路由信息，决定这个数据报是转发还是输入到本地
// 由此产生两条路径，输入到本机由ip_local_deliver()处理，而转发由ip_forward()处理
// ip_rcv_finish的作用：
// 1. 确定数据包是转发还是在本机协议栈中上传，如果是转发需要确定输出网络设备和下一个
// 接收站点的地址
// 2. 解析和处理部分ip选项
static inline int ip_rcv_finish(struct sk_buff *skb)
{
	struct iphdr *iph = skb->nh.iph;

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */ 
	if (skb->dst == NULL) {
		// 调用ip_route_input()为其查找输入路由缓存
		int err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
					 skb->dev);
		if (unlikely(err)) {
			if (err == -EHOSTUNREACH)
				IP_INC_STATS_BH(IPSTATS_MIB_INADDRERRORS);
			goto drop; 
		}
	}

// 如果在配置内核时配置了流量控制功能，则更新QoS的统计信息
#ifdef CONFIG_NET_CLS_ROUTE
	if (unlikely(skb->dst->tclassid)) {
		struct ip_rt_acct *st = ip_rt_acct + 256*smp_processor_id();
		u32 idx = skb->dst->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes+=skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes+=skb->len;
	}
#endif

	// 处理IP选项
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	// 调用kb->dst->input函数指针指向的处理函数
	// 最后根据输入路由缓存决定输入到本地或转发，最终前者调用ip_local_deliver()
	// 后者调用ip_forward()
	return dst_input(skb);

drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */ 
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	// 只接收发往本机的数据报
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	IP_INC_STATS_BH(IPSTATS_MIB_INRECEIVES);

	// 检测接收到的数据报是否为一个共享数据包，如果是，必须复制一个副本，再做进一步处理
	// 因为在处理过程中可能会修改数据报中的信息
	// 在调用网络层IP协议的处理函数之前，netif_receive_skb会对skb的引用技术加1，IP
	// 协议处理函数查看到数据包的引用计数大于1时，会创建一个数据包的拷贝，这样IP协议处理
	// 函数就可以任意修改数据包的值，而netif_receive_skb接下来调用网络层其他协议处理
	// 函数收到的就是原始数据包
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	// 通过判断数据报长度来检测数据报是否有效，不能小于IP首部长度
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = skb->nh.iph;

	/*
	 *	RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = skb->nh.iph;

	// 检验校验和是否正确
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto inhdr_error;

	len = ntohs(iph->tot_len);
	// 确定缓冲区的长度大于或等于ip协议头信息中报告的数据包的长度
	// 确定整个数据包的长度至少不小于ip协议头的长度
	// 做检查的原因是数据链路层的协议可能会在负载后加补丁，以保证
	// 发送的数据包长度不小于数据链路层协议允许的最小数据包长度，这样
	// skb中的数据包长度(由skb->len数据域给出)可能大于实际的数据包长度
	// (由ip协议头信息len=ntohs(iph->tot_len)给出)
	// 第二个检查的原因是ip协议头不能被分割，如果数据包被分割成小的数据片
	// 每个ip数据片至少包含一个ip协议头(iph->ihl * 4)
	if (skb->len < len || len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	// 根据IP数据报首部中的数据报总长度重新设置skb的长度
	// 去掉网络传输介质在数据包中加的填充字节
	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/* Remove any debris in the socket control block */
	// 清空skb中的控制缓冲区skb->cb，以便后续对IP选项的处理
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	// skb是由dev收到的数据包，网络过滤子系统查看该数据包是否允许继续处理，是否
	// 需要对该数据包做修改，这由网络协议栈的NF_IP_PRE_ROUTING来决定，通过检查
	// 后如果数据包没被扔掉，则继续执行ip_rcv_finish
	return NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, dev, NULL,
		       ip_rcv_finish);

inhdr_error:
	IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
drop:
        kfree_skb(skb);
out:
        return NET_RX_DROP;
}

EXPORT_SYMBOL(ip_statistics);
