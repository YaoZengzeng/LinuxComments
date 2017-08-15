/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *		
 * Version:	$Id: ip_forward.c,v 1.48 2000/12/13 18:31:48 davem Exp $
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for 
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast 
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

static inline int ip_forward_finish(struct sk_buff *skb)
{
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(IPSTATS_MIB_OUTFORWDATAGRAMS);

	if (unlikely(opt->optlen))
		// 处理转发IP数据报中的IP选项，包括记录路由选项和时间戳选项
		ip_forward_options(skb);

	// 通过路由缓存将数据报输出，最终会调用单播的输出函数ip_output()或组播的输出函数ip_mc_output()
	return dst_output(skb);
}

int ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	// 调用xfrm4_policy_check()检查IPsec策略数据库，查找失败，则丢弃该数据报
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

	// 如果数据报中存在路由警告选项，则调用ip_call_ra_chain()将数据报输入给对
	// 路由警告选项感兴趣的用户进程，如果成功，则不再转发数据报
	// ip_call_ra_chain会依据一个全局套接字列表: ip_ra_chain，其中的套接字对所有
	// 设置了IP_ROUTER_ALERT选项的数据包感兴趣
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	// 承载该IP数据报的以太网帧目的地址与收到它的网络设备的MAC地址相等才能转发
	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	// 由于在转发过程中可能会修改IP首部，因此将ip_summed设置为CHECKSUM_NONE，
	// 在后续的输出时还得由软件来执行校验和
	skb->ip_summed = CHECKSUM_NONE;
	
	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */
	// 此时还没对ttl递减是因为此时数据包可能还与别的子系统共享，还不能对头信息进行修改
	if (skb->nh.iph->ttl <= 1)
                goto too_many_hops;

    // 进行IPSec路由选路和转发处理
	if (!xfrm4_route_forward(skb))
		goto drop;

	rt = (struct rtable*)skb->dst;

	// 如果数据报启用严格路由选项，且数据报的下一条不是网关，则发送超时ICMP报文到对方，并丢弃该数据报
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;

	/* We are about to mangle packet. Copy it! */
	// 确保SKB有指定长度的headroom空间，当SKB的headroom空间小于指定长度或者克隆SKB时
	// 会新建SKB缓冲并释放对原包的引用
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;
	iph = skb->nh.iph;

	/* Decrease ttl after skb cow done */
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	// 该数据报的输出路由存在重定向标志，且该数据报中不存在源路由选项
	// 而路由子系统获取的路由更优化，则向发送方发送重定向ICMP报文
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr)
		ip_rt_send_redirect(skb);

	// 设置skb->priority数据域，该数据域给ip协议头的type of service使用，
	// 流量控制子系统(QoS)使用优先级决定数据包发送顺序
	skb->priority = rt_tos2priority(iph->tos);

	return NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ip_forward_finish);

sr_failed:
        /*
	 *	Strict routing permits no gatewaying
	 */
         icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
         goto drop;

too_many_hops:
        /* Tell the sender its packet died... */
        IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
        icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
