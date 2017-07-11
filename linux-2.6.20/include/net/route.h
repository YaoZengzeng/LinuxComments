/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>
#include <linux/security.h>

#ifndef __KERNEL__
#warning This file is not supposed to be used outside of kernel.
#endif

#define RTO_ONLINK	0x01

#define RTO_CONN	0
/* RTO_CONN is not used (being alias for 0), but preserved not to break
 * some modules referring to it. */

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))

struct fib_nh;
struct inet_peer;
struct rtable
{
	union
	{
		// dst_entry结构作为一部分嵌入到rtable结构中，而dst_entry结构的第一个成员next
		// 就是用于链接分布在同一个散列桶内的rtable实例，为了便于访问next，因此将dst和rt_next
		// 联合起来，虽然指针的名称不同，但它们所指向的内存位置是相同的
		struct dst_entry	dst;
		struct rtable		*rt_next;
	} u;

	// 指向输出网络设备的IPv4协议族的IP配置块，注意：对送往本地的输入报文的路由
	// 输出网络设备设置为回环设备
	struct in_device	*idev;
	
	// 用于标识路由表项的一些特性和标志
	// RTCF_NOTIFY：路由表项的所有变化通过netlink通知给感兴趣的用户空间应用程序
	// RTCF_REDIRECTED：由接收到的ICMP_REDIRECT消息作出响应而添加的一条路由缓存项
	// ...
	unsigned		rt_flags;
	// 路由表项的类型，它间接定义了当路由查找匹配时应采取的动作
	// RTN_UNSPEC：定义一个未初始化的值
	// RTN_LOCAL：目的地址被配置为一个本地接口的地址
	// ...
	__u16			rt_type;
	// 标识多路径缓存算法，在创建路由表项时根据相关路由项的配置来设置
	__u16			rt_multipath_alg;

	// 目的IP地址和源IP地址
	__be32			rt_dst;	/* Path destination	*/
	__be32			rt_src;	/* Path source		*/
	// 输入网络设备标识，从输入网络设备的net_device数据结构中得到，对本地生成的流量
	// (因为不是从任何接口上接收到的)，该字段被设置为出设备的ifindex字段，对本地生成
	// 的报文，fl中的iff字段被设置为０
	int			rt_iif;

	/* Info on neighbour */
	// 当目的主机为直连时，即在同一链路上，rt_gateway表示目的地址，当需要通过一个网关
	// 到达目的地时，rt_gateway被设置为路由项中的下一跳网关
	__be32			rt_gateway;

	/* Cache lookup keys */
	// 用于缓存查找的搜索的条件组合
	struct flowi		fl;

	/* Miscellaneous cached information */
	// 首选源地址
	// 添加到路由缓存内的路由缓存项是单向的，但是在一些情况下，接收到报文可能触发一个动作，
	// 要求本地主机选择一个源IP地址，以便在向发送方回送报文时使用，这个地址，即首选源IP地址
	// 必须与路由该报文的路由缓存项保存在一起，下面是使用该地址的两种情况：
	// (1) 当一个主机接收到一个ICMP回显请求时（常用的ping命令），如果主机没有明确配置不作出回应
	// 则该主机返回一个ICMP回显应答消息。对该输入ICMP回显请求消息选择路由，路由项的rt_spec_dst被
	// 用作路由ICMP回显请求消息而进行路由查找的源地址
	// (2) 记录路由IP选项和时间戳IP选项要求途经主机的IP地址记录到选项中
	__be32			rt_spec_dst; /* RFC1122 specific destination */
	// 指向与目的地址相关的对端信息块
	struct inet_peer	*peer; /* long-living peer info */
};

struct ip_rt_acct
{
	__u32 	o_bytes;
	__u32 	o_packets;
	__u32 	i_bytes;
	__u32 	i_packets;
};

struct rt_cache_stat 
{
        unsigned int in_hit;
        unsigned int in_slow_tot;
        unsigned int in_slow_mc;
        unsigned int in_no_route;
        unsigned int in_brd;
        unsigned int in_martian_dst;
        unsigned int in_martian_src;
        unsigned int out_hit;
        unsigned int out_slow_tot;
        unsigned int out_slow_mc;
        unsigned int gc_total;
        unsigned int gc_ignored;
        unsigned int gc_goal_miss;
        unsigned int gc_dst_overflow;
        unsigned int in_hlist_search;
        unsigned int out_hlist_search;
};

extern struct ip_rt_acct *ip_rt_acct;

struct in_device;
extern int		ip_rt_init(void);
extern void		ip_rt_redirect(__be32 old_gw, __be32 dst, __be32 new_gw,
				       __be32 src, struct net_device *dev);
extern void		ip_rt_advice(struct rtable **rp, int advice);
extern void		rt_cache_flush(int how);
extern int		__ip_route_output_key(struct rtable **, const struct flowi *flp);
extern int		ip_route_output_key(struct rtable **, struct flowi *flp);
extern int		ip_route_output_flow(struct rtable **rp, struct flowi *flp, struct sock *sk, int flags);
extern int		ip_route_input(struct sk_buff*, __be32 dst, __be32 src, u8 tos, struct net_device *devin);
extern unsigned short	ip_rt_frag_needed(struct iphdr *iph, unsigned short new_mtu);
extern void		ip_rt_send_redirect(struct sk_buff *skb);

extern unsigned		inet_addr_type(__be32 addr);
extern void		ip_rt_multicast_event(struct in_device *);
extern int		ip_rt_ioctl(unsigned int cmd, void __user *arg);
extern void		ip_rt_get_source(u8 *src, struct rtable *rt);
extern int		ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb);

struct in_ifaddr;
extern void fib_add_ifaddr(struct in_ifaddr *);

static inline void ip_rt_put(struct rtable * rt)
{
	if (rt)
		dst_release(&rt->u.dst);
}

#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

static inline int ip_route_connect(struct rtable **rp, __be32 dst,
				   __be32 src, u32 tos, int oif, u8 protocol,
				   __be16 sport, __be16 dport, struct sock *sk)
{
	struct flowi fl = { .oif = oif,
			    .nl_u = { .ip4_u = { .daddr = dst,
						 .saddr = src,
						 .tos   = tos } },
			    .proto = protocol,
			    .uli_u = { .ports =
				       { .sport = sport,
					 .dport = dport } } };

	int err;
	if (!dst || !src) {
		err = __ip_route_output_key(rp, &fl);
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;
		fl.fl4_src = (*rp)->rt_src;
		ip_rt_put(*rp);
		*rp = NULL;
	}
	security_sk_classify_flow(sk, &fl);
	return ip_route_output_flow(rp, &fl, sk, 0);
}

static inline int ip_route_newports(struct rtable **rp, u8 protocol,
				    __be16 sport, __be16 dport, struct sock *sk)
{
	if (sport != (*rp)->fl.fl_ip_sport ||
	    dport != (*rp)->fl.fl_ip_dport) {
		struct flowi fl;

		memcpy(&fl, &(*rp)->fl, sizeof(fl));
		fl.fl_ip_sport = sport;
		fl.fl_ip_dport = dport;
		fl.proto = protocol;
		ip_rt_put(*rp);
		*rp = NULL;
		security_sk_classify_flow(sk, &fl);
		return ip_route_output_flow(rp, &fl, sk, 0);
	}
	return 0;
}

extern void rt_bind_peer(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	rt_bind_peer(rt, 0);
	return rt->peer;
}

extern ctl_table ipv4_route_table[];

#endif	/* _ROUTE_H */
