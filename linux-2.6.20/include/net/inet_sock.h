/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/string.h>
#include <linux/types.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	// 只针对向外发送，并设置了源路由选项的数据包有意义，faddr存放源路由列表的第一个ip地址
	__be32		faddr;
	// ip选项的总长度
	unsigned char	optlen;
	// 源路由选项存放在协议头的偏移量
	unsigned char	srr;
	// rr表示路由器应在ip协议头的何处记录路由选项的偏移量
	unsigned char	rr;
	// ts记录了时间戳选项在ip协议头中位置的偏移量
	unsigned char	ts;
	// 接下来的数据域为一个标志位数据域，各标志位在该数据域中占1位，标志
	// ip选项的设备状态及应对选项或数据包做的处理
	unsigned char	is_data:1,
			// 该位为true时，说明ip选项中源路由选项设置的是严格源路由
			is_strictroute:1,
			// 该位为true时，说明数据包中设置了源路由选项，在为发送数据包
			// 做路由决策时，通过skb->dst或路由表获取的下一跳ip地址和路由
			// 列表中下一跳ip地址一致称为ip地址命中(hit)
			srr_is_hit:1,
			// 若ip协议头发生变好，则设置该位，ip协议头是否发生变化决定了是否需要
			// 重新计算ip校验和
			is_changed:1,
			// 当ip选项设置了记录路由选项时，如果rr_needaddr的值为1，表明协议头中
			// 还有空间记录其他路由信息，这时当前站点应将发送数据包的网络接口ip地址
			// 复制到协议头中rr指定的偏移量处
			rr_needaddr:1,
			// ts_needtime和ts_needaddr这两个标志与时间戳选项有关，分别表明了时间戳
			// 选项是否记录数据包达到站点的时间和ip地址
			ts_needtime:1,
			ts_needaddr:1;
	// 如果ip选项中设置了路由报警选项，route_alert指明路由报警选项在协议头中存放位置的偏移量
	unsigned char	router_alert;
	unsigned char	cipso;
	// 此数据域是为使ip选项处于32位地址边界对齐而加在最后的填充数据
	unsigned char	__pad2;
	// 这个数据域用于将本地主机产生的数据包向外发送情况下，以及本地站点要求回答的icmp请求传回
	// 应答数据包时，__data[0]指向存放要加入数据包协议头的ip选项的地址
	unsigned char	__data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
	/* 2 bytes hole, try to pack */
#endif
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	u16			snd_wscale : 4, 
				rcv_wscale : 4, 
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1;
	struct ip_options	*opt;
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @daddr - Foreign IPv4 addr
 * @rcv_saddr - Bound local IPv4 addr
 * @dport - Destination port
 * @num - Local port
 * @saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @sport - Source port
 * @id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
// inet_sock结构是IPv4协议专用的传输控制块，是对sock结构的扩展，在传输控制块的基本
// 属性已具备的情况下，进一步提供IPv4协议专有的一些属性，如TTL、组播列表、IP地址、端口等
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	// 如果支持IPv6特性，pinet6是指向IPv6控制块的指针
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	// 目的IP地址
	__be32			daddr;
	// 已绑定的本地IP地址，接收数据时，作为条件的一部分查找数据所属的传输控制块
	__be32			rcv_saddr;
	// 目的端口
	__be16			dport;
	// 主机字节序存储的本地端口
	__u16			num;
	// 标识本地IP地址，但在发送时使用，rcv_saddr和saddr都描述本地IP地址，但用途不同
	__be32			saddr;
	// 单播报文的TTL、默认值为-1，表示使用默认的TTL值，在输出IP数据报时，TTL值首先从
	// 这里获取，若没有设置，则从路由缓存的metric中获取
	__s16			uc_ttl;
	// 存放一些IPPROTO_IP级别的选项值
	__u16			cmsg_flags;
	// 指向IP数据报选项的指针
	struct ip_options	*opt;
	// 由num转换成的网络字节序的源端口
	__be16			sport;
	// 一个单调递增的值，用来赋给IP首部中的id域
	__u16			id;
	// 用于设置IP数据报首部的TOS域，参见IP_TOS套接口选项
	__u8			tos;
	// 设置多播数据报的TTL
	__u8			mc_ttl;
	// 标识套接口是否启用路径MTU发现功能，初始值根据系统控制参数ip_no_pmtu_disc来确定
	// IP_PMTUDISC_DO:启用路径MTU发现功能，通常输出的数据报不分片，对于非STREAM套接口，
	// 则会拒绝发送大于MTU的报文
	// IP_PMTUDISC_DONT:不启用路径MTU发现功能，输出的报文允许分片
	// IP_PMTUDISC_WANT:在允许修改存储在路由项中的路径MTU(没有锁定)情况下，启用路径MTU发现功能
	// 在输出IP数据报时，会用ip_dont_fragment()来检测待输出的IP数据报能否分片，如果不能分片，
	// 则会在IP数据报首部添加不允许分片的标志
	__u8			pmtudisc;
	// 标识是否允许接收扩展的可靠错误消息
	__u8			recverr:1,
				// 标识是否为基于连接的传输控制块，即是否为基于inet_connection_sock结构的传输控制块
				// 如TCP的传输控制块
				is_icsk:1,
				// 标识是否允许绑定非主机地址，参见IP_FREEBIND套接口选项
				freebind:1,
				// 标识IP首部是否由用户数据构建，该标志只用于RAW套接口，一旦设置后，IP选项中的IP_TTL和
				// IP_TOS都将被忽略
				hdrincl:1,
				// 标识组播是否发向回路
				mc_loop:1;
	// 发送组播报文的网络设备索引号，如果为0，则表示可以从任何网络设备发送			
	int			mc_index;
	// 发送组播报文的源地址
	__be32			mc_addr;
	// 所在套接口加入的组播地址列表
	struct ip_mc_socklist	*mc_list;
	// UDP或原始IP在每次发送时缓存的一些临时信息，如，UDP数据报或原始IP数据报分片的大小
	struct {
		// IPCORK_OPT:标识IP选项信息是否已在cork的opt成员中
		// IPCORK_ALLFRAG:总是分片（只用于IPv6）
		unsigned int		flags;
		// UDP数据报或原始IP数据报分片大小
		unsigned int		fragsize;
		// 指向此次发送数据报的IP选项
		struct ip_options	*opt;
		// 发送数据报使用的输出路由缓存项
		struct rtable		*rt;
		// 当前发送的数据报的数据长度
		int			length; /* Total length of all frames */
		// 输出IP数据报的目的地址
		__be32			addr;
		// 用flowi结构来缓存目的地址，目的端口，源地址和源端口，构造UDP报文时
		// 有关信息就取自这里
		struct flowi		fl;
	} cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

static inline unsigned int inet_ehashfn(const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	unsigned int h = ((__force __u32)laddr ^ lport) ^ ((__force __u32)faddr ^ (__force __u32)fport);
	h ^= h >> 16;
	h ^= h >> 8;
	return h;
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __be32 faddr = inet->daddr;
	const __be16 fport = inet->dport;

	return inet_ehashfn(laddr, lport, faddr, fport);
}

#endif	/* _INET_SOCK_H */
