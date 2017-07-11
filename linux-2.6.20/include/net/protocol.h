/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */
 
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define MAX_INET_PROTOS	256		/* Must be a power of 2		*/


/* This is used to register protocols. */
// 此结构是网络层和传输层（包括ICMP和IGMP协议）之间的桥梁
// 内核中为Internet协议族定义了4个net_protocol结构实例，icmp_protocol,udp_protocol
// tcp_protocol和igmp_protocol
// 调用inet_add_protocol()将它们注册到net_protocol结构指针数组inet_protos[MAX_INET_PROTOS]ZHONG
struct net_protocol {
	// 传输层协议数据报接收处理函数指针，当网络层接收IP数据报之后，根据IP数据报所指示传输层协议
	// 调用对应传输层net_protocol结构的该例程接收报文
	// TCP对应tcp_v4_rcv(),UDP对应为udp_rcv(),IGMP对应为igmp_rcv(),ICMP对应为icmp_rcv()
	int			(*handler)(struct sk_buff *skb);
	// 在ICMP模块中接收到差错报文后，会解析差错报文，并根据差错报文中原始的IP首部，
	// 调用对应传输层的异常处理函数err_handler
	void			(*err_handler)(struct sk_buff *skb, u32 info);
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff	       *(*gso_segment)(struct sk_buff *skb,
					       int features);
	// 标识在路由时是否进行策略路由，TCP和UDP默认不进行策略路由
	int			no_policy;
};

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
struct inet6_protocol 
{
	int	(*handler)(struct sk_buff **skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       int type, int code, int offset,
			       __be32 info);

	int	(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff *(*gso_segment)(struct sk_buff *skb,
				       int features);

	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x4
#endif

/* This is used to register socket interfaces for IP protocols.  */
// 此结构只在套接口层起作用
struct inet_protosw {
	// 用于初始化时在散列表中将type值相同的inet_protosw结构实例连接成链表
	struct list_head list;

        /* These two fields form the lookup key.  */
	// Internet协议族共有三种类型SOCK_STREAM, SOCK_DGRAM, SOCK_RAW
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). */
	// 标识协议族中四层协议号，Internet协议族中的值包括IPPROTO_TCP,IPPROTO_UDP
	unsigned short	 protocol; /* This is the L4 protocol number.  */

	// 套接口网络层接口，TCP为tcp_prot,UDP为udp_prot,原始套接口为raw_prot
	struct proto	 *prot;
	// 套接口传输层接口，TCP为inet_stream_ops,UDP为inet_dgram_ops,原始套接口为inet_sockraw_ops
	const struct proto_ops *ops;
  
	// 当大于0时，需要检查当前创建套接口的进程是否有这种能力，TCP和UDP均为-1，标示无需进行能力检查
	// 只有原始套接口为CAP_NET_RAW
	int              capability; /* Which (if any) capability do
				      * we need to use this socket
				      * interface?
                                      */
	// TCP的no_check为0，表示要执行校验和
	char             no_check;   /* checksum on rcv/xmit/none? */
	// 辅助标志，用于初始化传输控制块的is_icsk成员
	// INET_PROTOSW_REUSE标识端口是否能被重用
	// INET_PROTOSW_PERMANENT标识此协议不能被替换或卸载
	// INET_PROTOSW_ICSK标识是不是连接型的套接口
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable? */
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. */
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? */

extern struct net_protocol *inet_protocol_base;
extern struct net_protocol *inet_protos[MAX_INET_PROTOS];

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern struct inet6_protocol *inet6_protos[MAX_INET_PROTOS];
#endif

extern int	inet_add_protocol(struct net_protocol *prot, unsigned char num);
extern int	inet_del_protocol(struct net_protocol *prot, unsigned char num);
extern void	inet_register_protosw(struct inet_protosw *p);
extern void	inet_unregister_protosw(struct inet_protosw *p);

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern int	inet6_add_protocol(struct inet6_protocol *prot, unsigned char num);
extern int	inet6_del_protocol(struct inet6_protocol *prot, unsigned char num);
extern void	inet6_register_protosw(struct inet_protosw *p);
extern void	inet6_unregister_protosw(struct inet_protosw *p);
#endif

#endif	/* _PROTOCOL_H */
