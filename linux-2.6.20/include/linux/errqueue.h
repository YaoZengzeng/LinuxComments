#ifndef _LINUX_ERRQUEUE_H
#define _LINUX_ERRQUEUE_H 1

struct sock_extended_err
{
	// 出错信息的错误码
	__u32	ee_errno;
	// 标识出错信息的来源
	__u8	ee_origin;
	// 在出错信息来自ICMP消息的情况下，标识ICMP差错消息的类型；其他来源均为0
	__u8	ee_type;
	// 在出错信息来自ICMP消息的情况下，标识ICMP差错消息的编码；其他来源均为0
	__u8	ee_code;
	// 目前未使用，填充为0
	__u8	ee_pad;
	// 出错信息的扩展信息，其意义随出错信息的错误码具体而定
	__u32   ee_info;
	// 目前未使用，填充为0
	__u32   ee_data;
};

#define SO_EE_ORIGIN_NONE	0
// 出错信息来自本地
#define SO_EE_ORIGIN_LOCAL	1
// 出错信息来自ICMP消息
#define SO_EE_ORIGIN_ICMP	2
#define SO_EE_ORIGIN_ICMP6	3

#define SO_EE_OFFENDER(ee)	((struct sockaddr*)((ee)+1))

#ifdef __KERNEL__

#include <net/ip.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define SKB_EXT_ERR(skb) ((struct sock_exterr_skb *) ((skb)->cb))

struct sock_exterr_skb
{
	// 与IP控制块兼容，可以存储IP选项信息
	union {
		struct inet_skb_parm	h4;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		struct inet6_skb_parm	h6;
#endif
	} header;
	// 记录出错信息
	struct sock_extended_err	ee;
	u16				addr_offset;
	__be16				port;
};

#endif

#endif
