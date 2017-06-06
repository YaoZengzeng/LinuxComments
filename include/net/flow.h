/*
 *
 *	Generic internet FLOW.
 *
 */

#ifndef _NET_FLOW_H
#define _NET_FLOW_H

#include <linux/in6.h>
#include <asm/atomic.h>

// 利用flowi数据结构，就可以根据诸如输入网络设备和输出网络设备、三层和四层协议报头中的
// 参数等字段的组合对流量进行分类，它通常被用作路由查找的搜索条件组合，IPSec策略的流量
// 选择器以及其他高级用途
struct flowi {
	// 输出网络设备索引和输入网络设备索引
	int	oif;
	int	iif;
	__u32	mark;

	// 该联合对应第三层，目前支持的协议为IPv4、IPv6和DECnet
	union {
		struct {
			__be32			daddr;
			__be32			saddr;
			__u8			tos;
			__u8			scope;
		} ip4_u;
		
		struct {
			struct in6_addr		daddr;
			struct in6_addr		saddr;
			__be32			flowlabel;
		} ip6_u;

		struct {
			__le16			daddr;
			__le16			saddr;
			__u8			scope;
		} dn_u;
	} nl_u;
#define fld_dst		nl_u.dn_u.daddr
#define fld_src		nl_u.dn_u.saddr
#define fld_scope	nl_u.dn_u.scope
#define fl6_dst		nl_u.ip6_u.daddr
#define fl6_src		nl_u.ip6_u.saddr
#define fl6_flowlabel	nl_u.ip6_u.flowlabel
#define fl4_dst		nl_u.ip4_u.daddr
#define fl4_src		nl_u.ip4_u.saddr
#define fl4_tos		nl_u.ip4_u.tos
#define fl4_scope	nl_u.ip4_u.scope

	// 标识四层协议
	__u8	proto;
	// 该变量只定义了一个标识，FLOWI_FLAG_MULTIPATHOLDROUTE，它最初用于多路径代码
	// 但现在已废弃不再使用
	__u8	flags;
#define FLOWI_FLAG_MULTIPATHOLDROUTE 0x01
	// 该联合对应四层，目前支持的协议为TCP、UDP、ICMP、DECnet和IPsec
	union {
		struct {
			__be16	sport;
			__be16	dport;
		} ports;

		struct {
			__u8	type;
			__u8	code;
		} icmpt;

		struct {
			__le16	sport;
			__le16	dport;
		} dnports;

		__be32		spi;

#ifdef CONFIG_IPV6_MIP6
		struct {
			__u8	type;
		} mht;
#endif
	} uli_u;
#define fl_ip_sport	uli_u.ports.sport
#define fl_ip_dport	uli_u.ports.dport
#define fl_icmp_type	uli_u.icmpt.type
#define fl_icmp_code	uli_u.icmpt.code
#define fl_ipsec_spi	uli_u.spi
#ifdef CONFIG_IPV6_MIP6
#define fl_mh_type	uli_u.mht.type
#endif
	__u32           secid;	/* used by xfrm; see secid.txt */
} __attribute__((__aligned__(BITS_PER_LONG/8)));

#define FLOW_DIR_IN	0
#define FLOW_DIR_OUT	1
#define FLOW_DIR_FWD	2

struct sock;
typedef int (*flow_resolve_t)(struct flowi *key, u16 family, u8 dir,
			       void **objp, atomic_t **obj_refp);

extern void *flow_cache_lookup(struct flowi *key, u16 family, u8 dir,
	 		       flow_resolve_t resolver);
extern void flow_cache_flush(void);
extern atomic_t flow_cache_genid;

#endif
