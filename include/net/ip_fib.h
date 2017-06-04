/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	u8			fc_dst_len;
	u8			fc_tos;
	u8			fc_protocol;
	u8			fc_scope;
	u8			fc_type;
	/* 3 bytes unused */
	u32			fc_table;
	__be32			fc_dst;
	__be32			fc_gw;
	int			fc_oif;
	u32			fc_flags;
	u32			fc_priority;
	__be32			fc_prefsrc;
	struct nlattr		*fc_mx;
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	u32			fc_flow;
	u32			fc_mp_alg;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
 };

struct fib_info;

// fib_nh结构存放着下一跳路由的地址(nh_gw)。通常情况下一个路由会有一个该结构
// 然而当支持多路由路径时，一个路由(fib_alias)可能有多个fib_nh结构，说明这个路由
// 有多个下一跳地址，下一跳的选择也有多种算法，这些算法都是基于nh_weigh、nh_power
// 成员的
struct fib_nh {
	// 该路由表项输出网络设备
	struct net_device	*nh_dev;
	// 用于将nh_hash链入散列表
	struct hlist_node	nh_hash;
	// 指向所属的路由表项的fib_info结构
	struct fib_info		*nh_parent;
	// 一些标志
	unsigned		nh_flags;
	// 路由范围
	unsigned char		nh_scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	// 当内核编译支持多路径路由时，用于实现加权随机轮转算法
	int			nh_weight;
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	// 基于策略路由的分类标签
	__u32			nh_tclassid;
#endif
	// 该路由表项的输出网络设备索引
	int			nh_oif;
	// 路由项的网关地址
	__be32			nh_gw;
};

/*
 * This structure contains data shared by many of routes.
 */
// fib_node结构和fib_alias结构的组合用于标识一条路由表项，同时存储相关信息，而更多的信息
// 比如下一跳网关等重要的路由信息存储在fib_info结构中
struct fib_info {
	// 通过fib_hash将fib_info实例插入到fib_info_hash散列表中，并且所有的fib_info实例
	// 都会插入到fib_inof_hash散列表中
	struct hlist_node	fib_hash;
	// 将fib_info实例插入到fib_info_laddrhash散列表中，在路由表项有一个首选源地址时，才将
	// fib_info结构插入到fib_info_laddrhash散列表中
	struct hlist_node	fib_lhash;
	// fib_treeref是持有该fib_info实例引用的fib_node数据结构的数目
	int			fib_treeref;
	// fib_clntref是由于路由查找成功而被持有的引用计数
	atomic_t		fib_clntref;
	// 标记路由项正在被删除的标志，当该标志被设置为1时，警告该数据结构将被删除而不能再使用
	int			fib_dead;
	// 当前使用的唯一标志是RTNH_F_DEAD，表示下一跳已无效，在支持多路径条件下使用
	unsigned		fib_flags;
	// 设置路由的协议
	// RTPORT_UNSPEC：表示该字段无效
	// RTPORT_REDIRECT:由ICMP重定向设置的路由，当前的IPv4不使用该标志
	// RTPORT_KERNEL:由内核设置的路由
	// RTPORT_BOOT:由诸如ip route和route等用户空间命令设置的路由
	// RTPORT_STATIC:由管理员设置的路由
	int			fib_protocol;
	// 首选源IP地址
	__be32			fib_prefsrc;
	// 路由优先级，值越小则优先级越高，添加路由表项时，当没有明确设定时，它的初始值为默认值0
	u32			fib_priority;
	// 与路由相关的一组度量值，当配置路由时，可以通过ip route命令设定，默认值为0
	u32			fib_metrics[RTAX_MAX];
#define fib_mtu fib_metrics[RTAX_MTU-1]			// 路径MTU
#define fib_window fib_metrics[RTAX_WINDOW-1]	// 最大通知窗口
#define fib_rtt fib_metrics[RTAX_RTT-1]			// 往返时间
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]	// 最大段长度
	// 可用下一跳的数量，通常为1,只有当内核支持多路径时，fib_nhs才可能大于1
	int			fib_nhs;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	// 当内核编译支持多路径路由时，实现加权随机轮转算法
	int			fib_power;
#endif
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	// 当内核编译支持多路径路由时，标识多路径缓存算法
	u32			fib_mp_alg;
#endif
	// 在支持多路径路由时的下一跳散列表
	struct fib_nh		fib_nh[0];
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result {
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	__be32          network;
	__be32          netmask;
#endif
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
#define FIB_RES_NETWORK(res)		((res).network)
#define FIB_RES_NETMASK(res)	        ((res).netmask)
#else /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
#define FIB_RES_NETWORK(res)		(0)
#define FIB_RES_NETMASK(res)	        (0)
#endif /* CONFIG_IP_ROUTE_MULTIPATH_WRANDOM */

// 对每个路由表实例创建一个fib_table结构，这个结构主要由一个路由表标识和管理
// 该路由表的一组函数指针组成
struct fib_table {
	// 用来将各个路由表链接成一个双向链表
	struct hlist_node tb_hlist;
	// 路由表标识，在支持策略路由的情况下，系统最多可以有256个路由表，枚举类型rt_class_t
	// 中定义了保留的路由表ID,如RT_TABLE_MAIN、RT_TABLE_LOCAL，除此之外，从1到RT_TABLE_DEFAULT-1
	// 都是可以由用户定义的
	u32		tb_id;
	// 未使用
	unsigned	tb_stamp;
	// 用于在当前路由表搜索符合条件的路由表项，在FIB_HASH算法中为fn_hash_lookup()，此接口被fib_lookup调用
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	// 用于在当前路由表中插入给定的路由表项，在FIB_HASH算法中为fn_hash_insert()，此接口被inet_rtm_newroute
	// 和ip_rt_ioctl调用，通常在处理ip route add命令和route add 命令时被激活
	// 该接口也被fib_magic()调用
	int		(*tb_insert)(struct fib_table *, struct fib_config *);
	// 用于在当前路由表中删除符合条件的路由表项，描述和insert类似
	int		(*tb_delete)(struct fib_table *, struct fib_config *);
	// dump出路由表的内容，在FIB_HASH算法中为fn_hash_dump()，此接口被inet_rtm_getroute调用
	// 通常在执行ip route get命令时被激活
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	// 删除设置有RTNH_F_DEAD标志的fib_info结构实例，在FIB_HASH算法中为fn_hash_flush()
	int		(*tb_flush)(struct fib_table *table);
	// 选择一条默认路由，在FIB_HASH算法中为fn_hash_select_default()
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);

	// 路由表项的散列表起始地址
	unsigned char	tb_data[0];
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

extern struct fib_table *ip_fib_local_table;
extern struct fib_table *ip_fib_main_table;

static inline struct fib_table *fib_get_table(u32 id)
{
	if (id != RT_TABLE_LOCAL)
		return ip_fib_main_table;
	return ip_fib_local_table;
}

static inline struct fib_table *fib_new_table(u32 id)
{
	return fib_get_table(id);
}

static inline int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	if (ip_fib_local_table->tb_lookup(ip_fib_local_table, flp, res) &&
	    ip_fib_main_table->tb_lookup(ip_fib_main_table, flp, res))
		return -ENETUNREACH;
	return 0;
}

static inline void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	if (FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		ip_fib_main_table->tb_select_default(ip_fib_main_table, flp, res);
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
#define ip_fib_local_table fib_get_table(RT_TABLE_LOCAL)
#define ip_fib_main_table fib_get_table(RT_TABLE_MAIN)

extern int fib_lookup(struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(u32 id);
extern struct fib_table *fib_get_table(u32 id);
extern void fib_select_default(const struct flowi *flp, struct fib_result *res);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_getroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst, u32 *itag);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

struct rtentry;

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down(__be32 local, struct net_device *dev, int force);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);

/* Exported by fib_hash.c */
extern struct fib_table *fib_hash_init(u32 id);

#ifdef CONFIG_IP_MULTIPLE_TABLES
extern int fib4_rules_dump(struct sk_buff *skb, struct netlink_callback *cb);

extern void __init fib4_rules_init(void);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

#endif

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int  fib_proc_init(void);
extern void fib_proc_exit(void);
#endif

#endif  /* _NET_FIB_H */
