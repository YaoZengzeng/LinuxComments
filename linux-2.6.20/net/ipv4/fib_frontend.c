/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: FIB frontend.
 *
 * Version:	$Id: fib_frontend.c,v 1.26 2001/10/31 21:55:54 davem Exp $
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/init.h>
#include <linux/list.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/icmp.h>
#include <net/arp.h>
#include <net/ip_fib.h>

#define FFprint(a...) printk(KERN_DEBUG a)

#ifndef CONFIG_IP_MULTIPLE_TABLES

struct fib_table *ip_fib_local_table;
struct fib_table *ip_fib_main_table;

#define FIB_TABLE_HASHSZ 1
static struct hlist_head fib_table_hash[FIB_TABLE_HASHSZ];

#else

#define FIB_TABLE_HASHSZ 256
static struct hlist_head fib_table_hash[FIB_TABLE_HASHSZ];

// fib_new_table()用于获取指定的路由表
// fib_new_table()有两个版本，在不支持策略路由的情况下，由于在初始化时已经创建了
// ip_fib_main_table和ip_fib_local_table路由表，因此直接获取指定id的路由表即可
struct fib_table *fib_new_table(u32 id)
{
	struct fib_table *tb;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	// 在支持策略路由时，路由表最多可达255个，随时都有可能创建新的路由表，因此通过fib_get_table()
	// 在fib_get_table()在fib_table_hash散列表中查找指定的路由表
	tb = fib_get_table(id);
	if (tb)
		return tb;
	// 如果不存在，则通过fib_hash_init()创建并初始化新的路由表
	tb = fib_hash_init(id);
	if (!tb)
		return NULL;
	h = id & (FIB_TABLE_HASHSZ - 1);
	// 然后添加到fib_table_hash散列表中并返回
	hlist_add_head_rcu(&tb->tb_hlist, &fib_table_hash[h]);
	return tb;
}

struct fib_table *fib_get_table(u32 id)
{
	struct fib_table *tb;
	struct hlist_node *node;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);
	rcu_read_lock();
	hlist_for_each_entry_rcu(tb, node, &fib_table_hash[h], tb_hlist) {
		if (tb->tb_id == id) {
			rcu_read_unlock();
			return tb;
		}
	}
	rcu_read_unlock();
	return NULL;
}
#endif /* CONFIG_IP_MULTIPLE_TABLES */

static void fib_flush(void)
{
	int flushed = 0;
	struct fib_table *tb;
	struct hlist_node *node;
	unsigned int h;

	for (h = 0; h < FIB_TABLE_HASHSZ; h++) {
		hlist_for_each_entry(tb, node, &fib_table_hash[h], tb_hlist)
			flushed += tb->tb_flush(tb);
	}

	if (flushed)
		rt_cache_flush(-1);
}

/*
 *	Find the first device with a given source address.
 */

struct net_device * ip_dev_find(__be32 addr)
{
	struct flowi fl = { .nl_u = { .ip4_u = { .daddr = addr } } };
	struct fib_result res;
	struct net_device *dev = NULL;

#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif

	if (!ip_fib_local_table ||
	    ip_fib_local_table->tb_lookup(ip_fib_local_table, &fl, &res))
		return NULL;
	if (res.type != RTN_LOCAL)
		goto out;
	dev = FIB_RES_DEV(res);

	if (dev)
		dev_hold(dev);
out:
	fib_res_put(&res);
	return dev;
}

unsigned inet_addr_type(__be32 addr)
{
	struct flowi		fl = { .nl_u = { .ip4_u = { .daddr = addr } } };
	struct fib_result	res;
	unsigned ret = RTN_BROADCAST;

	if (ZERONET(addr) || BADCLASS(addr))
		return RTN_BROADCAST;
	if (MULTICAST(addr))
		return RTN_MULTICAST;

#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif
	
	if (ip_fib_local_table) {
		ret = RTN_UNICAST;
		if (!ip_fib_local_table->tb_lookup(ip_fib_local_table,
						   &fl, &res)) {
			ret = res.type;
			fib_res_put(&res);
		}
	}
	return ret;
}

/* Given (packet source, input interface) and optional (dst, oif, tos):
   - (main) check, that source is valid i.e. not broadcast or our local
     address.
   - figure out what "logical" interface this packet arrived
     and calculate "specific destination" address.
   - check, that packet arrived from expected physical interface.
 */

int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			struct net_device *dev, __be32 *spec_dst, u32 *itag)
{
	struct in_device *in_dev;
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = src,
					.saddr = dst,
					.tos = tos } },
			    .iif = oif };
	struct fib_result res;
	int no_addr, rpf;
	int ret;

	no_addr = rpf = 0;
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev) {
		no_addr = in_dev->ifa_list == NULL;
		rpf = IN_DEV_RPFILTER(in_dev);
	}
	rcu_read_unlock();

	if (in_dev == NULL)
		goto e_inval;

	if (fib_lookup(&fl, &res))
		goto last_resort;
	if (res.type != RTN_UNICAST)
		goto e_inval_res;
	*spec_dst = FIB_RES_PREFSRC(res);
	fib_combine_itag(itag, &res);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (FIB_RES_DEV(res) == dev || res.fi->fib_nhs > 1)
#else
	if (FIB_RES_DEV(res) == dev)
#endif
	{
		ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
		fib_res_put(&res);
		return ret;
	}
	fib_res_put(&res);
	if (no_addr)
		goto last_resort;
	if (rpf)
		goto e_inval;
	fl.oif = dev->ifindex;

	ret = 0;
	if (fib_lookup(&fl, &res) == 0) {
		if (res.type == RTN_UNICAST) {
			*spec_dst = FIB_RES_PREFSRC(res);
			ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
		}
		fib_res_put(&res);
	}
	return ret;

last_resort:
	if (rpf)
		goto e_inval;
	*spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
	*itag = 0;
	return 0;

e_inval_res:
	fib_res_put(&res);
e_inval:
	return -EINVAL;
}

#ifndef CONFIG_IP_NOSIOCRT

static inline __be32 sk_extract_addr(struct sockaddr *addr)
{
	return ((struct sockaddr_in *) addr)->sin_addr.s_addr;
}

static int put_rtax(struct nlattr *mx, int len, int type, u32 value)
{
	struct nlattr *nla;

	nla = (struct nlattr *) ((char *) mx + len);
	nla->nla_type = type;
	nla->nla_len = nla_attr_size(4);
	*(u32 *) nla_data(nla) = value;

	return len + nla_total_size(4);
}

static int rtentry_to_fib_config(int cmd, struct rtentry *rt,
				 struct fib_config *cfg)
{
	__be32 addr;
	int plen;

	memset(cfg, 0, sizeof(*cfg));

	if (rt->rt_dst.sa_family != AF_INET)
		return -EAFNOSUPPORT;

	/*
	 * Check mask for validity:
	 * a) it must be contiguous.
	 * b) destination must have all host bits clear.
	 * c) if application forgot to set correct family (AF_INET),
	 *    reject request unless it is absolutely clear i.e.
	 *    both family and mask are zero.
	 */
	plen = 32;
	addr = sk_extract_addr(&rt->rt_dst);
	if (!(rt->rt_flags & RTF_HOST)) {
		__be32 mask = sk_extract_addr(&rt->rt_genmask);

		if (rt->rt_genmask.sa_family != AF_INET) {
			if (mask || rt->rt_genmask.sa_family)
				return -EAFNOSUPPORT;
		}

		if (bad_mask(mask, addr))
			return -EINVAL;

		plen = inet_mask_len(mask);
	}

	cfg->fc_dst_len = plen;
	cfg->fc_dst = addr;

	if (cmd != SIOCDELRT) {
		cfg->fc_nlflags = NLM_F_CREATE;
		cfg->fc_protocol = RTPROT_BOOT;
	}

	if (rt->rt_metric)
		cfg->fc_priority = rt->rt_metric - 1;

	if (rt->rt_flags & RTF_REJECT) {
		cfg->fc_scope = RT_SCOPE_HOST;
		cfg->fc_type = RTN_UNREACHABLE;
		return 0;
	}

	cfg->fc_scope = RT_SCOPE_NOWHERE;
	cfg->fc_type = RTN_UNICAST;

	if (rt->rt_dev) {
		char *colon;
		struct net_device *dev;
		char devname[IFNAMSIZ];

		if (copy_from_user(devname, rt->rt_dev, IFNAMSIZ-1))
			return -EFAULT;

		devname[IFNAMSIZ-1] = 0;
		colon = strchr(devname, ':');
		if (colon)
			*colon = 0;
		dev = __dev_get_by_name(devname);
		if (!dev)
			return -ENODEV;
		cfg->fc_oif = dev->ifindex;
		if (colon) {
			struct in_ifaddr *ifa;
			struct in_device *in_dev = __in_dev_get_rtnl(dev);
			if (!in_dev)
				return -ENODEV;
			*colon = ':';
			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next)
				if (strcmp(ifa->ifa_label, devname) == 0)
					break;
			if (ifa == NULL)
				return -ENODEV;
			cfg->fc_prefsrc = ifa->ifa_local;
		}
	}

	addr = sk_extract_addr(&rt->rt_gateway);
	if (rt->rt_gateway.sa_family == AF_INET && addr) {
		cfg->fc_gw = addr;
		if (rt->rt_flags & RTF_GATEWAY &&
		    inet_addr_type(addr) == RTN_UNICAST)
			cfg->fc_scope = RT_SCOPE_UNIVERSE;
	}

	if (cmd == SIOCDELRT)
		return 0;

	if (rt->rt_flags & RTF_GATEWAY && !cfg->fc_gw)
		return -EINVAL;

	if (cfg->fc_scope == RT_SCOPE_NOWHERE)
		cfg->fc_scope = RT_SCOPE_LINK;

	if (rt->rt_flags & (RTF_MTU | RTF_WINDOW | RTF_IRTT)) {
		struct nlattr *mx;
		int len = 0;

		mx = kzalloc(3 * nla_total_size(4), GFP_KERNEL);
 		if (mx == NULL)
			return -ENOMEM;

		if (rt->rt_flags & RTF_MTU)
			len = put_rtax(mx, len, RTAX_ADVMSS, rt->rt_mtu - 40);

		if (rt->rt_flags & RTF_WINDOW)
			len = put_rtax(mx, len, RTAX_WINDOW, rt->rt_window);

		if (rt->rt_flags & RTF_IRTT)
			len = put_rtax(mx, len, RTAX_RTT, rt->rt_irtt << 3);

		cfg->fc_mx = mx;
		cfg->fc_mx_len = len;
	}

	return 0;
}

/*
 *	Handle IP routing ioctl calls. These are used to manipulate the routing tables
 */
 
int ip_rt_ioctl(unsigned int cmd, void __user *arg)
{
	struct fib_config cfg;
	struct rtentry rt;
	int err;

	switch (cmd) {
	case SIOCADDRT:		/* Add a route */
	case SIOCDELRT:		/* Delete a route */
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		if (copy_from_user(&rt, arg, sizeof(rt)))
			return -EFAULT;

		rtnl_lock();
		err = rtentry_to_fib_config(cmd, &rt, &cfg);
		if (err == 0) {
			struct fib_table *tb;

			if (cmd == SIOCDELRT) {
				tb = fib_get_table(cfg.fc_table);
				if (tb)
					err = tb->tb_delete(tb, &cfg);
				else
					err = -ESRCH;
			} else {
				tb = fib_new_table(cfg.fc_table);
				if (tb)
					err = tb->tb_insert(tb, &cfg);
				else
					err = -ENOBUFS;
			}

			/* allocated by rtentry_to_fib_config() */
			kfree(cfg.fc_mx);
		}
		rtnl_unlock();
		return err;
	}
	return -EINVAL;
}

#else

int ip_rt_ioctl(unsigned int cmd, void *arg)
{
	return -EINVAL;
}

#endif

struct nla_policy rtm_ipv4_policy[RTA_MAX+1] __read_mostly = {
	[RTA_DST]		= { .type = NLA_U32 },
	[RTA_SRC]		= { .type = NLA_U32 },
	[RTA_IIF]		= { .type = NLA_U32 },
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= { .type = NLA_U32 },
	[RTA_PRIORITY]		= { .type = NLA_U32 },
	[RTA_PREFSRC]		= { .type = NLA_U32 },
	[RTA_METRICS]		= { .type = NLA_NESTED },
	[RTA_MULTIPATH]		= { .len = sizeof(struct rtnexthop) },
	[RTA_PROTOINFO]		= { .type = NLA_U32 },
	[RTA_FLOW]		= { .type = NLA_U32 },
	[RTA_MP_ALGO]		= { .type = NLA_U32 },
};

static int rtm_to_fib_config(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct fib_config *cfg)
{
	struct nlattr *attr;
	int err, remaining;
	struct rtmsg *rtm;

	err = nlmsg_validate(nlh, sizeof(*rtm), RTA_MAX, rtm_ipv4_policy);
	if (err < 0)
		goto errout;

	memset(cfg, 0, sizeof(*cfg));

	rtm = nlmsg_data(nlh);
	cfg->fc_dst_len = rtm->rtm_dst_len;
	cfg->fc_tos = rtm->rtm_tos;
	cfg->fc_table = rtm->rtm_table;
	cfg->fc_protocol = rtm->rtm_protocol;
	cfg->fc_scope = rtm->rtm_scope;
	cfg->fc_type = rtm->rtm_type;
	cfg->fc_flags = rtm->rtm_flags;
	cfg->fc_nlflags = nlh->nlmsg_flags;

	cfg->fc_nlinfo.pid = NETLINK_CB(skb).pid;
	cfg->fc_nlinfo.nlh = nlh;

	nlmsg_for_each_attr(attr, nlh, sizeof(struct rtmsg), remaining) {
		switch (attr->nla_type) {
		case RTA_DST:
			cfg->fc_dst = nla_get_be32(attr);
			break;
		case RTA_OIF:
			cfg->fc_oif = nla_get_u32(attr);
			break;
		case RTA_GATEWAY:
			cfg->fc_gw = nla_get_be32(attr);
			break;
		case RTA_PRIORITY:
			cfg->fc_priority = nla_get_u32(attr);
			break;
		case RTA_PREFSRC:
			cfg->fc_prefsrc = nla_get_be32(attr);
			break;
		case RTA_METRICS:
			cfg->fc_mx = nla_data(attr);
			cfg->fc_mx_len = nla_len(attr);
			break;
		case RTA_MULTIPATH:
			cfg->fc_mp = nla_data(attr);
			cfg->fc_mp_len = nla_len(attr);
			break;
		case RTA_FLOW:
			cfg->fc_flow = nla_get_u32(attr);
			break;
		case RTA_MP_ALGO:
			cfg->fc_mp_alg = nla_get_u32(attr);
			break;
		case RTA_TABLE:
			cfg->fc_table = nla_get_u32(attr);
			break;
		}
	}

	return 0;
errout:
	return err;
}

int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct fib_config cfg;
	struct fib_table *tb;
	int err;

	err = rtm_to_fib_config(skb, nlh, &cfg);
	if (err < 0)
		goto errout;

	tb = fib_get_table(cfg.fc_table);
	if (tb == NULL) {
		err = -ESRCH;
		goto errout;
	}

	err = tb->tb_delete(tb, &cfg);
errout:
	return err;
}

// 当通过netlink，操作类型为RTM_NEWROUTE对路由进行配置时，inet_rtm_newroute()被调用
int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct fib_config cfg;
	struct fib_table *tb;
	int err;

	// 从netlink消息格式的参数中获取用于配置的路由表项信息到fib_config结构实例
	err = rtm_to_fib_config(skb, nlh, &cfg);
	if (err < 0)
		goto errout;

	// 根据给定的路由表ID获取路由表，不支持策略路由时返回的是local和main两个
	// 路由表中的一个，而支持策略路由时查找散列表fib_table_hash获取
	tb = fib_new_table(cfg.fc_table);
	if (tb == NULL) {
		err = -ENOBUFS;
		goto errout;
	}

	// 获取路由表后，通过路由表中的tb_insert接口创建路由表并添加到路由表中
	err = tb->tb_insert(tb, &cfg);
errout:
	return err;
}

int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	unsigned int h, s_h;
	unsigned int e = 0, s_e;
	struct fib_table *tb;
	struct hlist_node *node;
	int dumped = 0;

	if (nlmsg_len(cb->nlh) >= sizeof(struct rtmsg) &&
	    ((struct rtmsg *) nlmsg_data(cb->nlh))->rtm_flags & RTM_F_CLONED)
		return ip_rt_dump(skb, cb);

	s_h = cb->args[0];
	s_e = cb->args[1];

	for (h = s_h; h < FIB_TABLE_HASHSZ; h++, s_e = 0) {
		e = 0;
		hlist_for_each_entry(tb, node, &fib_table_hash[h], tb_hlist) {
			if (e < s_e)
				goto next;
			if (dumped)
				memset(&cb->args[2], 0, sizeof(cb->args) -
				                 2 * sizeof(cb->args[0]));
			if (tb->tb_dump(tb, skb, cb) < 0)
				goto out;
			dumped = 1;
next:
			e++;
		}
	}
out:
	cb->args[1] = e;
	cb->args[0] = h;

	return skb->len;
}

/* Prepare and feed intra-kernel routing request.
   Really, it should be netlink message, but :-( netlink
   can be not configured, so that we feed it directly
   to fib engine. It is legal, because all events occur
   only when netlink is already locked.
 */
// fib_magic()在本地地址发生了变化之后，用于修改RT_TABLE_MAIN或RT_TABLE_LOCAL路由表
// 在fib_add_ifaddr()和fib_del_ifaddr()被调用
// cmd,添加或删除路由表项的命令，RTM_NEWROUTE 添加路由表项，　RTM_DELROUTE 删除路由表项
// type,　用来确定操作的路由表，当type为RTN_UNICAST操作RT_TABLE_MAIN路由表，其他值则操作RT_TABLE_LOCAL路由表
// dst,　路由表项的目的地址
// dst_len,　路由表项的目的地址的长度
// ifa, 添加路由表项的相关信息，包括首选源地址和输出网络设备索引
static void fib_magic(int cmd, int type, __be32 dst, int dst_len, struct in_ifaddr *ifa)
{
	struct fib_table *tb;
	// 构成用于添加路由表项的信息
	struct fib_config cfg = {
		.fc_protocol = RTPROT_KERNEL,
		.fc_type = type,
		.fc_dst = dst,
		.fc_dst_len = dst_len,
		.fc_prefsrc = ifa->ifa_local,
		.fc_oif = ifa->ifa_dev->dev->ifindex,
		.fc_nlflags = NLM_F_CREATE | NLM_F_APPEND,
	};

	// 根据路由类型确定操作的路由表，当路由类型为一条到单播地址的直连或非直连
	// 则操作RT_TABLE_MAIN路由表，其他类型操作RT_TABLE_LOCAL路由表
	if (type == RTN_UNICAST)
		tb = fib_new_table(RT_TABLE_MAIN);
	else
		tb = fib_new_table(RT_TABLE_LOCAL);

	if (tb == NULL)
		return;

	// 设置操作的路由表ID和路由范围
	cfg.fc_table = tb->tb_id;

	if (type != RTN_LOCAL)
		cfg.fc_scope = RT_SCOPE_LINK;
	else
		cfg.fc_scope = RT_SCOPE_HOST;

	// 根据命令添加或删除路由表项
	if (cmd == RTM_NEWROUTE)
		tb->tb_insert(tb, &cfg);
	else
		tb->tb_delete(tb, &cfg);
}

// 当网络设备上添加了一个新地址之后，便会调用fib_add_ifaddr()函数进行路由表项的操作
// 该设备可能处于禁用状态，因此需要检测，只有启用了设备后，才能配置RT_TABLE_MAIN或
// RT_TABLE_LOCAL路由表
void fib_add_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *prim = ifa;
	__be32 mask = ifa->ifa_mask;
	__be32 addr = ifa->ifa_local;
	__be32 prefix = ifa->ifa_address&mask;

	// 如果添加的是从属地址，则先校验添加的从属IP地址是否存在主IP地址
	if (ifa->ifa_flags&IFA_F_SECONDARY) {
		prim = inet_ifa_byprefix(in_dev, prefix, mask);
		if (prim == NULL) {
			printk(KERN_DEBUG "fib_add_ifaddr: bug: prim == NULL\n");
			return;
		}
	}

	// 在RT_TABLE_LOCAL路由表添加一条输入到本地表项
	fib_magic(RTM_NEWROUTE, RTN_LOCAL, addr, 32, prim);

	// 检测添加IP地址的网络设备是否处于启用状态，如果启用，则还需要添加其他类型的路由
	if (!(dev->flags&IFF_UP))
		return;

	/* Add broadcast address, if it is explicitly assigned. */
	// 如果配置了广播地址并且不为255.255.255.255，则添加广播地址为目的地址路由表项
	if (ifa->ifa_broadcast && ifa->ifa_broadcast != htonl(0xFFFFFFFF))
		fib_magic(RTM_NEWROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);

	// 如果添加的是主IP地址并且网络掩码长度小于32，则根据添加地址的网络设备添加路由表项
	// 添加地址的是回环网络设备，则在RT_TABLE_LOCAL路由表添加表项，否则在RT_TABLE_MAIN
	// 路由表中添加表项
	if (!ZERONET(prefix) && !(ifa->ifa_flags&IFA_F_SECONDARY) &&
	    (prefix != addr || ifa->ifa_prefixlen < 32)) {
		fib_magic(RTM_NEWROUTE, dev->flags&IFF_LOOPBACK ? RTN_LOCAL :
			  RTN_UNICAST, prefix, ifa->ifa_prefixlen, prim);

		/* Add network specific broadcasts, when it takes a sense */
		// 如果网络掩码长度小于31，则在RT_TABLE_LOCAL路由表中添加两条广播类型的表项
		if (ifa->ifa_prefixlen < 31) {
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix, 32, prim);
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix|~mask, 32, prim);
		}
	}
}

// 如果删除的从属IP地址，则需要进行校验，该从属地址必须有处于同一个子网的主地址，否则出错
// 由于广播地址和掩码并不是总随着主IP地址添加而添加，因此需要检测那些广播地址确实已经删除了
// 如果有主IP地址或其他从属IP地址还在使用广播地址和掩码，则不能删除对应的路由表项
static void fib_del_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *ifa1;
	struct in_ifaddr *prim = ifa;
	__be32 brd = ifa->ifa_address|~ifa->ifa_mask;
	__be32 any = ifa->ifa_address&ifa->ifa_mask;
#define LOCAL_OK	1
#define BRD_OK		2
#define BRD0_OK		4
#define BRD1_OK		8
	unsigned ok = 0;

	if (!(ifa->ifa_flags&IFA_F_SECONDARY))
		// 如果删除的是主IP地址，则根据删除地址的网络设备删除路由表项
		// 删除的是回环网络设备，则在RT_TABLE_LOCAL路由表删除表项
		// 否则在RT_TABLE_MAIN路由表中删除路由表项
		fib_magic(RTM_DELROUTE, dev->flags&IFF_LOOPBACK ? RTN_LOCAL :
			  RTN_UNICAST, any, ifa->ifa_prefixlen, prim);
	else {
		// 如果删除的是从属IP地址，则先校验删除的从属IP地址是否存在主IP地址
		prim = inet_ifa_byprefix(in_dev, any, ifa->ifa_mask);
		if (prim == NULL) {
			printk(KERN_DEBUG "fib_del_ifaddr: bug: prim == NULL\n");
			return;
		}
	}

	/* Deletion is more complicated than add.
	   We should take care of not to delete too much :-)

	   Scan address list to be sure that addresses are really gone.
	 */

	// 扫描地址列表，确信该地址已经真正删除了，包括广播地址、本地地址等
	for (ifa1 = in_dev->ifa_list; ifa1; ifa1 = ifa1->ifa_next) {
		if (ifa->ifa_local == ifa1->ifa_local)
			ok |= LOCAL_OK;
		if (ifa->ifa_broadcast == ifa1->ifa_broadcast)
			ok |= BRD_OK;
		if (brd == ifa1->ifa_broadcast)
			ok |= BRD1_OK;
		if (any == ifa1->ifa_broadcast)
			ok |= BRD0_OK;
	}

	// 如果地址列表中已经不存在相同的广播地址，则删除目的地址是一个广播类型的路由表项
	if (!(ok&BRD_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);
	if (!(ok&BRD1_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, brd, 32, prim);
	if (!(ok&BRD0_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, any, 32, prim);
	if (!(ok&LOCAL_OK)) {
		// 如果本地地址确实删除了，则删除RT_TABLE_LOCAL路由表中的表项
		// 并且，删除的地址不是本地接口的地址，则标识该地址的路由表项全部
		// 无效，然后刷新路由表
		fib_magic(RTM_DELROUTE, RTN_LOCAL, ifa->ifa_local, 32, prim);

		/* Check, that this local address finally disappeared. */
		if (inet_addr_type(ifa->ifa_local) != RTN_LOCAL) {
			/* And the last, but not the least thing.
			   We must flush stray FIB entries.

			   First of all, we scan fib_info list searching
			   for stray nexthop entries, then ignite fib_flush.
			*/
			if (fib_sync_down(ifa->ifa_local, NULL, 0))
				fib_flush();
		}
	}
#undef LOCAL_OK
#undef BRD_OK
#undef BRD0_OK
#undef BRD1_OK
}

static void nl_fib_lookup(struct fib_result_nl *frn, struct fib_table *tb )
{
	
	struct fib_result       res;
	struct flowi            fl = { .mark = frn->fl_mark,
				       .nl_u = { .ip4_u = { .daddr = frn->fl_addr,
							    .tos = frn->fl_tos,
							    .scope = frn->fl_scope } } };
	if (tb) {
		local_bh_disable();

		frn->tb_id = tb->tb_id;
		frn->err = tb->tb_lookup(tb, &fl, &res);

		if (!frn->err) {
			frn->prefixlen = res.prefixlen;
			frn->nh_sel = res.nh_sel;
			frn->type = res.type;
			frn->scope = res.scope;
		}
		local_bh_enable();
	}
}

static void nl_fib_input(struct sock *sk, int len)
{
	struct sk_buff *skb = NULL;
        struct nlmsghdr *nlh = NULL;
	struct fib_result_nl *frn;
	u32 pid;     
	struct fib_table *tb;
	
	skb = skb_dequeue(&sk->sk_receive_queue);
	nlh = (struct nlmsghdr *)skb->data;
	if (skb->len < NLMSG_SPACE(0) || skb->len < nlh->nlmsg_len ||
	    nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*frn))) {
		kfree_skb(skb);
		return;
	}
	
	frn = (struct fib_result_nl *) NLMSG_DATA(nlh);
	tb = fib_get_table(frn->tb_id_in);

	nl_fib_lookup(frn, tb);
	
	pid = nlh->nlmsg_pid;           /*pid of sending process */
	NETLINK_CB(skb).pid = 0;         /* from kernel */
	NETLINK_CB(skb).dst_group = 0;  /* unicast */
	netlink_unicast(sk, skb, pid, MSG_DONTWAIT);
}    

static void nl_fib_lookup_init(void)
{
      netlink_kernel_create(NETLINK_FIB_LOOKUP, 0, nl_fib_input, THIS_MODULE);
}

// 清楚网络设备的网络功能信息和相关功能，比如强制删除通过此网络设备所有路由表项
// 所有路由表项并刷新路由缓存，删除该网络设备的ARP表，并停止ARP功能
static void fib_disable_ip(struct net_device *dev, int force)
{
	if (fib_sync_down(0, dev, force))
		fib_flush();
	rt_cache_flush(0);
	arp_ifdown(dev);
}

// 当一个网络设备的IP地址发送变化，路由子系统通过fib_inetaddr_notifier收到通知注册到
// inetaddr_chain通知链，然后调用fib_inetaddr_event()处理添加或删除IP地址的事件
static int fib_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr*)ptr;

	switch (event) {
	// 添加了一个新的本地地址之后，根据该本地地址添加路由表项到RT_TABLE_LOCAL路由表中
	// 然后延时刷新路由缓存
	case NETDEV_UP:
		fib_add_ifaddr(ifa);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(ifa->ifa_dev->dev);
#endif
		rt_cache_flush(-1);
		break;
	// 删除了一个本地地址之后，将该地址从RT_TABLE_LOCAL路由表中删除，如果该设备的IP
	// 地址被全部删除，则立刻刷新路由缓存和该网络设备的ARP表，并停止ARP功能
	case NETDEV_DOWN:
		fib_del_ifaddr(ifa);
		if (ifa->ifa_dev->ifa_list == NULL) {
			/* Last address was deleted from this interface.
			   Disable IP.
			 */
			fib_disable_ip(ifa->ifa_dev->dev, 1);
		} else {
			rt_cache_flush(-1);
		}
		break;
	}
	return NOTIFY_DONE;
}

// 当网络设备的状态发生变化，路由子系统通过fib_netdev_notifier收到通知注册到
// netdev_chain通知链，然后调用fib_netdev_event()来处理相关事件
static int fib_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct in_device *in_dev = __in_dev_get_rtnl(dev);

	// 如果网络设备注销，则清除该网络设备的网络功能信息和相关功能
	if (event == NETDEV_UNREGISTER) {
		fib_disable_ip(dev, 2);
		return NOTIFY_DONE;
	}

	// 如果网络设备的IP配置块无效，则不做处理
	if (!in_dev)
		return NOTIFY_DONE;

	switch (event) {
	// 当激活网络设备时，则根据配置在该网络设备上的本地地址添加
	// 路由表项到RT_TABLE_LOCAL路由表中，然后延时刷新路由缓存
	case NETDEV_UP:
		for_ifa(in_dev) {
			fib_add_ifaddr(ifa);
		} endfor_ifa(in_dev);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(dev);
#endif
		rt_cache_flush(-1);
		break;
	// 当关闭网络设备时，则清楚该网络设备的网络功能信息和相关功能
	case NETDEV_DOWN:
		fib_disable_ip(dev, 0);
		break;
	// 当网络设备修改了MTU或状态配置发生变化，则立刻刷新路由缓存
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGE:
		rt_cache_flush(0);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block fib_inetaddr_notifier = {
	.notifier_call =fib_inetaddr_event,
};

static struct notifier_block fib_netdev_notifier = {
	.notifier_call =fib_netdev_event,
};

void __init ip_fib_init(void)
{
	unsigned int i;

	for (i = 0; i < FIB_TABLE_HASHSZ; i++)
		INIT_HLIST_HEAD(&fib_table_hash[i]);
#ifndef CONFIG_IP_MULTIPLE_TABLES
	ip_fib_local_table = fib_hash_init(RT_TABLE_LOCAL);
	hlist_add_head_rcu(&ip_fib_local_table->tb_hlist, &fib_table_hash[0]);
	ip_fib_main_table  = fib_hash_init(RT_TABLE_MAIN);
	hlist_add_head_rcu(&ip_fib_main_table->tb_hlist, &fib_table_hash[0]);
#else
	fib4_rules_init();
#endif

	register_netdevice_notifier(&fib_netdev_notifier);
	register_inetaddr_notifier(&fib_inetaddr_notifier);
	nl_fib_lookup_init();
}

EXPORT_SYMBOL(inet_addr_type);
EXPORT_SYMBOL(ip_dev_find);
