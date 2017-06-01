#ifndef _LINUX_INETDEVICE_H
#define _LINUX_INETDEVICE_H

#ifdef __KERNEL__

#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>

// ipv4_devconf结构是网络设备接口的IPv4系统配置，在内核中有一个名为ipv4)devconf的
// 系统全局遍历，该配置对所有接口有效，另外，每个网络设备的IP控制块中也都存在一份配置，
// 但该配置只对所在网络设备有效
struct ipv4_devconf
{
	// 是否接收ICMP重定向报文
	int	accept_redirects;
	// 是否启用ICMP重定向报文输出
	int	send_redirects;
	// 是否接收ICMP重定向报文，但只针对具有路由功能的网关
	int	secure_redirects;
	// 是否启用发送（路由器）或接收（主机）RFC1620共享媒体重定向
	int	shared_media;
	// 是否接收带有SRR选项的数据
	int	accept_source_route;
	// 是否启用通过反向路径回溯进行源地址验证
	int	rp_filter;
	// 是否启用arp代理功能
	int	proxy_arp;
	// 是否接收源地址为0.b.c.d，目的地址不是本机的数据报。用来支持BOOTP转发服务进程
	// 该进程将捕获并转发该包，目前尚未实现
	int	bootp_relay;
	// 是否记录那些非法地址的数据报到内核日志中
	int	log_martians;
	// 在ipv4_devconf中，标识是否启用IP数据报转发功能；而在IP配置块中，标识是否启用
	// 所在网络设备的IP数据报转发功能
	int	forwarding;
	// 在ipv4_devconf中，标识是否进行组播路由；而在IP配置块中，表示当前虚拟接口数目
	int	mc_forwarding;
	// 留给用户根据需要设置
	int	tag;
	// 允许从其他网络设备输出ARP应答
	int     arp_filter;
	// 输出ARP请求时，由IP数据报确定源IP地址的规则
	int	arp_announce;
	// 接收ARP请求报文的过滤规则
	int	arp_ignore;
	// 处理非ARP请求而接收到的ARP应答
	int	arp_accept;
	// 用于区分不同的媒介
	int	medium_id;
	// 标识是否启用XFRM，只用于IPsec
	int	no_xfrm;
	// 标识是否启用策略路由
	int	no_policy;
	// 强制当前启用的IGMP版本
	int	force_igmp_version;
	// 标识在删除主地址时，第二IP地址是否能升级为主IP地址
	int	promote_secondaries;
	void	*sysctl;
};

extern struct ipv4_devconf ipv4_devconf;

// 为设备设置第一个IP地址时，在inetdev_init()中分配并初始化in_device结构实例
// 应用层可以通过ip或ifconfig工具来修改这些配置，该结构实例的地址保存在net_device
// 结构成员ip_ptr中
struct in_device
{
	struct net_device	*dev;
	atomic_t		refcnt;
	// dead为1时表示所在的IP配置块将要被释放，不再允许访问其成员
	int			dead;
	// in_ifaddr结构存储了网络设备的IP地址，因为一个网络设备可以配置多个IP地址
	// 因此需要用链表来存储
	struct in_ifaddr	*ifa_list;	/* IP ifaddr chain		*/
	rwlock_t		mc_list_lock;
	struct ip_mc_list	*mc_list;	/* IP multicast filter chain    */
	spinlock_t		mc_tomb_lock;
	struct ip_mc_list	*mc_tomb;
	unsigned long		mr_v1_seen;
	unsigned long		mr_v2_seen;
	unsigned long		mr_maxdelay;
	unsigned char		mr_qrv;
	unsigned char		mr_gq_running;
	unsigned char		mr_ifc_count;
	struct timer_list	mr_gq_timer;	/* general query timer */
	struct timer_list	mr_ifc_timer;	/* interface change timer */

	struct neigh_parms	*arp_parms;
	// 一些针对网络设备接口的IPv4配置
	struct ipv4_devconf	cnf;
	struct rcu_head		rcu_head;
};

#define IN_DEV_FORWARD(in_dev)		((in_dev)->cnf.forwarding)
#define IN_DEV_MFORWARD(in_dev)		(ipv4_devconf.mc_forwarding && (in_dev)->cnf.mc_forwarding)
#define IN_DEV_RPFILTER(in_dev)		(ipv4_devconf.rp_filter && (in_dev)->cnf.rp_filter)
#define IN_DEV_SOURCE_ROUTE(in_dev)	(ipv4_devconf.accept_source_route && (in_dev)->cnf.accept_source_route)
#define IN_DEV_BOOTP_RELAY(in_dev)	(ipv4_devconf.bootp_relay && (in_dev)->cnf.bootp_relay)

#define IN_DEV_LOG_MARTIANS(in_dev)	(ipv4_devconf.log_martians || (in_dev)->cnf.log_martians)
#define IN_DEV_PROXY_ARP(in_dev)	(ipv4_devconf.proxy_arp || (in_dev)->cnf.proxy_arp)
#define IN_DEV_SHARED_MEDIA(in_dev)	(ipv4_devconf.shared_media || (in_dev)->cnf.shared_media)
#define IN_DEV_TX_REDIRECTS(in_dev)	(ipv4_devconf.send_redirects || (in_dev)->cnf.send_redirects)
#define IN_DEV_SEC_REDIRECTS(in_dev)	(ipv4_devconf.secure_redirects || (in_dev)->cnf.secure_redirects)
#define IN_DEV_IDTAG(in_dev)		((in_dev)->cnf.tag)
#define IN_DEV_MEDIUM_ID(in_dev)	((in_dev)->cnf.medium_id)
#define IN_DEV_PROMOTE_SECONDARIES(in_dev)	(ipv4_devconf.promote_secondaries || (in_dev)->cnf.promote_secondaries)

#define IN_DEV_RX_REDIRECTS(in_dev) \
	((IN_DEV_FORWARD(in_dev) && \
	  (ipv4_devconf.accept_redirects && (in_dev)->cnf.accept_redirects)) \
	 || (!IN_DEV_FORWARD(in_dev) && \
	  (ipv4_devconf.accept_redirects || (in_dev)->cnf.accept_redirects)))

#define IN_DEV_ARPFILTER(in_dev)	(ipv4_devconf.arp_filter || (in_dev)->cnf.arp_filter)
#define IN_DEV_ARP_ANNOUNCE(in_dev)	(max(ipv4_devconf.arp_announce, (in_dev)->cnf.arp_announce))
#define IN_DEV_ARP_IGNORE(in_dev)	(max(ipv4_devconf.arp_ignore, (in_dev)->cnf.arp_ignore))

// IP地址块，用于存储主机的IP地址、子网掩码、广播地址，这些配置属于主机
// 但是又配置到网络设备上，因此与网络设备也相关。一个网络设备配置多少个
// IP地址，就有多少个IP地址块
struct in_ifaddr
{
	struct in_ifaddr	*ifa_next;
	struct in_device	*ifa_dev;
	struct rcu_head		rcu_head;
	// 在支持广播的设备上，ifa_local和ifa_address都是本地的IP地址
	// 但是在点对点设备，ifa_address是对端的IP地址，ifa_local存储
	// 的是本地的IP地址
	__be32			ifa_local;
	__be32			ifa_address;
	__be32			ifa_mask;
	__be32			ifa_broadcast;
	__be32			ifa_anycast;
	// 寻址范围，RT_SCOPE_UNIVERSE等等
	unsigned char		ifa_scope;
	// IP地址属性
	unsigned char		ifa_flags;
	// 子网掩码长度
	unsigned char		ifa_prefixlen;
	// 地址标签，通常是网络设备名或者网络设备别名
	char			ifa_label[IFNAMSIZ];
};

extern int register_inetaddr_notifier(struct notifier_block *nb);
extern int unregister_inetaddr_notifier(struct notifier_block *nb);

extern struct net_device 	*ip_dev_find(__be32 addr);
extern int		inet_addr_onlink(struct in_device *in_dev, __be32 a, __be32 b);
extern int		devinet_ioctl(unsigned int cmd, void __user *);
extern void		devinet_init(void);
extern struct in_device *inetdev_init(struct net_device *dev);
extern struct in_device	*inetdev_by_index(int);
extern __be32		inet_select_addr(const struct net_device *dev, __be32 dst, int scope);
extern __be32		inet_confirm_addr(const struct net_device *dev, __be32 dst, __be32 local, int scope);
extern struct in_ifaddr *inet_ifa_byprefix(struct in_device *in_dev, __be32 prefix, __be32 mask);
extern void		inet_forward_change(void);

static __inline__ int inet_ifa_match(__be32 addr, struct in_ifaddr *ifa)
{
	return !((addr^ifa->ifa_address)&ifa->ifa_mask);
}

/*
 *	Check if a mask is acceptable.
 */
 
static __inline__ int bad_mask(__be32 mask, __be32 addr)
{
	__u32 hmask;
	if (addr & (mask = ~mask))
		return 1;
	hmask = ntohl(mask);
	if (hmask & (hmask+1))
		return 1;
	return 0;
}

#define for_primary_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa && !(ifa->ifa_flags&IFA_F_SECONDARY); ifa = ifa->ifa_next)

#define for_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa; ifa = ifa->ifa_next)


#define endfor_ifa(in_dev) }

static inline struct in_device *__in_dev_get_rcu(const struct net_device *dev)
{
	struct in_device *in_dev = dev->ip_ptr;
	if (in_dev)
		in_dev = rcu_dereference(in_dev);
	return in_dev;
}

static __inline__ struct in_device *
in_dev_get(const struct net_device *dev)
{
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev)
		atomic_inc(&in_dev->refcnt);
	rcu_read_unlock();
	return in_dev;
}

static __inline__ struct in_device *
__in_dev_get_rtnl(const struct net_device *dev)
{
	return (struct in_device*)dev->ip_ptr;
}

extern void in_dev_finish_destroy(struct in_device *idev);

static inline void in_dev_put(struct in_device *idev)
{
	if (atomic_dec_and_test(&idev->refcnt))
		in_dev_finish_destroy(idev);
}

#define __in_dev_put(idev)  atomic_dec(&(idev)->refcnt)
#define in_dev_hold(idev)   atomic_inc(&(idev)->refcnt)

#endif /* __KERNEL__ */

static __inline__ __be32 inet_make_mask(int logmask)
{
	if (logmask)
		return htonl(~((1<<(32-logmask))-1));
	return 0;
}

static __inline__ int inet_mask_len(__be32 mask)
{
	__u32 hmask = ntohl(mask);
	if (!hmask)
		return 0;
	return 32 - ffz(~hmask);
}


#endif /* _LINUX_INETDEVICE_H */
