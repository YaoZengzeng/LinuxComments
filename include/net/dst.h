/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_H
#define _NET_DST_H

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <net/neighbour.h>
#include <asm/processor.h>

/*
 * 0 - no debugging messages
 * 1 - rare events and bugs (default)
 * 2 - trace mode.
 */
#define RT_CACHE_DEBUG		0

#define DST_GC_MIN	(HZ/10)
#define DST_GC_INC	(HZ/2)
#define DST_GC_MAX	(120*HZ)

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

struct sk_buff;

// dst_entry结构被用于存储缓存路由项中独立于协议的信息，三层协议在另外的结构中存储本协议中
// 更多的私有信息（例如，IPv4使用rtable结构）
struct dst_entry
{
	// 用于将分布在同一个散列表桶内的dst_entry实例链接在一起
	struct dst_entry        *next;
	// 引用计数
	atomic_t		__refcnt;	/* client references	*/

	// 该表项已经被使用的次数（即缓存查找返回该表项的次数）
	int			__use;
	struct dst_entry	*child;
	// 输出网络设备（即将报文送达目的地的发送设备）
	struct net_device       *dev;
	// 当fib_lookup()查找失败时，错误码值会被保存在这个字段中，在之后ip_error()中使用
	// 该值来决定如何处理本次路由查找失败，即决定生成哪一类ICMP消息
	short			error;
	// 用于标识本dst_entry实例的可用状态
	// 0 (默认值)　表示所在结构实例有效而且可以被使用
	// 2 表示所在结构实例将被删除因而不能被使用
	// -1 被IPsec和IPv6使用但不被IPv4使用
	short			obsolete;
	// 标志集合
	int			flags;
#define DST_HOST		1		// 表示主机路由，即不是到网络或一个广播/多播地址的路由
// 只用于IPsec
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
#define DST_NOHASH		8
#define DST_BALANCED            0x10
	// 记录该表项最后一次被使用的时间戳，当缓存查找成功时更新该时间戳，垃圾回收程序使用该时间戳
	// 来决定最应该被释放的表项
	unsigned long		lastuse;
	// 表示该表项将过期的时间戳
	unsigned long		expires;

	unsigned short		header_len;	/* more space at head required */
	unsigned short		nfheader_len;	/* more non-fragment space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	// 多种度量值，TCP中被多处使用
	u32			metrics[RTAX_MAX];
	struct dst_entry	*path;

	// rate_last为上一个ICMP重定向消息送出的时间戳
	unsigned long		rate_last;	/* rate limiting for ICMP */
	// rate_tokens是已经向与该dst_entry实例相关的目的地发送ICMP重定向消息的次数，因此
	// (rate_tokens-1)也就是连续被目的地忽略的ICMP重定向消息的数目
	unsigned long		rate_tokens;

	// neighbour是包含下一跳三层地址到二层地址映射的结构
	struct neighbour	*neighbour;
	// hh是缓存的二层首部
	struct hh_cache		*hh;
	struct xfrm_state	*xfrm;

	// 分别处理输入报文和输出报文的函数
	int			(*input)(struct sk_buff*);
	int			(*output)(struct sk_buff*);

#ifdef CONFIG_NET_CLS_ROUTE
	// 基于路由表的classifier的标签
	__u32			tclassid;
#endif

	// 用于处理dst_entry结构的虚函数表结构
	struct  dst_ops	        *ops;
	// 处理互斥
	struct rcu_head		rcu_head;
		
	// 由于dst_entry是内嵌在rtable结构中的，因此通过info可以访问rtable结构的后续
	// 成员，事实上未使用该成员
	char			info[0];
};

// dst_ops结构是使用路由缓存的三层协议与独立于协议的缓存之间的接口，协议相关的结构
// 如rtable等对这个结构进行了封装
// IP层拥有路由缓存，但其他协议通常保持到这些路由缓存元素的引用，所有这些引用都指向
// dst_entry结构，而不是封装该结构的rtable。SKB缓冲区也保持到dst_entry结构的一个
// 引用，而不是到rtable结构的引用，这个引用被用于存储路由查找结果
struct dst_ops
{
	// 对应的地址族
	unsigned short		family;
	// 协议ID
	__be16			protocol;
	// 指定了路由缓存的容量（即散列表桶的数目），用于垃圾回收算法，在ip_rt_init()中被初始化
	unsigned		gc_thresh;

	// 垃圾回收函数，当协议已分配的dst_entry实例数目达到或超过门限值gc_thresh时，由dst_alloc()
	// 激活该函数
	int			(*gc)(void);
	// 使用IPsec时，检测一个过时的dst_entry是否还有用，通常被标记为dead的缓存路由项通常不再被使用
	// 但当使用IPsec时，该结论并不一定成立
	struct dst_entry *	(*check)(struct dst_entry *, __u32 cookie);
	// 在删除一个dst_entry实例前做一些必要的清理工作，该接口被dst_destroy调用，在IPv4中，注册的
	// 函数为ipv4_dst_destroy()，它会递减对IPv4配置块的引用计数，当引用计数为0时会释放该IPv4配置块等
	void			(*destroy)(struct dst_entry *);
	// 当一个设备被关闭或注销时，会调用dst_ifdown()，该接口被激活，在IPv4中注册的函数为ipv4_dst_ifdown()
	//　它用loopback设备的IP配置块来替换rtable中指向设备的IP配置块，这是因为loopback设备总是存在，每个受影响
	// 的缓存路由项都会被替换
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
	// 检测路由缓存项，当TCP传输超时时，会激活此接口，IPv4中注册的函数为ipv4_negative_advice()
	// 减少引用将被删除因而不能被使用缓存项，或者删除将过期的缓存项或由于ICMP_REDIRECT消息而添加的
	// 缓存项
	struct dst_entry *	(*negative_advice)(struct dst_entry *);
	// 处理目的地不可达错误。通常在发送报文时由于检测到目的地址不可达而被调用，比如，在IPv4的邻居子系统中
	// 使用ARP，没有或超时接收请求的应答时，该接口被调用
	void			(*link_failure)(struct sk_buff *);
	// 更新缓存路由项的PMTU，通常是在处理所接收到的ICMP分片需求消息时调用
	void			(*update_pmtu)(struct dst_entry *dst, u32 mtu);
	// 三层路由缓存结构的大小，对IPv4而言是rtable结构的大小
	int			entry_size;

	// 已经分配的dst_entry实例数目
	atomic_t		entries;
	// 分配路由缓存元素的内存池
	struct kmem_cache 		*kmem_cachep;
};

#ifdef __KERNEL__

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32 dst_mtu(const struct dst_entry *dst)
{
	u32 mtu = dst_metric(dst, RTAX_MTU);
	/*
	 * Alexey put it here, so ask him about it :)
	 */
	barrier();
	return mtu;
}

static inline u32
dst_allfrag(const struct dst_entry *dst)
{
	int ret = dst_metric(dst, RTAX_FEATURES) & RTAX_FEATURE_ALLFRAG;
	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return ret;
}

static inline int
dst_metric_locked(struct dst_entry *dst, int metric)
{
	return dst_metric(dst, RTAX_LOCK) & (1<<metric);
}

static inline void dst_hold(struct dst_entry * dst)
{
	atomic_inc(&dst->__refcnt);
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

static inline
void dst_release(struct dst_entry * dst)
{
	if (dst) {
		WARN_ON(atomic_read(&dst->__refcnt) < 1);
		smp_mb__before_atomic_dec();
		atomic_dec(&dst->__refcnt);
	}
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *dst_pop(struct dst_entry *dst)
{
	struct dst_entry *child = dst_clone(dst->child);

	dst_release(dst);
	return child;
}

extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

static inline void dst_free(struct dst_entry * dst)
{
	if (dst->obsolete > 1)
		return;
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		if (!dst)
			return;
	}
	__dst_free(dst);
}

static inline void dst_rcu_free(struct rcu_head *head)
{
	struct dst_entry *dst = container_of(head, struct dst_entry, rcu_head);
	dst_free(dst);
}

static inline void dst_confirm(struct dst_entry *dst)
{
	if (dst)
		neigh_confirm(dst->neighbour);
}

static inline void dst_negative_advice(struct dst_entry **dst_p)
{
	struct dst_entry * dst = *dst_p;
	if (dst && dst->ops->negative_advice)
		*dst_p = dst->ops->negative_advice(dst);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry * dst = skb->dst;
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}

static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}

/* Output packet to network from transport.  */
// 封装了输出数据报目的路由缓存项中的输出接口
static inline int dst_output(struct sk_buff *skb)
{
	return skb->dst->output(skb);
}

/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	int err;

	for (;;) {
		err = skb->dst->input(skb);

		if (likely(err == 0))
			return err;
		/* Oh, Jamal... Seems, I will not forgive you this mess. :-) */
		if (unlikely(err != NET_XMIT_BYPASS))
			return err;
	}
}

static inline struct dst_entry *dst_check(struct dst_entry *dst, u32 cookie)
{
	if (dst->obsolete)
		dst = dst->ops->check(dst, cookie);
	return dst;
}

extern void		dst_init(void);

struct flowi;
#ifndef CONFIG_XFRM
static inline int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags)
{
	return 0;
} 
#else
extern int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags);
#endif
#endif

#endif /* _NET_DST_H */
