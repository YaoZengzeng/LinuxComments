/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		ROUTE - implementation of the IP router.
 *
 * Version:	$Id: route.c,v 1.103 2002/01/12 07:44:09 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Linus Torvalds, <Linus.Torvalds@helsinki.fi>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *		Alan Cox	:	Verify area fixes.
 *		Alan Cox	:	cli() protects routing changes
 *		Rui Oliveira	:	ICMP routing table updates
 *		(rco@di.uminho.pt)	Routing table insertion and update
 *		Linus Torvalds	:	Rewrote bits to be sensible
 *		Alan Cox	:	Added BSD route gw semantics
 *		Alan Cox	:	Super /proc >4K 
 *		Alan Cox	:	MTU in route table
 *		Alan Cox	: 	MSS actually. Also added the window
 *					clamper.
 *		Sam Lantinga	:	Fixed route matching in rt_del()
 *		Alan Cox	:	Routing cache support.
 *		Alan Cox	:	Removed compatibility cruft.
 *		Alan Cox	:	RTF_REJECT support.
 *		Alan Cox	:	TCP irtt support.
 *		Jonathan Naylor	:	Added Metric support.
 *	Miquel van Smoorenburg	:	BSD API fixes.
 *	Miquel van Smoorenburg	:	Metrics.
 *		Alan Cox	:	Use __u32 properly
 *		Alan Cox	:	Aligned routing errors more closely with BSD
 *					our system is still very different.
 *		Alan Cox	:	Faster /proc handling
 *	Alexey Kuznetsov	:	Massive rework to support tree based routing,
 *					routing caches and better behaviour.
 *		
 *		Olaf Erb	:	irtt wasn't being copied right.
 *		Bjorn Ekwall	:	Kerneld route support.
 *		Alan Cox	:	Multicast fixed (I hope)
 * 		Pavel Krauz	:	Limited broadcast fixed
 *		Mike McLagan	:	Routing by source
 *	Alexey Kuznetsov	:	End of old history. Split to fib.c and
 *					route.c and rewritten from scratch.
 *		Andi Kleen	:	Load-limit warning messages.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *	Vitaly E. Lavrov	:	Race condition in ip_route_input_slow.
 *	Tobias Ringstrom	:	Uninitialized res.type in ip_route_output_slow.
 *	Vladimir V. Ivanov	:	IP rule info (flowid) is really useful.
 *		Marc Boucher	:	routing by fwmark
 *	Robert Olsson		:	Added rt_cache statistics
 *	Arnaldo C. Melo		:	Convert proc stuff to seq_file
 *	Eric Dumazet		:	hashed spinlocks and rt_check_expire() fixes.
 * 	Ilia Sotnikov		:	Ignore TOS on PMTUD and Redirect
 * 	Ilia Sotnikov		:	Removed TOS from hash calculations
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
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/times.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/ip_mp_alg.h>
#include <net/netevent.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#define RT_FL_TOS(oldflp) \
    ((u32)(oldflp->fl4_tos & (IPTOS_RT_MASK | RTO_ONLINK)))

#define IP_MAX_MTU	0xFFF0

#define RT_GC_TIMEOUT (300*HZ)

static int ip_rt_min_delay		= 2 * HZ;
static int ip_rt_max_delay		= 10 * HZ;
static int ip_rt_max_size;
static int ip_rt_gc_timeout		= RT_GC_TIMEOUT;
static int ip_rt_gc_interval		= 60 * HZ;
static int ip_rt_gc_min_interval	= HZ / 2;
static int ip_rt_redirect_number	= 9;
static int ip_rt_redirect_load		= HZ / 50;
static int ip_rt_redirect_silence	= ((HZ / 50) << (9 + 1));
static int ip_rt_error_cost		= HZ;
static int ip_rt_error_burst		= 5 * HZ;
static int ip_rt_gc_elasticity		= 8;
static int ip_rt_mtu_expires		= 10 * 60 * HZ;
static int ip_rt_min_pmtu		= 512 + 20 + 20;
static int ip_rt_min_advmss		= 256;
static int ip_rt_secret_interval	= 10 * 60 * HZ;
static unsigned long rt_deadline;

#define RTprint(a...)	printk(KERN_DEBUG a)

static struct timer_list rt_flush_timer;
static struct timer_list rt_periodic_timer;
static struct timer_list rt_secret_timer;

/*
 *	Interface to generic destination cache.
 */

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie);
static void		 ipv4_dst_destroy(struct dst_entry *dst);
static void		 ipv4_dst_ifdown(struct dst_entry *dst,
					 struct net_device *dev, int how);
static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst);
static void		 ipv4_link_failure(struct sk_buff *skb);
static void		 ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu);
static int rt_garbage_collect(void);


static struct dst_ops ipv4_dst_ops = {
	.family =		AF_INET,
	.protocol =		__constant_htons(ETH_P_IP),
	.gc =			rt_garbage_collect,
	.check =		ipv4_dst_check,
	.destroy =		ipv4_dst_destroy,
	.ifdown =		ipv4_dst_ifdown,
	.negative_advice =	ipv4_negative_advice,
	.link_failure =		ipv4_link_failure,
	.update_pmtu =		ip_rt_update_pmtu,
	.entry_size =		sizeof(struct rtable),
};

#define ECN_OR_COST(class)	TC_PRIO_##class

__u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};


/*
 * Route cache.
 */

/* The locking scheme is rather straight forward:
 *
 * 1) Read-Copy Update protects the buckets of the central route hash.
 * 2) Only writers remove entries, and they hold the lock
 *    as they look at rtable reference counts.
 * 3) Only readers acquire references to rtable entries,
 *    they do so with atomic increments and with the
 *    lock held.
 */

struct rt_hash_bucket {
	struct rtable	*chain;
};
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) || \
	defined(CONFIG_PROVE_LOCKING)
/*
 * Instead of using one spinlock for each rt_hash_bucket, we use a table of spinlocks
 * The size of this table is a power of two and depends on the number of CPUS.
 * (on lockdep we have a quite big spinlock_t, so keep the size down there)
 */
#ifdef CONFIG_LOCKDEP
# define RT_HASH_LOCK_SZ	256
#else
# if NR_CPUS >= 32
#  define RT_HASH_LOCK_SZ	4096
# elif NR_CPUS >= 16
#  define RT_HASH_LOCK_SZ	2048
# elif NR_CPUS >= 8
#  define RT_HASH_LOCK_SZ	1024
# elif NR_CPUS >= 4
#  define RT_HASH_LOCK_SZ	512
# else
#  define RT_HASH_LOCK_SZ	256
# endif
#endif

static spinlock_t	*rt_hash_locks;
# define rt_hash_lock_addr(slot) &rt_hash_locks[(slot) & (RT_HASH_LOCK_SZ - 1)]
# define rt_hash_lock_init()	{ \
		int i; \
		rt_hash_locks = kmalloc(sizeof(spinlock_t) * RT_HASH_LOCK_SZ, GFP_KERNEL); \
		if (!rt_hash_locks) panic("IP: failed to allocate rt_hash_locks\n"); \
		for (i = 0; i < RT_HASH_LOCK_SZ; i++) \
			spin_lock_init(&rt_hash_locks[i]); \
		}
#else
# define rt_hash_lock_addr(slot) NULL
# define rt_hash_lock_init()
#endif

static struct rt_hash_bucket 	*rt_hash_table;
static unsigned			rt_hash_mask;
static int			rt_hash_log;
static unsigned int		rt_hash_rnd;

static DEFINE_PER_CPU(struct rt_cache_stat, rt_cache_stat);
#define RT_CACHE_STAT_INC(field) \
	(__raw_get_cpu_var(rt_cache_stat).field++)

static int rt_intern_hash(unsigned hash, struct rtable *rth,
				struct rtable **res);

static unsigned int rt_hash_code(u32 daddr, u32 saddr)
{
	return (jhash_2words(daddr, saddr, rt_hash_rnd)
		& rt_hash_mask);
}

#define rt_hash(daddr, saddr, idx) \
	rt_hash_code((__force u32)(__be32)(daddr),\
		     (__force u32)(__be32)(saddr) ^ ((idx) << 5))

#ifdef CONFIG_PROC_FS
struct rt_cache_iter_state {
	int bucket;
};

static struct rtable *rt_cache_get_first(struct seq_file *seq)
{
	struct rtable *r = NULL;
	struct rt_cache_iter_state *st = seq->private;

	for (st->bucket = rt_hash_mask; st->bucket >= 0; --st->bucket) {
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
		if (r)
			break;
		rcu_read_unlock_bh();
	}
	return r;
}

static struct rtable *rt_cache_get_next(struct seq_file *seq, struct rtable *r)
{
	struct rt_cache_iter_state *st = rcu_dereference(seq->private);

	r = r->u.rt_next;
	while (!r) {
		rcu_read_unlock_bh();
		if (--st->bucket < 0)
			break;
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
	}
	return r;
}

static struct rtable *rt_cache_get_idx(struct seq_file *seq, loff_t pos)
{
	struct rtable *r = rt_cache_get_first(seq);

	if (r)
		while (pos && (r = rt_cache_get_next(seq, r)))
			--pos;
	return pos ? NULL : r;
}

static void *rt_cache_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? rt_cache_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *rt_cache_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct rtable *r = NULL;

	if (v == SEQ_START_TOKEN)
		r = rt_cache_get_first(seq);
	else
		r = rt_cache_get_next(seq, v);
	++*pos;
	return r;
}

static void rt_cache_seq_stop(struct seq_file *seq, void *v)
{
	if (v && v != SEQ_START_TOKEN)
		rcu_read_unlock_bh();
}

static int rt_cache_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "Iface\tDestination\tGateway \tFlags\t\tRefCnt\tUse\t"
			   "Metric\tSource\t\tMTU\tWindow\tIRTT\tTOS\tHHRef\t"
			   "HHUptod\tSpecDst");
	else {
		struct rtable *r = v;
		char temp[256];

		sprintf(temp, "%s\t%08lX\t%08lX\t%8X\t%d\t%u\t%d\t"
			      "%08lX\t%d\t%u\t%u\t%02X\t%d\t%1d\t%08X",
			r->u.dst.dev ? r->u.dst.dev->name : "*",
			(unsigned long)r->rt_dst, (unsigned long)r->rt_gateway,
			r->rt_flags, atomic_read(&r->u.dst.__refcnt),
			r->u.dst.__use, 0, (unsigned long)r->rt_src,
			(dst_metric(&r->u.dst, RTAX_ADVMSS) ?
			     (int)dst_metric(&r->u.dst, RTAX_ADVMSS) + 40 : 0),
			dst_metric(&r->u.dst, RTAX_WINDOW),
			(int)((dst_metric(&r->u.dst, RTAX_RTT) >> 3) +
			      dst_metric(&r->u.dst, RTAX_RTTVAR)),
			r->fl.fl4_tos,
			r->u.dst.hh ? atomic_read(&r->u.dst.hh->hh_refcnt) : -1,
			r->u.dst.hh ? (r->u.dst.hh->hh_output ==
				       dev_queue_xmit) : 0,
			r->rt_spec_dst);
		seq_printf(seq, "%-127s\n", temp);
        }
  	return 0;
}

static struct seq_operations rt_cache_seq_ops = {
	.start  = rt_cache_seq_start,
	.next   = rt_cache_seq_next,
	.stop   = rt_cache_seq_stop,
	.show   = rt_cache_seq_show,
};

static int rt_cache_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct rt_cache_iter_state *s = kmalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		goto out;
	rc = seq_open(file, &rt_cache_seq_ops);
	if (rc)
		goto out_kfree;
	seq          = file->private_data;
	seq->private = s;
	memset(s, 0, sizeof(*s));
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

static struct file_operations rt_cache_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cache_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release_private,
};


static void *rt_cpu_seq_start(struct seq_file *seq, loff_t *pos)
{
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return &per_cpu(rt_cache_stat, cpu);
	}
	return NULL;
}

static void *rt_cpu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return &per_cpu(rt_cache_stat, cpu);
	}
	return NULL;
	
}

static void rt_cpu_seq_stop(struct seq_file *seq, void *v)
{

}

static int rt_cpu_seq_show(struct seq_file *seq, void *v)
{
	struct rt_cache_stat *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search\n");
		return 0;
	}
	
	seq_printf(seq,"%08x  %08x %08x %08x %08x %08x %08x %08x "
		   " %08x %08x %08x %08x %08x %08x %08x %08x %08x \n",
		   atomic_read(&ipv4_dst_ops.entries),
		   st->in_hit,
		   st->in_slow_tot,
		   st->in_slow_mc,
		   st->in_no_route,
		   st->in_brd,
		   st->in_martian_dst,
		   st->in_martian_src,

		   st->out_hit,
		   st->out_slow_tot,
		   st->out_slow_mc, 

		   st->gc_total,
		   st->gc_ignored,
		   st->gc_goal_miss,
		   st->gc_dst_overflow,
		   st->in_hlist_search,
		   st->out_hlist_search
		);
	return 0;
}

static struct seq_operations rt_cpu_seq_ops = {
	.start  = rt_cpu_seq_start,
	.next   = rt_cpu_seq_next,
	.stop   = rt_cpu_seq_stop,
	.show   = rt_cpu_seq_show,
};


static int rt_cpu_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &rt_cpu_seq_ops);
}

static struct file_operations rt_cpu_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cpu_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#endif /* CONFIG_PROC_FS */
  
static __inline__ void rt_free(struct rtable *rt)
{
	multipath_remove(rt);
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static __inline__ void rt_drop(struct rtable *rt)
{
	multipath_remove(rt);
	ip_rt_put(rt);
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static __inline__ int rt_fast_clean(struct rtable *rth)
{
	/* Kill broadcast/multicast entries very aggresively, if they
	   collide in hash table with more useful entries */
	return (rth->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) &&
		rth->fl.iif && rth->u.rt_next;
}

static __inline__ int rt_valuable(struct rtable *rth)
{
	return (rth->rt_flags & (RTCF_REDIRECTED | RTCF_NOTIFY)) ||
		rth->u.dst.expires;
}

// 同步和异步垃圾回收使用同一个函数rt_may_expire()来对给定的dst_entry实例进行判断
// 是否复合删除条件
// 参数tmo1和tmo2是检查路由表项是否符合过期的超时时间，适用于不同的情况：tmo1用于输入
// 广播或组播路由，且其所在散列表桶内还存在其他正常路由的情况；而tmo2用于正常情况下，
// 如果路由表超过超时时间没有使用，并且该路由表项可以删除，则表示过期，显然，这两个值越低
// 表项就越有可能被删除
static int rt_may_expire(struct rtable *rth, unsigned long tmo1, unsigned long tmo2)
{
	unsigned long age;
	int ret = 0;

	if (atomic_read(&rth->u.dst.__refcnt))
		goto out;

	ret = 1;
	if (rth->u.dst.expires &&
	    time_after_eq(jiffies, rth->u.dst.expires))
		goto out;

	age = jiffies - rth->u.dst.lastuse;
	ret = 0;
	if ((age <= tmo1 && !rt_fast_clean(rth)) ||
	    (age <= tmo2 && rt_valuable(rth)))
		goto out;
	ret = 1;
out:	return ret;
}

/* Bits of score are:
 * 31: very valuable
 * 30: not quite useless
 * 29..0: usage counter
 */
static inline u32 rt_score(struct rtable *rt)
{
	u32 score = jiffies - rt->u.dst.lastuse;

	score = ~score & ~(3<<30);

	if (rt_valuable(rt))
		score |= (1<<31);

	if (!rt->fl.iif ||
	    !(rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST|RTCF_LOCAL)))
		score |= (1<<30);

	return score;
}

static inline int compare_keys(struct flowi *fl1, struct flowi *fl2)
{
	return ((__force u32)((fl1->nl_u.ip4_u.daddr ^ fl2->nl_u.ip4_u.daddr) |
		(fl1->nl_u.ip4_u.saddr ^ fl2->nl_u.ip4_u.saddr)) |
		(fl1->mark ^ fl2->mark) |
		(*(u16 *)&fl1->nl_u.ip4_u.tos ^
		 *(u16 *)&fl2->nl_u.ip4_u.tos) |
		(fl1->oif ^ fl2->oif) |
		(fl1->iif ^ fl2->iif)) == 0;
}

#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
static struct rtable **rt_remove_balanced_route(struct rtable **chain_head,
						struct rtable *expentry,
						int *removed_count)
{
	int passedexpired = 0;
	struct rtable **nextstep = NULL;
	struct rtable **rthp = chain_head;
	struct rtable *rth;

	if (removed_count)
		*removed_count = 0;

	while ((rth = *rthp) != NULL) {
		if (rth == expentry)
			passedexpired = 1;

		if (((*rthp)->u.dst.flags & DST_BALANCED) != 0  &&
		    compare_keys(&(*rthp)->fl, &expentry->fl)) {
			if (*rthp == expentry) {
				*rthp = rth->u.rt_next;
				continue;
			} else {
				*rthp = rth->u.rt_next;
				rt_free(rth);
				if (removed_count)
					++(*removed_count);
			}
		} else {
			if (!((*rthp)->u.dst.flags & DST_BALANCED) &&
			    passedexpired && !nextstep)
				nextstep = &rth->u.rt_next;

			rthp = &rth->u.rt_next;
		}
	}

	rt_free(expentry);
	if (removed_count)
		++(*removed_count);

	return nextstep;
}
#endif /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */


/* This runs via a timer and thus is always in BH context. */
// 同步垃圾回收被用于处理内存不够时的特殊情况，事实上这种情况比较少见，同时也非常影响性能
// 通常路由模块中使用rt_periodic_timer定时器来周期性进行垃圾回收工作，该定时器的处理函数
// 为rt_check_expire()
// rt_periodic_timer定时器默认每隔ip_rt_gc_inerval秒到期，但是在ip_rt_init中，设定该
// 定时器第一次激活的时间为ip_rt_gc_inerval和2*ip_rt_gc_inerval之间的一个随机时间，使用
// 随机值的原因是为了避免不能内核模块中的定时器可能在同一时间到期而花费大量的CPU资源
static void rt_check_expire(unsigned long dummy)
{
	// 获取上一次垃圾回收时扫描到的最后一个桶，每当rt_periodic_timer定时器
	// 被激活时，它只从上次激活时扫描到的最后一个桶开始，因此用到了一个static
	// 变量rover来记录每次扫描的最后一个桶
	static unsigned int rover;
	unsigned int i = rover, goal;
	struct rtable *rth, **rthp;
	unsigned long now = jiffies;
	u64 mult;

	// 计算待删除的缓存项数目存储到goal
	mult = ((u64)ip_rt_gc_interval) << rt_hash_log;
	if (ip_rt_gc_timeout > 1)
		do_div(mult, ip_rt_gc_timeout);
	goal = (unsigned int)mult;
	if (goal > rt_hash_mask) goal = rt_hash_mask + 1;
	// 利用rt_may_expire检查它们是否复符合过期条件，如满足则直接删除
	// 符合条件的表项
	for (; goal > 0; goal--) {
		unsigned long tmo = ip_rt_gc_timeout;

		i = (i + 1) & rt_hash_mask;
		rthp = &rt_hash_table[i].chain;

		if (*rthp == 0)
			continue;
		spin_lock(rt_hash_lock_addr(i));
		while ((rth = *rthp) != NULL) {
			if (rth->u.dst.expires) {
				/* Entry is expired even if it is in use */
				if (time_before_eq(now, rth->u.dst.expires)) {
					tmo >>= 1;
					rthp = &rth->u.rt_next;
					continue;
				}
			} else if (!rt_may_expire(rth, tmo, ip_rt_gc_timeout)) {
				tmo >>= 1;
				rthp = &rth->u.rt_next;
				continue;
			}

			/* Cleanup aged off entries. */
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
			/* remove all related balanced entries if necessary */
			if (rth->u.dst.flags & DST_BALANCED) {
				rthp = rt_remove_balanced_route(
					&rt_hash_table[i].chain,
					rth, NULL);
				if (!rthp)
					break;
			} else {
				*rthp = rth->u.rt_next;
				rt_free(rth);
			}
#else /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
 			*rthp = rth->u.rt_next;
 			rt_free(rth);
#endif /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
		}
		spin_unlock(rt_hash_lock_addr(i));

		/* Fallback loop breaker. */
		if (time_after(jiffies, now))
			break;
	}
	// 记录本次垃圾回收时扫描到的最后一个桶
	rover = i;
	// 定时器下次超时时间
	mod_timer(&rt_periodic_timer, jiffies + ip_rt_gc_interval);
}

/* This can run from both BH and non-BH contexts, the latter
 * in the case of a forced flush event.
 */
static void rt_run_flush(unsigned long dummy)
{
	int i;
	struct rtable *rth, *next;

	rt_deadline = 0;

	get_random_bytes(&rt_hash_rnd, 4);

	for (i = rt_hash_mask; i >= 0; i--) {
		spin_lock_bh(rt_hash_lock_addr(i));
		rth = rt_hash_table[i].chain;
		if (rth)
			rt_hash_table[i].chain = NULL;
		spin_unlock_bh(rt_hash_lock_addr(i));

		for (; rth; rth = next) {
			next = rth->u.rt_next;
			rt_free(rth);
		}
	}
}

static DEFINE_SPINLOCK(rt_flush_lock);

// 一旦系统中发生了某种变化，使缓存中的一些信息因此而过期，内核就会刷新路由缓存
// 在许多情况下，尽管只有一些表项过期，但内核为了简化操作会清空所有表项
// rt_cache_flush()依据delay的值对缓存进行刷新
// delay < 0:在ip_rt_min_delay指定的时间后刷新缓存
// delay = 0:立即缓存刷新
// delay > 0:在delay指定的时间后刷新缓存，但最长延时不得超过ip_rt_max_delay
void rt_cache_flush(int delay)
{
	unsigned long now = jiffies;
	int user_mode = !in_softirq();

	// 如果delay小于0，则重新设定delay为ip_rt_min_delay，确保ip_rt_min_delay
	// 指定的时间后被刷新
	if (delay < 0)
		delay = ip_rt_min_delay;

	/* flush existing multipath state*/
	// 如果支持多路径路由，则需要同时刷新多路径路由算法实例的状态
	multipath_flush();

	spin_lock_bh(&rt_flush_lock);

	// 当提交一个新刷新请求并且已经存在一个刷新请求尚未出发的情况下，需要重新为
	// 请求设置定时时间，但需要通过使用全局变量rt_deadline来保证，这个新请求
	// 不能让定时器迟于上次请求之后ip_rx_max_delay秒后才过期
	if (del_timer(&rt_flush_timer) && delay > 0 && rt_deadline) {
		long tmo = (long)(rt_deadline - now);

		/* If flush timer is already running
		   and flush request is not immediate (delay > 0):

		   if deadline is not achieved, prolongate timer to "delay",
		   otherwise fire it at deadline time.
		 */

		if (user_mode && tmo < ip_rt_max_delay-ip_rt_min_delay)
			tmo = 0;
		
		if (delay > tmo)
			delay = tmo;
	}

	// 调整之后的delay还小于或等于0时，则需要立即刷新缓存
	if (delay <= 0) {
		spin_unlock_bh(&rt_flush_lock);
		rt_run_flush(0);
		return;
	}

	// 重新计算rt_deadline，一倍下次刷新请求延时的计算
	if (rt_deadline == 0)
		rt_deadline = now + ip_rt_max_delay;

	// 重新设置刷新定时器
	mod_timer(&rt_flush_timer, now+delay);
	spin_unlock_bh(&rt_flush_lock);
}

static void rt_secret_rebuild(unsigned long dummy)
{
	unsigned long now = jiffies;

	rt_cache_flush(0);
	mod_timer(&rt_secret_timer, now + ip_rt_secret_interval);
}

/*
   Short description of GC goals.

   We want to build algorithm, which will keep routing cache
   at some equilibrium point, when number of aged off entries
   is kept approximately equal to newly generated ones.

   Current expiration strength is variable "expire".
   We try to adjust it dynamically, so that if networking
   is idle expires is large enough to keep enough of warm entries,
   and when load increases it reduces to limit cache size.
 */
// 路由缓存的同步清理函数是rt_garbage_collect()，这个函数只在两处被调用，
// 一是添加新表项到路由缓存的rt_intern_hash()中，绑定邻居项出错 -> 删除暂时不用的缓存项
// 也会删除其中绑定的邻居表项
// 二是分配表项的dst_alloc()中发现表项总数将超过门限值gc_thresh
// 返回0，表示未能完成预期垃圾回收，不能分配路由缓存
// 返回1,　表示当前的路由缓存项的数目小于缓存内的表项数目上限，可以继续分配路由缓存
static int rt_garbage_collect(void)
{
	// expire为用于判断缓存项是否过期的超时条件
	static unsigned long expire = RT_GC_TIMEOUT;
	// last_gc记录每次进行垃圾回收的时间
	static unsigned long last_gc;
	// rover来记录上一次垃圾回收时扫描到的最后一个桶
	static int rover;
	static int equilibrium;
	struct rtable *rth, **rthp;
	unsigned long now = jiffies;
	int goal;

	/*
	 * Garbage collection is pretty expensive,
	 * do not make it too frequently.
	 */

	RT_CACHE_STAT_INC(gc_total);
	// 由于垃圾回收需要消耗大量的CPU时间，因此如果上次垃圾回收的时间与现在的时间间隔
	// 小于ip_rt_gc_min_interval秒，则不做任何事而立即返回，除非缓存项数目已经达到
	// 上限ip_rt_max_size
	if (now - last_gc < ip_rt_gc_min_interval &&
	    atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size) {
		RT_CACHE_STAT_INC(gc_ignored);
		goto out;
	}

	/* Calculate number of entries, which we want to expire now. */
	// 计算待删除的缓存项数目和剩余的数目，分别存储到goal和equilibrium中
	goal = atomic_read(&ipv4_dst_ops.entries) -
		(ip_rt_gc_elasticity << rt_hash_log);
	if (goal <= 0) {
		if (equilibrium < ipv4_dst_ops.gc_thresh)
			equilibrium = ipv4_dst_ops.gc_thresh;
		goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		if (goal > 0) {
			equilibrium += min_t(unsigned int, goal / 2, rt_hash_mask + 1);
			goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		}
	} else {
		/* We are in dangerous area. Try to reduce cache really
		 * aggressively.
		 */
		goal = max_t(unsigned int, goal / 2, rt_hash_mask + 1);
		equilibrium = atomic_read(&ipv4_dst_ops.entries) - goal;
	}

	// 记录此次进行垃圾回收的时间
	if (now - last_gc >= ip_rt_gc_min_interval)
		last_gc = now;

	// 如果不存在待删除的缓存项，则调整expire后返回
	if (goal <= 0) {
		equilibrium += goal;
		goto work_done;
	}

	do {
		int i, k;

		for (i = rt_hash_mask, k = rover; i >= 0; i--) {
			// 遍历散列表中的缓存项，利用rt_may_expire()检查它们是否符合过期条件
			// 如果满足则将符合条件的表项直接删除
			unsigned long tmo = expire;

			k = (k + 1) & rt_hash_mask;
			rthp = &rt_hash_table[k].chain;
			spin_lock_bh(rt_hash_lock_addr(k));
			while ((rth = *rthp) != NULL) {
				if (!rt_may_expire(rth, tmo, expire)) {
					tmo >>= 1;
					rthp = &rth->u.rt_next;
					continue;
				}
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
				/* remove all related balanced entries
				 * if necessary
				 */
				if (rth->u.dst.flags & DST_BALANCED) {
					int r;

					rthp = rt_remove_balanced_route(
						&rt_hash_table[k].chain,
						rth,
						&r);
					goal -= r;
					if (!rthp)
						break;
				} else {
					*rthp = rth->u.rt_next;
					rt_free(rth);
					goal--;
				}
#else /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
				*rthp = rth->u.rt_next;
				rt_free(rth);
				goal--;
#endif /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
			}
			spin_unlock_bh(rt_hash_lock_addr(k));
			if (goal <= 0)
				break;
		}
		rover = k;

		// 在扫描缓存散列表过程中会检测删除的表项数是否已经达到goal个
		// 一旦到达便返回，结束本次垃圾回收
		if (goal <= 0)
			goto work_done;

		/* Goal is not achieved. We stop process if:

		   - if expire reduced to zero. Otherwise, expire is halfed.
		   - if table is not full.
		   - if we are called from interrupt.
		   - jiffies check is just fallback/debug loop breaker.
		     We will not spin here for long time in any case.
		 */

		RT_CACHE_STAT_INC(gc_goal_miss);

		if (expire == 0)
			break;

		// 如果删除路由缓存项的数目未达到goal个，
		// 否则用更为激进的判断标准来重新扫描散列表
		// 即将用于判断表项是否过期的超时条件减半
		// 被删除的表项数依赖于散列表内的表项数目
		// 目的是当散列表中的表项数目越多，表项过期也越快
		expire >>= 1;
#if RT_CACHE_DEBUG >= 2
		printk(KERN_DEBUG "expire>> %u %d %d %d\n", expire,
				atomic_read(&ipv4_dst_ops.entries), goal, i);
#endif

		if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
			goto out;
	} while (!in_softirq() && time_before_eq(jiffies, now));

	// 当缓存内当前的路由缓存项的数目小于缓存内的表项数目上限时，则不需要
	// 调整用于判断表项是否过期的超时条件了
	if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
		goto out;
	if (net_ratelimit())
		printk(KERN_WARNING "dst cache overflow\n");
	RT_CACHE_STAT_INC(gc_dst_overflow);
	return 1;

// 当完成垃圾回收后，需要调整expire
work_done:
	expire += ip_rt_gc_min_interval;
	if (expire > ip_rt_gc_timeout ||
	    atomic_read(&ipv4_dst_ops.entries) < ipv4_dst_ops.gc_thresh)
		expire = ip_rt_gc_timeout;
#if RT_CACHE_DEBUG >= 2
	printk(KERN_DEBUG "expire++ %u %d %d %d\n", expire,
			atomic_read(&ipv4_dst_ops.entries), goal, rover);
#endif
out:	return 0;
}

// 每当为输入报文或输出报文选择路由时，如果缓存查找失败，则会查找路由表并将表项保存到
// 路由缓存内，利用dst_alloc()分配一个新的缓存项，根据路由表查找结果来初始化该表项
// 的一些字段，最终调用rt_intern_hash()将这个新表项插入到缓存表散列桶的链表首部
// 当接收到一个ICMP重定向消息时，也会用到这个函数
static int rt_intern_hash(unsigned hash, struct rtable *rt, struct rtable **rp)
{
	struct rtable	*rth, **rthp;
	unsigned long	now;
	struct rtable *cand, **candp;
	u32 		min_score;
	int		chain_length;
	int attempts = !in_softirq();

restart:
	chain_length = 0;
	min_score = ~(u32)0;
	cand = NULL;
	candp = NULL;
	now = jiffies;

	// 遍历散列表中hash键上的路由缓存
	rthp = &rt_hash_table[hash].chain;

	spin_lock_bh(rt_hash_lock_addr(hash));
	while ((rth = *rthp) != NULL) {
// 查找来确定新路由表项是否已经存在，因为该路由项可能同时已经被另一个CPU添加到缓存内
// 如果查找成功，则不需要添加到缓存中，更新该路由缓存被访问的最后时间，同时将原来的
// 缓存路由表项移动到散列表桶链表的首部
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
		if (!(rth->u.dst.flags & DST_BALANCED) &&
		    compare_keys(&rth->fl, &rt->fl)) {
#else
		if (compare_keys(&rth->fl, &rt->fl)) {
#endif
			/* Put it first */
			*rthp = rth->u.rt_next;
			/*
			 * Since lookup is lockfree, the deletion
			 * must be visible to another weakly ordered CPU before
			 * the insertion at the start of the hash chain.
			 */
			rcu_assign_pointer(rth->u.rt_next,
					   rt_hash_table[hash].chain);
			/*
			 * Since lookup is lockfree, the update writes
			 * must be ordered for consistency on SMP.
			 */
			rcu_assign_pointer(rt_hash_table[hash].chain, rth);

			rth->u.dst.__use++;
			dst_hold(&rth->u.dst);
			rth->u.dst.lastuse = now;
			spin_unlock_bh(rt_hash_lock_addr(hash));

			rt_drop(rt);
			*rp = rth;
			return 0;
		}

		if (!atomic_read(&rth->u.dst.__refcnt)) {
			// rt_intern_hash()对每一个引用计数为0的路由项调用rt_score()来计算其价值
			// 这是一个32位值，由此可以得到最没有价值而最应该被删除的表项
			// 最高位：表示非常有价值，当路由项是由于ICMP重定向而插入的，或是正被用户空间命令监控
			// 再或者设置了过期时间，置该位
			// 次高位：表示价值相对较次，当路由项是本地生成报文的路由项、广播路由、多播路由、到本地
			// 地址的路由时，置该位
			// 其余30位：由最近一次使用到目前的时间间隔决定，间隔越久，价值越低
			u32 score = rt_score(rth);

			if (score <= min_score) {
				cand = rth;
				candp = rthp;
				min_score = score;
			}
		}

		chain_length++;

		rthp = &rth->u.rt_next;
	}

	// rt_intern_hash()在每次添加一个新表项时都试图删除一个表项来控制缓存容量
	if (cand) {
		/* ip_rt_gc_elasticity used to be average length of chain
		 * length, when exceeded gc becomes really aggressive.
		 *
		 * The second limit is less certain. At the moment it allows
		 * only 2 entries per bucket. We will see.
		 */
		// 删除路由项还有一个条件，那就是散列桶链表的长度超过配置参数ip_rt_gc_elasticity
		if (chain_length > ip_rt_gc_elasticity) {
			*candp = cand->u.rt_next;
			rt_free(cand);
		}
	}

	/* Try to bind route to arp only if it is output
	   route or unicast forwarding path.
	 */
	if (rt->rt_type == RTN_UNICAST || rt->fl.iif == 0) {
		// 对于本地生成报文的输出路由和单播转发路由，需要ARP来解析下一跳的二层地址
		// 因此需要绑定到该路由下一跳的ARP缓存项；而转发目的地为广播地址、多播地址
		// 和本地地址则不需要ARP解析，因为可以使用其他方法解析得到这个地址
		int err = arp_bind_neighbour(&rt->u.dst);
		if (err) {
			spin_unlock_bh(rt_hash_lock_addr(hash));

			if (err != -ENOBUFS) {
				rt_drop(rt);
				return err;
			}

			/* Neighbour tables are full and nothing
			   can be released. Try to shrink route cache,
			   it is most likely it holds some neighbour records.
			 */
			if (attempts-- > 0) {
				// 通过arp_bind_neighbour来为路由缓存项创建邻居并与之绑定
				// 当函数由于缺少内存而失败时，rt_intern_hash通过调用降低
				// ip_rt_gc_elasticity和ip_rt_gc_min_interval门限值
				// 调用rt_garbage_collect来强行进行一次垃圾回收操作
				// 这种垃圾回收只做一次，并且只有当rt_intern_hash的调用不是在
				// 软中断上下文中时才进行，否则将耗费大量的CPU时间，一旦完成垃圾
				// 回收，就重新从缓存查找步骤开始插入新的缓存项
				int saved_elasticity = ip_rt_gc_elasticity;
				int saved_int = ip_rt_gc_min_interval;
				ip_rt_gc_elasticity	= 1;
				ip_rt_gc_min_interval	= 0;
				rt_garbage_collect();
				ip_rt_gc_min_interval	= saved_int;
				ip_rt_gc_elasticity	= saved_elasticity;
				goto restart;
			}

			if (net_ratelimit())
				printk(KERN_WARNING "Neighbour table overflow.\n");
			rt_drop(rt);
			return -ENOBUFS;
		}
	}

	// 最后将该缓存项添加到散列表上
	rt->u.rt_next = rt_hash_table[hash].chain;
#if RT_CACHE_DEBUG >= 2
	if (rt->u.rt_next) {
		struct rtable *trt;
		printk(KERN_DEBUG "rt_cache @%02x: %u.%u.%u.%u", hash,
		       NIPQUAD(rt->rt_dst));
		for (trt = rt->u.rt_next; trt; trt = trt->u.rt_next)
			printk(" . %u.%u.%u.%u", NIPQUAD(trt->rt_dst));
		printk("\n");
	}
#endif
	rt_hash_table[hash].chain = rt;
	spin_unlock_bh(rt_hash_lock_addr(hash));
	*rp = rt;
	return 0;
}

void rt_bind_peer(struct rtable *rt, int create)
{
	static DEFINE_SPINLOCK(rt_peer_lock);
	struct inet_peer *peer;

	peer = inet_getpeer(rt->rt_dst, create);

	spin_lock_bh(&rt_peer_lock);
	if (rt->peer == NULL) {
		rt->peer = peer;
		peer = NULL;
	}
	spin_unlock_bh(&rt_peer_lock);
	if (peer)
		inet_putpeer(peer);
}

/*
 * Peer allocation may fail only in serious out-of-memory conditions.  However
 * we still can generate some output.
 * Random ID selection looks a bit dangerous because we have no chances to
 * select ID being unique in a reasonable period of time.
 * But broken packet identifier may be better than no packet at all.
 */
static void ip_select_fb_ident(struct iphdr *iph)
{
	static DEFINE_SPINLOCK(ip_fb_id_lock);
	static u32 ip_fallback_id;
	u32 salt;

	spin_lock_bh(&ip_fb_id_lock);
	salt = secure_ip_id((__force __be32)ip_fallback_id ^ iph->daddr);
	iph->id = htons(salt & 0xFFFF);
	ip_fallback_id = salt;
	spin_unlock_bh(&ip_fb_id_lock);
}

void __ip_select_ident(struct iphdr *iph, struct dst_entry *dst, int more)
{
	struct rtable *rt = (struct rtable *) dst;

	if (rt) {
		if (rt->peer == NULL)
			rt_bind_peer(rt, 1);

		/* If peer is attached to destination, it is never detached,
		   so that we need not to grab a lock to dereference it.
		 */
		if (rt->peer) {
			iph->id = htons(inet_getid(rt->peer, more));
			return;
		}
	} else
		printk(KERN_DEBUG "rt_bind_peer(0) @%p\n", 
		       __builtin_return_address(0));

	ip_select_fb_ident(iph);
}

static void rt_del(unsigned hash, struct rtable *rt)
{
	struct rtable **rthp;

	spin_lock_bh(rt_hash_lock_addr(hash));
	ip_rt_put(rt);
	for (rthp = &rt_hash_table[hash].chain; *rthp;
	     rthp = &(*rthp)->u.rt_next)
		if (*rthp == rt) {
			*rthp = rt->u.rt_next;
			rt_free(rt);
			break;
		}
	spin_unlock_bh(rt_hash_lock_addr(hash));
}

// ICMP模块中接收到ICMP重定向消息后，调用ip_rt_redirect()来处理输入的ICMP重定向消息
// 校验通过后，会添加一个目的地址为新网关地址的路由缓存项
void ip_rt_redirect(__be32 old_gw, __be32 daddr, __be32 new_gw,
		    __be32 saddr, struct net_device *dev)
{
	int i, k;
	struct in_device *in_dev = in_dev_get(dev);
	struct rtable *rth, **rthp;
	__be32  skeys[2] = { saddr, 0 };
	int  ikeys[2] = { dev->ifindex, 0 };
	struct netevent_redirect netevent;

	// 校验输入ICMP重定向消息报文的网络设备的IP配置块
	if (!in_dev)
		return;
	// 符合以下条件会拒绝接收到的重定向消息
	// ICMP重定向消息中的新网关地址和当前网关地址相同
	// 新网关的IP地址是多播地址、无效地址（零地址）或保留地址
	if (new_gw == old_gw || !IN_DEV_RX_REDIRECTS(in_dev)
	    || MULTICAST(new_gw) || BADCLASS(new_gw) || ZERONET(new_gw))
		goto reject_redirect;

	if (!IN_DEV_SHARED_MEDIA(in_dev)) {
		// 未启用shared_media情况下，新网关地址与当前网关地址不在同一个子网
		if (!inet_addr_onlink(in_dev, new_gw, old_gw))
			goto reject_redirect;
		// 未启用shared_medai和secure_redirects
		if (IN_DEV_SEC_REDIRECTS(in_dev) && ip_fib_check_default(new_gw, dev))
			goto reject_redirect;
	} else {
		// 启用shared_media情况下，根据新网关地址获取到的路由表项不是RTN_UNICAST类型
		// 即不是一条到单播地址的直连或通过一个网关的路由
		if (inet_addr_type(new_gw) != RTN_UNICAST)
			goto reject_redirect;
	}

	// 通过两层循环，匹配条件从严格到宽松，删除现有符合条件的缓存项，添加新的缓存项
	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++) {
			// 根据目的地址、源地址和输出网络设备的索引得到的键值获取散列表的入口
			// 并进行遍历操作
			unsigned hash = rt_hash(daddr, skeys[i], ikeys[k]);

			rthp=&rt_hash_table[hash].chain;

			rcu_read_lock();
			while ((rth = rcu_dereference(*rthp)) != NULL) {
				struct rtable *rt;

				// 查找与目的地址、源地址以及输出网络设备索引完全一致的待删除路由缓存项
				if (rth->fl.fl4_dst != daddr ||
				    rth->fl.fl4_src != skeys[i] ||
				    rth->fl.oif != ikeys[k] ||
				    rth->fl.iif != 0) {
					rthp = &rth->u.rt_next;
					continue;
				}

				if (rth->rt_dst != daddr ||
				    rth->rt_src != saddr ||
				    rth->u.dst.error ||
				    rth->rt_gateway != old_gw ||
				    rth->u.dst.dev != dev)
					break;

				dst_hold(&rth->u.dst);
				rcu_read_unlock();

				// 找到之后，分配新的路由缓存项，并根据新网关地址设置相应的值
				rt = dst_alloc(&ipv4_dst_ops);
				if (rt == NULL) {
					ip_rt_put(rth);
					in_dev_put(in_dev);
					return;
				}

				/* Copy all the information. */
				*rt = *rth;
 				INIT_RCU_HEAD(&rt->u.dst.rcu_head);
				rt->u.dst.__use		= 1;
				atomic_set(&rt->u.dst.__refcnt, 1);
				rt->u.dst.child		= NULL;
				if (rt->u.dst.dev)
					dev_hold(rt->u.dst.dev);
				if (rt->idev)
					in_dev_hold(rt->idev);
				rt->u.dst.obsolete	= 0;
				rt->u.dst.lastuse	= jiffies;
				rt->u.dst.path		= &rt->u.dst;
				rt->u.dst.neighbour	= NULL;
				rt->u.dst.hh		= NULL;
				rt->u.dst.xfrm		= NULL;

				rt->rt_flags		|= RTCF_REDIRECTED;

				/* Gateway is different ... */
				rt->rt_gateway		= new_gw;

				/* Redirect received -> path was valid */
				// 并确认该目的可达
				dst_confirm(&rth->u.dst);

				// 如果系统中还存在新网关的对端信息块，则增加对其的引用
				if (rt->peer)
					atomic_inc(&rt->peer->refcnt);

				// 将创建的路由缓存项与邻居项绑定
				if (arp_bind_neighbour(&rt->u.dst) ||
				    !(rt->u.dst.neighbour->nud_state &
					    NUD_VALID)) {
					if (rt->u.dst.neighbour)
						neigh_event_send(rt->u.dst.neighbour, NULL);
					ip_rt_put(rth);
					rt_drop(rt);
					goto do_next;
				}
				
				netevent.old = &rth->u.dst;
				netevent.new = &rt->u.dst;
				// 通过netevent_notif_chain链表通知NETEVENT_REDIRECT消息，感兴趣的
				// 模块可以通过register_netevent_notifier()注册后，接收该消息
				call_netevent_notifiers(NETEVENT_REDIRECT, 
						        &netevent);

				// 删除老的路由缓存项，并将新的缓存项添加到系统中
				rt_del(hash, rth);
				if (!rt_intern_hash(hash, rt, &rt))
					ip_rt_put(rt);
				// 放宽匹配条件，继续查找并添加新的路由缓存项
				goto do_next;
			}
			rcu_read_unlock();
		do_next:
			;
		}
	}
	in_dev_put(in_dev);
	return;

// 当拒绝接收到的重定向消息时，有条件地打印消息
reject_redirect:
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_INFO "Redirect from %u.%u.%u.%u on %s about "
			"%u.%u.%u.%u ignored.\n"
			"  Advised path = %u.%u.%u.%u -> %u.%u.%u.%u\n",
		       NIPQUAD(old_gw), dev->name, NIPQUAD(new_gw),
		       NIPQUAD(saddr), NIPQUAD(daddr));
#endif
	in_dev_put(in_dev);
}

static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable*)dst;
	struct dst_entry *ret = dst;

	if (rt) {
		if (dst->obsolete) {
			ip_rt_put(rt);
			ret = NULL;
		} else if ((rt->rt_flags & RTCF_REDIRECTED) ||
			   rt->u.dst.expires) {
			unsigned hash = rt_hash(rt->fl.fl4_dst, rt->fl.fl4_src,
						rt->fl.oif);
#if RT_CACHE_DEBUG >= 1
			printk(KERN_DEBUG "ip_rt_advice: redirect to "
					  "%u.%u.%u.%u/%02x dropped\n",
				NIPQUAD(rt->rt_dst), rt->fl.fl4_tos);
#endif
			rt_del(hash, rt);
			ret = NULL;
		}
	}
	return ret;
}

/*
 * Algorithm:
 *	1. The first ip_rt_redirect_number redirects are sent
 *	   with exponential backoff, then we stop sending them at all,
 *	   assuming that the host ignores our redirects.
 *	2. If we did not see packets requiring redirects
 *	   during ip_rt_redirect_silence, we assume that the host
 *	   forgot redirected route and start to send redirects again.
 *
 * This algorithm is much cheaper and more intelligent than dumb load limiting
 * in icmp.c.
 *
 * NOTE. Do not forget to inhibit load limiting for redirects (redundant)
 * and "frag. need" (breaks PMTU discovery) in icmp.c.
 */
// 在为转发的数据报查询路由时，当发现该路由不是最优，则会在该路由表项上加上
// RTCF_DOREDIRECT标志，然后在转发该数据报时会调用ip_rt_send_redirect()
// 向该数据报的发送方发送ICMP重定向消息
void ip_rt_send_redirect(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	struct in_device *in_dev = in_dev_get(rt->u.dst.dev);

	if (!in_dev)
		return;

	// 如果系统禁止发送ICMP重定向消息，则不再继续发送
	if (!IN_DEV_TX_REDIRECTS(in_dev))
		goto out;

	/* No redirected packets during ip_rt_redirect_silence;
	 * reset the algorithm.
	 */
	// 自从上次发送ICMP重定向消息到此次输入数据报触发内核生成ICMP重定向消息的时间
	// 间隔超过了ip_rt_redirect_silence秒，则需要对rate_tokens清零
	if (time_after(jiffies, rt->u.dst.rate_last + ip_rt_redirect_silence))
		rt->u.dst.rate_tokens = 0;

	/* Too many ignored redirects; do not send anything
	 * set u.dst.rate_last to the last seen redirected packet.
	 */
	// 如果由于目的地持续忽略ICMP重定向消息，从而持续(间隔小于ip_rt_redirect_silence秒)
	// 发送ICMP重定向消息数目达到ip_rt_redirect_number，从而取消此次的发送，实现对
	// ICMP重定向消息发送的限速
	if (rt->u.dst.rate_tokens >= ip_rt_redirect_number) {
		rt->u.dst.rate_last = jiffies;
		goto out;
	}

	/* Check for load limit; set rate_last to the latest sent
	 * redirect.
	 */
	// 如果还为发送ICMP重定向消息，或者与上次发送ICMP重定向消息的时间间隔达到
	// 规定时间，则允许继续发送ICMP重定向消息，关于这个规定时间，用了一个简单的
	// 指数回退算法，即每发送一个消息就翻倍时间
	if (rt->u.dst.rate_tokens == 0 ||
	    time_after(jiffies,
		       (rt->u.dst.rate_last +
			(ip_rt_redirect_load << rt->u.dst.rate_tokens)))) {
		icmp_send(skb, ICMP_REDIRECT, ICMP_REDIR_HOST, rt->rt_gateway);
		rt->u.dst.rate_last = jiffies;
		++rt->u.dst.rate_tokens;
	// 有条件地记录ICMP重定向信息
#ifdef CONFIG_IP_ROUTE_VERBOSE
		if (IN_DEV_LOG_MARTIANS(in_dev) &&
		    rt->u.dst.rate_tokens == ip_rt_redirect_number &&
		    net_ratelimit())
			printk(KERN_WARNING "host %u.%u.%u.%u/if%d ignores "
				"redirects for %u.%u.%u.%u to %u.%u.%u.%u.\n",
				NIPQUAD(rt->rt_src), rt->rt_iif,
				NIPQUAD(rt->rt_dst), NIPQUAD(rt->rt_gateway));
#endif
	}
out:
        in_dev_put(in_dev);
}

static int ip_error(struct sk_buff *skb)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	unsigned long now;
	int code;

	switch (rt->u.dst.error) {
		case EINVAL:
		default:
			goto out;
		case EHOSTUNREACH:
			code = ICMP_HOST_UNREACH;
			break;
		case ENETUNREACH:
			code = ICMP_NET_UNREACH;
			break;
		case EACCES:
			code = ICMP_PKT_FILTERED;
			break;
	}

	now = jiffies;
	rt->u.dst.rate_tokens += now - rt->u.dst.rate_last;
	if (rt->u.dst.rate_tokens > ip_rt_error_burst)
		rt->u.dst.rate_tokens = ip_rt_error_burst;
	rt->u.dst.rate_last = now;
	if (rt->u.dst.rate_tokens >= ip_rt_error_cost) {
		rt->u.dst.rate_tokens -= ip_rt_error_cost;
		icmp_send(skb, ICMP_DEST_UNREACH, code, 0);
	}

out:	kfree_skb(skb);
	return 0;
} 

/*
 *	The last two values are not from the RFC but
 *	are needed for AMPRnet AX.25 paths.
 */

static const unsigned short mtu_plateau[] =
{32000, 17914, 8166, 4352, 2002, 1492, 576, 296, 216, 128 };

static __inline__ unsigned short guess_mtu(unsigned short old_mtu)
{
	int i;
	
	for (i = 0; i < ARRAY_SIZE(mtu_plateau); i++)
		if (old_mtu > mtu_plateau[i])
			return mtu_plateau[i];
	return 68;
}

// 当接收到一个ICMP的FRAGMENTATION NEEDED消息时，所有路由相关的PMTU必须被更新为
// ICMP首部中指定的MTU，ICMP模块调用ip_rt_frag_needed()来更新路由缓存项
unsigned short ip_rt_frag_needed(struct iphdr *iph, unsigned short new_mtu)
{
	int i;
	unsigned short old_mtu = ntohs(iph->tot_len);
	struct rtable *rth;
	__be32  skeys[2] = { iph->saddr, 0, };
	__be32  daddr = iph->daddr;
	unsigned short est_mtu = 0;

	// 如果系统未启用pmtu功能，则不作处理返回
	if (ipv4_config.no_pmtu_disc)
		return 0;

	//　在路由缓存中查找指定的目的路由缓存项
	for (i = 0; i < 2; i++) {
		unsigned hash = rt_hash(daddr, skeys[i], 0);

		rcu_read_lock();
		for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		     rth = rcu_dereference(rth->u.rt_next)) {
			// 在对应的路由项缓存，并且存储PMTU的度量值没有上锁，则可以进行更新
			if (rth->fl.fl4_dst == daddr &&
			    rth->fl.fl4_src == skeys[i] &&
			    rth->rt_dst  == daddr &&
			    rth->rt_src  == iph->saddr &&
			    rth->fl.iif == 0 &&
			    !(dst_metric_locked(&rth->u.dst, RTAX_MTU))) {
				unsigned short mtu = new_mtu;

				// 在新PMTU小于68B或新PMTU大于原先保存的PMTU的情况
				// 说明得到的新PMTU有异常，因此需要重新计算
				if (new_mtu < 68 || new_mtu >= old_mtu) {

					/* BSD 4.2 compatibility hack :-( */
					if (mtu == 0 &&
					    old_mtu >= rth->u.dst.metrics[RTAX_MTU-1] &&
					    old_mtu >= 68 + (iph->ihl << 2))
						old_mtu -= iph->ihl << 2;

					mtu = guess_mtu(old_mtu);
				}
				// 如果新PMTU小于当前存储的PMTU，则更新到路由项的度量值中
				if (mtu <= rth->u.dst.metrics[RTAX_MTU-1]) {
					if (mtu < rth->u.dst.metrics[RTAX_MTU-1]) { 
						dst_confirm(&rth->u.dst);
						if (mtu < ip_rt_min_pmtu) {
							mtu = ip_rt_min_pmtu;
							rth->u.dst.metrics[RTAX_LOCK-1] |=
								(1 << RTAX_MTU);
						}
						rth->u.dst.metrics[RTAX_MTU-1] = mtu;
						dst_set_expires(&rth->u.dst,
							ip_rt_mtu_expires);
					}
					est_mtu = mtu;
				}
			}
		}
		rcu_read_unlock();
	}
	return est_mtu ? : new_mtu;
}

static void ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu)
{
	if (dst->metrics[RTAX_MTU-1] > mtu && mtu >= 68 &&
	    !(dst_metric_locked(dst, RTAX_MTU))) {
		if (mtu < ip_rt_min_pmtu) {
			mtu = ip_rt_min_pmtu;
			dst->metrics[RTAX_LOCK-1] |= (1 << RTAX_MTU);
		}
		dst->metrics[RTAX_MTU-1] = mtu;
		dst_set_expires(dst, ip_rt_mtu_expires);
		call_netevent_notifiers(NETEVENT_PMTU_UPDATE, dst);
	}
}

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie)
{
	return NULL;
}

static void ipv4_dst_destroy(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable *) dst;
	struct inet_peer *peer = rt->peer;
	struct in_device *idev = rt->idev;

	if (peer) {
		rt->peer = NULL;
		inet_putpeer(peer);
	}

	if (idev) {
		rt->idev = NULL;
		in_dev_put(idev);
	}
}

static void ipv4_dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			    int how)
{
	struct rtable *rt = (struct rtable *) dst;
	struct in_device *idev = rt->idev;
	if (dev != &loopback_dev && idev && idev->dev == dev) {
		struct in_device *loopback_idev = in_dev_get(&loopback_dev);
		if (loopback_idev) {
			rt->idev = loopback_idev;
			in_dev_put(idev);
		}
	}
}

static void ipv4_link_failure(struct sk_buff *skb)
{
	struct rtable *rt;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

	rt = (struct rtable *) skb->dst;
	if (rt)
		dst_set_expires(&rt->u.dst, 0);
}

static int ip_rt_bug(struct sk_buff *skb)
{
	printk(KERN_DEBUG "ip_rt_bug: %u.%u.%u.%u -> %u.%u.%u.%u, %s\n",
		NIPQUAD(skb->nh.iph->saddr), NIPQUAD(skb->nh.iph->daddr),
		skb->dev ? skb->dev->name : "?");
	kfree_skb(skb);
	return 0;
}

/*
   We do not cache source address of outgoing interface,
   because it is used only by IP RR, TS and SRR options,
   so that it out of fast path.

   BTW remember: "addr" is allowed to be not aligned
   in IP options!
 */

void ip_rt_get_source(u8 *addr, struct rtable *rt)
{
	__be32 src;
	struct fib_result res;

	if (rt->fl.iif == 0)
		src = rt->rt_src;
	else if (fib_lookup(&rt->fl, &res) == 0) {
		src = FIB_RES_PREFSRC(res);
		fib_res_put(&res);
	} else
		src = inet_select_addr(rt->u.dst.dev, rt->rt_gateway,
					RT_SCOPE_UNIVERSE);
	memcpy(addr, &src, 4);
}

#ifdef CONFIG_NET_CLS_ROUTE
static void set_class_tag(struct rtable *rt, u32 tag)
{
	if (!(rt->u.dst.tclassid & 0xFFFF))
		rt->u.dst.tclassid |= tag & 0xFFFF;
	if (!(rt->u.dst.tclassid & 0xFFFF0000))
		rt->u.dst.tclassid |= tag & 0xFFFF0000;
}
#endif

static void rt_set_nexthop(struct rtable *rt, struct fib_result *res, u32 itag)
{
	struct fib_info *fi = res->fi;

	if (fi) {
		if (FIB_RES_GW(*res) &&
		    FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
			rt->rt_gateway = FIB_RES_GW(*res);
		memcpy(rt->u.dst.metrics, fi->fib_metrics,
		       sizeof(rt->u.dst.metrics));
		if (fi->fib_mtu == 0) {
			rt->u.dst.metrics[RTAX_MTU-1] = rt->u.dst.dev->mtu;
			if (rt->u.dst.metrics[RTAX_LOCK-1] & (1 << RTAX_MTU) &&
			    rt->rt_gateway != rt->rt_dst &&
			    rt->u.dst.dev->mtu > 576)
				rt->u.dst.metrics[RTAX_MTU-1] = 576;
		}
#ifdef CONFIG_NET_CLS_ROUTE
		rt->u.dst.tclassid = FIB_RES_NH(*res).nh_tclassid;
#endif
	} else
		rt->u.dst.metrics[RTAX_MTU-1]= rt->u.dst.dev->mtu;

	if (rt->u.dst.metrics[RTAX_HOPLIMIT-1] == 0)
		rt->u.dst.metrics[RTAX_HOPLIMIT-1] = sysctl_ip_default_ttl;
	if (rt->u.dst.metrics[RTAX_MTU-1] > IP_MAX_MTU)
		rt->u.dst.metrics[RTAX_MTU-1] = IP_MAX_MTU;
	if (rt->u.dst.metrics[RTAX_ADVMSS-1] == 0)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = max_t(unsigned int, rt->u.dst.dev->mtu - 40,
				       ip_rt_min_advmss);
	if (rt->u.dst.metrics[RTAX_ADVMSS-1] > 65535 - 40)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = 65535 - 40;

#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	set_class_tag(rt, fib_rules_tclass(res));
#endif
	set_class_tag(rt, itag);
#endif
        rt->rt_type = res->type;
}

static int ip_route_input_mc(struct sk_buff *skb, __be32 daddr, __be32 saddr,
				u8 tos, struct net_device *dev, int our)
{
	unsigned hash;
	struct rtable *rth;
	__be32 spec_dst;
	struct in_device *in_dev = in_dev_get(dev);
	u32 itag = 0;

	/* Primary sanity checks. */

	if (in_dev == NULL)
		return -EINVAL;

	if (MULTICAST(saddr) || BADCLASS(saddr) || LOOPBACK(saddr) ||
	    skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	if (ZERONET(saddr)) {
		if (!LOCAL_MCAST(daddr))
			goto e_inval;
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	} else if (fib_validate_source(saddr, 0, tos, 0,
					dev, &spec_dst, &itag) < 0)
		goto e_inval;

	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= &loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif	= 0;
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	rth->rt_type	= RTN_MULTICAST;
	rth->rt_flags	= RTCF_MULTICAST;
	if (our) {
		rth->u.dst.input= ip_local_deliver;
		rth->rt_flags |= RTCF_LOCAL;
	}

#ifdef CONFIG_IP_MROUTE
	if (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
		rth->u.dst.input = ip_mr_input;
#endif
	RT_CACHE_STAT_INC(in_slow_mc);

	in_dev_put(in_dev);
	hash = rt_hash(daddr, saddr, dev->ifindex);
	return rt_intern_hash(hash, rth, (struct rtable**) &skb->dst);

e_nobufs:
	in_dev_put(in_dev);
	return -ENOBUFS;

e_inval:
	in_dev_put(in_dev);
	return -EINVAL;
}


static void ip_handle_martian_source(struct net_device *dev,
				     struct in_device *in_dev,
				     struct sk_buff *skb,
				     __be32 daddr,
				     __be32 saddr)
{
	RT_CACHE_STAT_INC(in_martian_src);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit()) {
		/*
		 *	RFC1812 recommendation, if source is martian,
		 *	the only hint is MAC header.
		 */
		printk(KERN_WARNING "martian source %u.%u.%u.%u from "
			"%u.%u.%u.%u, on dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
		if (dev->hard_header_len && skb->mac.raw) {
			int i;
			unsigned char *p = skb->mac.raw;
			printk(KERN_WARNING "ll header: ");
			for (i = 0; i < dev->hard_header_len; i++, p++) {
				printk("%02x", *p);
				if (i < (dev->hard_header_len - 1))
					printk(":");
			}
			printk("\n");
		}
	}
#endif
}

// __mkroute_input()用来创建输入路由缓存项，但仅限于创建进行转发的路由缓存项
// 输入到本地的缓存项参见ip_route_input_mc()和ip_route_input_slow()等
static inline int __mkroute_input(struct sk_buff *skb, 
				  struct fib_result* res, 
				  struct in_device *in_dev, 
				  __be32 daddr, __be32 saddr, u32 tos,
				  struct rtable **result) 
{

	struct rtable *rth;
	int err;
	struct in_device *out_dev;
	unsigned flags = 0;
	__be32 spec_dst;
	u32 itag;

	/* get a working reference to the output device */
	// 获取并检测用于输出报文的网络设备
	out_dev = in_dev_get(FIB_RES_DEV(*res));
	if (out_dev == NULL) {
		if (net_ratelimit())
			printk(KERN_CRIT "Bug in ip_route_input" \
			       "_slow(). Please, report\n");
		return -EINVAL;
	}


	// 检测源地址的有效性，如果检测失败，则返回相应错误码
	err = fib_validate_source(saddr, daddr, tos, FIB_RES_OIF(*res), 
				  in_dev->dev, &spec_dst, &itag);
	if (err < 0) {
		ip_handle_martian_source(in_dev->dev, in_dev, skb, daddr, 
					 saddr);
		
		err = -EINVAL;
		goto cleanup;
	}

	// 如果检测到源地址不正确，则说明会给路由缓存项添加RTCF_DIRECTSRC标志，通知ICMP
	// 模块不对来自此源地址的地址掩码请求消息做出回应
	if (err)
		flags |= RTCF_DIRECTSRC;

	// 如果检测到并不是最优路由，则添加RTCF_DOREDIRECT标志，在转发报文时会根据
	// 该标志和其他信息，决定是否需要发送ICMP重定向消息
	if (out_dev == in_dev && err && !(flags & (RTCF_NAT | RTCF_MASQ)) &&
	    (IN_DEV_SHARED_MEDIA(out_dev) ||
	     inet_addr_onlink(out_dev, saddr, FIB_RES_GW(*res))))
		flags |= RTCF_DOREDIRECT;

	// 对于代理ARP（不是IP数据报），如果输入输出是同一个网络设备，则不能创建
	if (skb->protocol != htons(ETH_P_IP)) {
		/* Not IP (i.e. ARP). Do not create route, if it is
		 * invalid for proxy arp. DNAT routes are always valid.
		 */
		if (out_dev == in_dev && !(flags & RTCF_DNAT)) {
			err = -EINVAL;
			goto cleanup;
		}
	}


	// 校验通过后，为路由缓存项分配内存，并设置相关的值，进行转发缓存项的
	// input和output设置为ip_forward()和ip_output()
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth) {
		err = -ENOBUFS;
		goto cleanup;
	}

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	if (res->fi->fib_nhs > 1)
		rth->u.dst.flags |= DST_BALANCED;
#endif
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	if (out_dev->cnf.no_xfrm)
		rth->u.dst.flags |= DST_NOXFRM;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
	rth->rt_gateway	= daddr;
	rth->rt_iif 	=
		rth->fl.iif	= in_dev->dev->ifindex;
	rth->u.dst.dev	= (out_dev)->dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif 	= 0;
	rth->rt_spec_dst= spec_dst;

	rth->u.dst.input = ip_forward;
	rth->u.dst.output = ip_output;

	rt_set_nexthop(rth, res, itag);

	rth->rt_flags = flags;

	// 返回成功创建的路由缓存项
	*result = rth;
	err = 0;
 cleanup:
	/* release the working reference to the output device */
	in_dev_put(out_dev);
	return err;
}						

static inline int ip_mkroute_input_def(struct sk_buff *skb, 
				       struct fib_result* res, 
				       const struct flowi *fl,
				       struct in_device *in_dev,
				       __be32 daddr, __be32 saddr, u32 tos)
{
	struct rtable* rth = NULL;
	int err;
	unsigned hash;

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (res->fi && res->fi->fib_nhs > 1 && fl->oif == 0)
		fib_select_multipath(fl, res);
#endif

	/* create a routing cache entry */
	err = __mkroute_input(skb, res, in_dev, daddr, saddr, tos, &rth);
	if (err)
		return err;

	/* put it into the cache */
	hash = rt_hash(daddr, saddr, fl->iif);
	return rt_intern_hash(hash, rth, (struct rtable**)&skb->dst);	
}

static inline int ip_mkroute_input(struct sk_buff *skb, 
				   struct fib_result* res, 
				   const struct flowi *fl,
				   struct in_device *in_dev,
				   __be32 daddr, __be32 saddr, u32 tos)
{
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	struct rtable* rth = NULL, *rtres;
	unsigned char hop, hopcount;
	int err = -EINVAL;
	unsigned int hash;

	if (res->fi)
		hopcount = res->fi->fib_nhs;
	else
		hopcount = 1;

	/* distinguish between multipath and singlepath */
	if (hopcount < 2)
		return ip_mkroute_input_def(skb, res, fl, in_dev, daddr,
					    saddr, tos);
	
	/* add all alternatives to the routing cache */
	for (hop = 0; hop < hopcount; hop++) {
		res->nh_sel = hop;

		/* put reference to previous result */
		if (hop)
			ip_rt_put(rtres);

		/* create a routing cache entry */
		err = __mkroute_input(skb, res, in_dev, daddr, saddr, tos,
				      &rth);
		if (err)
			return err;

		/* put it into the cache */
		hash = rt_hash(daddr, saddr, fl->iif);
		err = rt_intern_hash(hash, rth, &rtres);
		if (err)
			return err;

		/* forward hop information to multipath impl. */
		multipath_set_nhinfo(rth,
				     FIB_RES_NETWORK(*res),
				     FIB_RES_NETMASK(*res),
				     res->prefixlen,
				     &FIB_RES_NH(*res));
	}
	skb->dst = &rtres->u.dst;
	return err;
#else /* CONFIG_IP_ROUTE_MULTIPATH_CACHED  */
	return ip_mkroute_input_def(skb, res, fl, in_dev, daddr, saddr, tos);
#endif /* CONFIG_IP_ROUTE_MULTIPATH_CACHED  */
}


/*
 *	NOTE. We drop all the packets that has local source
 *	addresses, because every properly looped back packet
 *	must have correct destination already attached by output routine.
 *
 *	Such approach solves two big problems:
 *	1. Not simplex devices are handled properly.
 *	2. IP spoofing attempts are filtered with 100% of guarantee.
 */
// 对从网络设备输入的数据报进行路由，会调用ip_route_input()进行路由，如果缓存没有
// 查找到匹配表项时，会调用ip_route_input_slow()在路由表中进行查找，查找命中后，
// 则将该表项添加到缓存中
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
			       u8 tos, struct net_device *dev)
{
	struct fib_result res;
	struct in_device *in_dev = in_dev_get(dev);
	// 根据源地址和目的地址以及tos构造flowi实例，组织查找路由表项的条件
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = daddr,
					.saddr = saddr,
					.tos = tos,
					.scope = RT_SCOPE_UNIVERSE,
				      } },
			    .mark = skb->mark,
			    .iif = dev->ifindex };
	unsigned	flags = 0;
	u32		itag = 0;
	struct rtable * rth;
	unsigned	hash;
	__be32		spec_dst;
	int		err = -EINVAL;
	int		free_res = 0;

	/* IP on this device is disabled. */
	// 检验网络设备的IP特性的配置块的有效性
	if (!in_dev)
		goto out;

	/* Check for the most weird martians, which can be not detected
	   by fib_lookup.
	 */
	// 检验源地址和目的地址的有效性，如目的地址不能为广播地址或回环地址
	if (MULTICAST(saddr) || BADCLASS(saddr) || LOOPBACK(saddr))
		goto martian_source;

	if (daddr == htonl(0xFFFFFFFF) || (saddr == 0 && daddr == 0))
		goto brd_input;

	/* Accept zero addresses only to limited broadcast;
	 * I even do not know to fix it or not. Waiting for complains :-)
	 */
	if (ZERONET(saddr))
		goto martian_source;

	if (BADCLASS(daddr) || ZERONET(daddr) || LOOPBACK(daddr))
		goto martian_destination;

	/*
	 *	Now we are ready to route packet.
	 */
	// 通过fib_lookup()在路由表中根据查找条件查找适合的表项
	if ((err = fib_lookup(&fl, &res)) != 0) {
		// 如果查找失败并且禁止转发，返回EHOSTUNREACH发送主机没找到的错误
		if (!IN_DEV_FORWARD(in_dev))
			goto e_hostunreach;
		// 否则跳转到no_route进行处理
		goto no_route;
	}
	free_res = 1;

	RT_CACHE_STAT_INC(in_slow_tot);

	// 目的地址为广播地址，由brd_input处理
	if (res.type == RTN_BROADCAST)
		goto brd_input;

	// 如果目的地址为本地接口的地址，需要检测源地址的有效性
	// 检测通过后，由local_input处理
	if (res.type == RTN_LOCAL) {
		int result;
		result = fib_validate_source(saddr, daddr, tos,
					     loopback_dev.ifindex,
					     dev, &spec_dst, &itag);
		if (result < 0)
			goto martian_source;
		if (result)
			flags |= RTCF_DIRECTSRC;
		spec_dst = daddr;
		goto local_input;
	}

	// 如果系统禁止转发，且查找命中的表项的目的地址不为本地接口的地址，则返回
	// EHOSTUNREACH发送主机没找到的错误
	if (!IN_DEV_FORWARD(in_dev))
		goto e_hostunreach;
	// 此函数处理的目的地址为单播地址，因此查找的路由目的地址不为单播地址，则返回无效
	if (res.type != RTN_UNICAST)
		goto martian_destination;

	// 在对转发的数据报完成校验检查找到的路由后，调用ip_mkroute_input()创建路由缓存
	// 表项并添加到缓存中
	err = ip_mkroute_input(skb, &res, &fl, in_dev, daddr, saddr, tos);
	if (err == -ENOBUFS)
		goto e_nobufs;
	if (err == -EINVAL)
		goto e_inval;
	
// 当正常查询结束后从此处返回
done:
	in_dev_put(in_dev);
	if (free_res)
		fib_res_put(&res);
out:	return err;

// 处理目的地址为受限的广播地址255.255.255.255，或者目的地址和源地址都为0的情况
brd_input:
	if (skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	if (ZERONET(saddr))
		// 如果源地址为０，则通过inet_select_addr()选择合适的源地址
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	else {
		// 否则校验该源地址是否有效
		err = fib_validate_source(saddr, 0, tos, 0, dev, &spec_dst,
					  &itag);
		// 根据校验结果，返回EHOSTUNREACH或设置该路由表项RTCF_DIRECTSRC标志
		if (err < 0)
			goto martian_source;
		if (err)
			flags |= RTCF_DIRECTSRC;
	}
	// 给路由表项设置RTCF_BROADCAST标志，说明路由的目的地址是一个广播地址
	flags |= RTCF_BROADCAST;
	res.type = RTN_BROADCAST;
	RT_CACHE_STAT_INC(in_brd);

// 选路的目的地址为本地接口的地址创建路由缓存表项并添加到路由缓存中
local_input:
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= &loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	rth->u.dst.input= ip_local_deliver;
	rth->rt_flags 	= flags|RTCF_LOCAL;
	if (res.type == RTN_UNREACHABLE) {
		rth->u.dst.input= ip_error;
		rth->u.dst.error= -err;
		rth->rt_flags 	&= ~RTCF_LOCAL;
	}
	rth->rt_type	= res.type;
	hash = rt_hash(daddr, saddr, fl.iif);
	err = rt_intern_hash(hash, rth, (struct rtable**)&skb->dst);
	goto done;

// 根据RT_SCOPE_UNIVERSE范围选择地址作为路由的目的地址，然后转到local_input处
// 创建路由缓存表项
no_route:
	RT_CACHE_STAT_INC(in_no_route);
	spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
	res.type = RTN_UNREACHABLE;
	goto local_input;

	/*
	 *	Do not cache martian addresses: they should be logged (RFC1812)
	 */
// 选路失败时，返回相应错误码
martian_destination:
	RT_CACHE_STAT_INC(in_martian_dst);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_WARNING "martian destination %u.%u.%u.%u from "
			"%u.%u.%u.%u, dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
#endif

e_hostunreach:
        err = -EHOSTUNREACH;
        goto done;

e_inval:
	err = -EINVAL;
	goto done;

e_nobufs:
	err = -ENOBUFS;
	goto done;

martian_source:
	ip_handle_martian_source(dev, in_dev, skb, daddr, saddr);
	goto e_inval;
}

// 此函数用于输入报文的路由缓存查询，有时报文本身可能不需要被路由，例如ARP出于
// 某些原因使用ip_route_input()来咨询local路由表，这时的skb应当是一个输入的
// ARP请求
// skb, 进行路由查找的报文
// saddr和daddr，用于查找的源地址和目的地址
// tos，IP首部中的TOS字段
// dev，输入该数据报的网络设备
int ip_route_input(struct sk_buff *skb, __be32 daddr, __be32 saddr,
		   u8 tos, struct net_device *dev)
{
	struct rtable * rth;
	unsigned	hash;
	int iif = dev->ifindex;

	tos &= IPTOS_RT_MASK;
	// 根据目的地址、源地址和输入网络设备得到存储该路由的散列桶
	hash = rt_hash(daddr, saddr, iif);

	rcu_read_lock();
	// 遍历该桶查找与目的地址、源地址和输入网络设备相匹配的路由项，直至查找命中
	// 或至链表尾部。如果能在缓存中命中路由项，则更新最后一次被使用的时间戳、该
	// 表项已经被使用的次数，以及缓存命中率等，然后设置输入SKB的目的路由入口后返回
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
	     rth = rcu_dereference(rth->u.rt_next)) {
		if (rth->fl.fl4_dst == daddr &&
		    rth->fl.fl4_src == saddr &&
		    rth->fl.iif == iif &&
		    rth->fl.oif == 0 &&
		    rth->fl.mark == skb->mark &&
		    rth->fl.fl4_tos == tos) {
			rth->u.dst.lastuse = jiffies;
			dst_hold(&rth->u.dst);
			rth->u.dst.__use++;
			RT_CACHE_STAT_INC(in_hit);
			rcu_read_unlock();
			skb->dst = (struct dst_entry*)rth;
			return 0;
		}
		RT_CACHE_STAT_INC(in_hlist_search);
	}
	rcu_read_unlock();

	/* Multicast recognition logic is moved from route cache to here.
	   The problem was that too many Ethernet cards have broken/missing
	   hardware multicast filters :-( As result the host on multicasting
	   network acquires a lot of useless route cache entries, sort of
	   SDR messages from all the world. Now we try to get rid of them.
	   Really, provided software IP multicast filter is organized
	   reasonably (at least, hashed), it does not result in a slowdown
	   comparing with route cache reject entries.
	   Note, that multicast routers are not affected, because
	   route cache entry is created eventually.
	 */
	// 如果在报文目的地址为多播时缓存查找失败，那么以下两个条件只要有一个满足
	// 该报文就被送给多播处理函数ip_route_input_mc()，否则不作处理，返回错误码
	if (MULTICAST(daddr)) {
		struct in_device *in_dev;

		rcu_read_lock();
		if ((in_dev = __in_dev_get_rcu(dev)) != NULL) {
			// 目的地址是本地配置的多播地址，通过ip_check_mc()来检查
			int our = ip_check_mc(in_dev, daddr, saddr,
				skb->nh.iph->protocol);
			if (our
//　在内核编译时启动了多播路由(CONFIG_IP_MROUTE)的情况下，目的地址不是本地配置，且设备支持多播转发
#ifdef CONFIG_IP_MROUTE
			    || (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
#endif
			    ) {
				rcu_read_unlock();
				return ip_route_input_mc(skb, daddr, saddr,
							 tos, dev, our);
			}
		}
		rcu_read_unlock();
		return -EINVAL;
	}
	// 如果目的地址不是多播情况下缓存查找失败，则调用ip_route_input_slow()在查找路由表中查找
	return ip_route_input_slow(skb, daddr, saddr, tos, dev);
}

// __mkroute_output()用来创建输出路由缓存项
static inline int __mkroute_output(struct rtable **result,
				   struct fib_result* res, 
				   const struct flowi *fl,
				   const struct flowi *oldflp, 
				   struct net_device *dev_out, 
				   unsigned flags) 
{
	struct rtable *rth;
	struct in_device *in_dev;
	u32 tos = RT_FL_TOS(oldflp);
	int err = 0;

	// 如果源地址是回环地址，则输出网络设备也必须是回环设备，不然无效
	if (LOOPBACK(fl->fl4_src) && !(dev_out->flags&IFF_LOOPBACK))
		return -EINVAL;

	// 根据目的地址，设置路由缓存项的类型，保留地址和零地址不能作为目的地址
	if (fl->fl4_dst == htonl(0xFFFFFFFF))
		res->type = RTN_BROADCAST;
	else if (MULTICAST(fl->fl4_dst))
		res->type = RTN_MULTICAST;
	else if (BADCLASS(fl->fl4_dst) || ZERONET(fl->fl4_dst))
		return -EINVAL;

	// 如果输出网络设备是回环设备，则路由缓存项目的地址是一个本地地址
	if (dev_out->flags & IFF_LOOPBACK)
		flags |= RTCF_LOCAL;

	/* get work reference to inet device */
	// 获取并检测输出网络设备IP配置块
	in_dev = in_dev_get(dev_out);
	if (!in_dev)
		return -EINVAL;

	// 如果待创建的路由缓存项是广播类型，则添加RTCF_LOCAL标志
	if (res->type == RTN_BROADCAST) {
		flags |= RTCF_BROADCAST | RTCF_LOCAL;
		if (res->fi) {
			fib_info_put(res->fi);
			res->fi = NULL;
		}
	} else if (res->type == RTN_MULTICAST) {
		// 如果待创建的路由缓存项是组播类型，则也要添加RTCF_LOCAL标志
		// 但必须通过检测
		flags |= RTCF_MULTICAST|RTCF_LOCAL;
		if (!ip_check_mc(in_dev, oldflp->fl4_dst, oldflp->fl4_src, 
				 oldflp->proto))
			flags &= ~RTCF_LOCAL;
		/* If multicast route do not exist use
		   default one, but do not gateway in this case.
		   Yes, it is hack.
		 */
		if (res->fi && res->prefixlen < 4) {
			fib_info_put(res->fi);
			res->fi = NULL;
		}
	}

	// 校验通过后，为路由缓存项分配内存，并设置相关的值
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth) {
		err = -ENOBUFS;
		goto cleanup;
	}		

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	if (res->fi) {
		rth->rt_multipath_alg = res->fi->fib_mp_alg;
		if (res->fi->fib_nhs > 1)
			rth->u.dst.flags |= DST_BALANCED;
	}
#endif
	if (in_dev->cnf.no_xfrm)
		rth->u.dst.flags |= DST_NOXFRM;
	if (in_dev->cnf.no_policy)
		rth->u.dst.flags |= DST_NOPOLICY;

	rth->fl.fl4_dst	= oldflp->fl4_dst;
	rth->fl.fl4_tos	= tos;
	rth->fl.fl4_src	= oldflp->fl4_src;
	rth->fl.oif	= oldflp->oif;
	rth->fl.mark    = oldflp->mark;
	rth->rt_dst	= fl->fl4_dst;
	rth->rt_src	= fl->fl4_src;
	rth->rt_iif	= oldflp->oif ? : dev_out->ifindex;
	/* get references to the devices that are to be hold by the routing 
	   cache entry */
	rth->u.dst.dev	= dev_out;
	dev_hold(dev_out);
	rth->idev	= in_dev_get(dev_out);
	rth->rt_gateway = fl->fl4_dst;
	rth->rt_spec_dst= fl->fl4_src;

	// 输出缓存项的output设置为ip_output()
	rth->u.dst.output=ip_output;

	RT_CACHE_STAT_INC(out_slow_tot);

	// 如果路由缓存项存在RTCF_LOCAL，则输出缓存项的input设置为ip_local_deliver()
	if (flags & RTCF_LOCAL) {
		rth->u.dst.input = ip_local_deliver;
		rth->rt_spec_dst = fl->fl4_dst;
	}
	// 如果目的地址为组播或广播地址，则输出缓存项的output设置为ip_mc_output()
	if (flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
		rth->rt_spec_dst = fl->fl4_src;
		if (flags & RTCF_LOCAL && 
		    !(dev_out->flags & IFF_LOOPBACK)) {
			rth->u.dst.output = ip_mc_output;
			RT_CACHE_STAT_INC(out_slow_mc);
		}
#ifdef CONFIG_IP_MROUTE
		if (res->type == RTN_MULTICAST) {
			if (IN_DEV_MFORWARD(in_dev) &&
			    !LOCAL_MCAST(oldflp->fl4_dst)) {
				rth->u.dst.input = ip_mr_input;
				rth->u.dst.output = ip_mc_output;
			}
		}
#endif
	}

	rt_set_nexthop(rth, res, 0);

	rth->rt_flags = flags;

	// 返回成功创建的路由缓存项
	*result = rth;
 cleanup:
	/* release work reference to inet device */
	in_dev_put(in_dev);

	return err;
}

static inline int ip_mkroute_output_def(struct rtable **rp,
					struct fib_result* res,
					const struct flowi *fl,
					const struct flowi *oldflp,
					struct net_device *dev_out,
					unsigned flags)
{
	struct rtable *rth = NULL;
	int err = __mkroute_output(&rth, res, fl, oldflp, dev_out, flags);
	unsigned hash;
	if (err == 0) {
		hash = rt_hash(oldflp->fl4_dst, oldflp->fl4_src, oldflp->oif);
		err = rt_intern_hash(hash, rth, rp);
	}
	
	return err;
}

static inline int ip_mkroute_output(struct rtable** rp,
				    struct fib_result* res,
				    const struct flowi *fl,
				    const struct flowi *oldflp,
				    struct net_device *dev_out,
				    unsigned flags)
{
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	unsigned char hop;
	unsigned hash;
	int err = -EINVAL;
	struct rtable *rth = NULL;

	if (res->fi && res->fi->fib_nhs > 1) {
		unsigned char hopcount = res->fi->fib_nhs;

		for (hop = 0; hop < hopcount; hop++) {
			struct net_device *dev2nexthop;

			res->nh_sel = hop;

			/* hold a work reference to the output device */
			dev2nexthop = FIB_RES_DEV(*res);
			dev_hold(dev2nexthop);

			/* put reference to previous result */
			if (hop)
				ip_rt_put(*rp);

			err = __mkroute_output(&rth, res, fl, oldflp,
					       dev2nexthop, flags);

			if (err != 0)
				goto cleanup;

			hash = rt_hash(oldflp->fl4_dst, oldflp->fl4_src,
					oldflp->oif);
			err = rt_intern_hash(hash, rth, rp);

			/* forward hop information to multipath impl. */
			multipath_set_nhinfo(rth,
					     FIB_RES_NETWORK(*res),
					     FIB_RES_NETMASK(*res),
					     res->prefixlen,
					     &FIB_RES_NH(*res));
		cleanup:
			/* release work reference to output device */
			dev_put(dev2nexthop);

			if (err != 0)
				return err;
		}
		return err;
	} else {
		return ip_mkroute_output_def(rp, res, fl, oldflp, dev_out,
					     flags);
	}
#else /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
	return ip_mkroute_output_def(rp, res, fl, oldflp, dev_out, flags);
#endif
}

/*
 * Major route resolver routine.
 */
// 对本地生成数据报进行路由，会调用ip_route_output_slow()在路由表中进行查找
// 并在查找到匹配的表项后，将表项添加到缓存中
static int ip_route_output_slow(struct rtable **rp, const struct flowi *oldflp)
{
	// 根据在缓存中查找的条件oldflp初始化在路由表中查找的条件fl，作为之后调用
	// fib_lookup()的参数
	// 因为TOS字段不需要占用整个八位，因此可将flags存储在fl4_tos字段的两个
	// 最低位中，这样ip_route_output_slow()可以使用该flags来确定待搜索路由项
	// 的范围
	u32 tos	= RT_FL_TOS(oldflp);
	// 源地址，目的地址和防火墙标记是直接从输入参数复制而来的，而源设备则被初始化为
	// 回环设备，因为ip_route_output_slow()只是路由本地生成的包
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = oldflp->fl4_dst,
					.saddr = oldflp->fl4_src,
					.tos = tos & IPTOS_RT_MASK,
					.scope = ((tos & RTO_ONLINK) ?
						  RT_SCOPE_LINK :
						  RT_SCOPE_UNIVERSE),
				      } },
			    .mark = oldflp->mark,
			    .iif = loopback_dev.ifindex,
			    .oif = oldflp->oif };
	struct fib_result res;
	unsigned flags = 0;
	struct net_device *dev_out = NULL;
	int free_res = 0;
	int err;


	res.fi		= NULL;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r		= NULL;
#endif

	// 在源地址已知的情况下，对该源地址以及与该源地址对应网络设备进行校验
	if (oldflp->fl4_src) {
		err = -EINVAL;
		// 源地址不能为广播地址，组播地址或为０
		if (MULTICAST(oldflp->fl4_src) ||
		    BADCLASS(oldflp->fl4_src) ||
		    ZERONET(oldflp->fl4_src))
			goto out;

		/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
		// 检测根据该源地址获取对应设备是否有效
		dev_out = ip_dev_find(oldflp->fl4_src);
		if (dev_out == NULL)
			goto out;

		/* I removed check for oif == dev_out->oif here.
		   It was wrong for two reasons:
		   1. ip_dev_find(saddr) can return wrong iface, if saddr is
		      assigned to multiple interfaces.
		   2. Moreover, we are allowed to send packets with saddr
		      of another iface. --ANK
		 */
		// 如果key中没有设定输出网络设备，并且目的地址为组播地址或广播地址
		// 则将根据源地址获取到的设备作为输出网络地址，在这种情况下，可以进行
		// 创建路由缓存了
		if (oldflp->oif == 0
		    && (MULTICAST(oldflp->fl4_dst) || oldflp->fl4_dst == htonl(0xFFFFFFFF))) {
			/* Special hack: user can direct multicasts
			   and limited broadcast via necessary interface
			   without fiddling with IP_MULTICAST_IF or IP_PKTINFO.
			   This hack is not just for fun, it allows
			   vic,vat and friends to work.
			   They bind socket to loopback, set ttl to zero
			   and expect that it will work.
			   From the viewpoint of routing cache they are broken,
			   because we are not allowed to build multicast path
			   with loopback source addr (look, routing cache
			   cannot know, that ttl is zero, so that packet
			   will not leave this host and route is valid).
			   Luckily, this hack is good workaround.
			 */

			fl.oif = dev_out->ifindex;
			goto make_route;
		}
		if (dev_out)
			dev_put(dev_out);
		dev_out = NULL;
	}


	// 在输出网络设备已知的情况下，对该网络设备进行校验，并获取源地址
	if (oldflp->oif) {
		// 根据给定的输出网络设备ID获取网络设备
		dev_out = dev_get_by_index(oldflp->oif);
		err = -ENODEV;
		if (dev_out == NULL)
			goto out;

		/* RACE: Check return value of inet_select_addr instead. */
		// 检测该输出网络设备的IPv4设备块是否有效
		if (__in_dev_get_rtnl(dev_out) == NULL) {
			dev_put(dev_out);
			goto out;	/* Wrong error code */
		}

		if (LOCAL_MCAST(oldflp->fl4_dst) || oldflp->fl4_dst == htonl(0xFFFFFFFF)) {
			if (!fl.fl4_src)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			goto make_route;
		}
		// 当搜索的条件fl没有提供源地址时，则通过inet_select_addr()的输入参数来
		// 选择一个源IP地址，但是需要根据目的地址不同的类型，inet_select_addr()
		// 获取源地址的范围也不同，比如目的地址为本地组播地址或广播地址，则类型为
		// RT_SCOPE_LINK，而且完成后创建路由缓存
		if (!fl.fl4_src) {
			if (MULTICAST(oldflp->fl4_dst))
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      fl.fl4_scope);
			else if (!oldflp->fl4_dst)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_HOST);
		}
	}

	// 目的地址未知的情况下将源地址设置为目的地址，如果目的地址和源地址都未设置
	// 则使用回环地址作为目的地址和源地址。输出网络设备设置为回环网络设备，同时
	// 设置路由表项类型为RTN_LOCAL，完成设置后进行创建路由缓存
	if (!fl.fl4_dst) {
		fl.fl4_dst = fl.fl4_src;
		if (!fl.fl4_dst)
			fl.fl4_dst = fl.fl4_src = htonl(INADDR_LOOPBACK);
		if (dev_out)
			dev_put(dev_out);
		dev_out = &loopback_dev;
		dev_hold(dev_out);
		fl.oif = loopback_dev.ifindex;
		res.type = RTN_LOCAL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

	// 通过fib_lookup()在路由表中查找合适的路由表项
	// 查找失败，但输出的数据报确定了输出网络设备，在这种情况下，即使路由查找失败
	// 但确信目的地址是有效的，因为当指定了输出网络设备的ID，查找路由只有一个目的，
	// 那就是确定目的地址是经过网关的，而不是直连的
	// 另外，如果设置MSG_DONTROUTE，在发送数据报时会忽略路由表
	if (fib_lookup(&fl, &res)) {
		res.fi = NULL;
		if (oldflp->oif) {
			/* Apparently, routing tables are wrong. Assume,
			   that the destination is on link.

			   WHY? DW.
			   Because we are allowed to send to iface
			   even if it has NO routes and NO assigned
			   addresses. When oif is specified, routing
			   tables are looked up with only one purpose:
			   to catch if destination is gatewayed, rather than
			   direct. Moreover, if MSG_DONTROUTE is set,
			   we send packet, ignoring both routing tables
			   and ifaddr state. --ANK


			   We could make it even if oif is unknown,
			   likely IPv6, but we do not.
			 */

			if (fl.fl4_src == 0)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			res.type = RTN_UNICAST;
			goto make_route;
		}
		if (dev_out)
			dev_put(dev_out);
		err = -ENETUNREACH;
		goto out;
	}
	free_res = 1;

	// 当fib_lookup查找的数据报的目的地址是本地地址，或者当数据报中没有提供目的地址
	// (即搜索包含了未知地址0.0.0.0)，则该数据报被送往本地
	if (res.type == RTN_LOCAL) {
		if (!fl.fl4_src)
			fl.fl4_src = fl.fl4_dst;
		if (dev_out)
			dev_put(dev_out);
		// 输出设备被设置为回环设备，表示该数据报不会离开本地主机，该数据报被发送出去后
		// 将重新回到IP输入栈
		dev_out = &loopback_dev;
		dev_hold(dev_out);
		fl.oif = dev_out->ifindex;
		if (res.fi)
			fib_info_put(res.fi);
		res.fi = NULL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	// 在启用了多路径路由时，选择路由
	if (res.fi->fib_nhs > 1 && fl.oif == 0)
		fib_select_multipath(&fl, &res);
	else
#endif
	// res.prefixlen字段为0时表示是默认路由，这表示"前缀长度"，
	// 即与该地址相关的掩码长度为0
	if (!res.prefixlen && res.type == RTN_UNICAST && !fl.oif)
		// 当查找返回的路由是默认路由时，需要选择使用的默认网关
		fib_select_default(&fl, &res);

	if (!fl.fl4_src)
		fl.fl4_src = FIB_RES_PREFSRC(res);

	// 即使fib_lookup()查找失败，但还是有可能成功地将数据报发送出去
	// 当搜索key提供了输出网络设备，ip_route_output_slow()假定通过该
	// 网络设备可以直接到达目的地。这时，如果还没有源IP地址，则还需要设置
	// 一个作用范围为RT_SCOPE_LINK的源IP地址，可能的情况下用的是该输出
	// 网络设备上的一个地址
	if (dev_out)
		dev_put(dev_out);
	dev_out = FIB_RES_DEV(res);
	dev_hold(dev_out);
	fl.oif = dev_out->ifindex;

// 最后创建缓存表项并添加到路由缓存中，这由ip_mkroute_output()来执行
make_route:
	err = ip_mkroute_output(rp, &res, &fl, oldflp, dev_out, flags);


	if (free_res)
		fib_res_put(&res);
	if (dev_out)
		dev_put(dev_out);
out:	return err;
}

// __ip_route_output_key()在路由缓存中根据查询条件搜索符合条件的缓存项，该函数
// 通常被间接调用，由ip_route_output_flow()封装调用
int __ip_route_output_key(struct rtable **rp, const struct flowi *flp)
{
	unsigned hash;
	struct rtable *rth;

	hash = rt_hash(flp->fl4_dst, flp->fl4_src, flp->oif);

	rcu_read_lock_bh();
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		rth = rcu_dereference(rth->u.rt_next)) {
		if (rth->fl.fl4_dst == flp->fl4_dst &&
		    rth->fl.fl4_src == flp->fl4_src &&
		    rth->fl.iif == 0 &&
		    rth->fl.oif == flp->oif &&
		    rth->fl.mark == flp->mark &&
		    !((rth->fl.fl4_tos ^ flp->fl4_tos) &
			    (IPTOS_RT_MASK | RTO_ONLINK))) {
			// 检查路由缓存，输出缓存查找成功需要匹配RTO_ONLINK标志
			// 上面的条件只有在以下两个条件都满足时才为真：
			// (1) 路由缓存的TOS与搜索条件中的TOS匹配，这个TOS字段被保存在8位tos
			// 变量的2,3,4,5位
			// (2) 当路由缓存项和搜索条件都设置了RTO_ONLINK标志，或者都没设置

			/* check for multipath routes and choose one if
			 * necessary
			 */
			if (multipath_select_route(flp, rth, rp)) {
				dst_hold(&(*rp)->u.dst);
				RT_CACHE_STAT_INC(out_hit);
				rcu_read_unlock_bh();
				return 0;
			}

			rth->u.dst.lastuse = jiffies;
			dst_hold(&rth->u.dst);
			rth->u.dst.__use++;
			RT_CACHE_STAT_INC(out_hit);
			rcu_read_unlock_bh();
			*rp = rth;
			return 0;
		}
		RT_CACHE_STAT_INC(out_hlist_search);
	}
	rcu_read_unlock_bh();

	// 在缓存查询失败的情况下调用ip_route_output_slow()
	return ip_route_output_slow(rp, flp);
}

EXPORT_SYMBOL_GPL(__ip_route_output_key);

// 由本地生成的报文输出时都会调用ip_route_output_flow()或ip_route_output_key()进行路由查询
// 这两个函数的区别在于ip_route_output_flow()支持IPsec，而ip_route_output_key()不支持IPsec
// 事实上ip_route_output_key()也是对ip_route_output_flow()的简单封装，只是省略了IPSec的参数
// rp，当查询成功时，返回查询得到的路由缓存项
// flp，用于查询路由缓存项的条件组合
// sk, flags，支持IPsec策略处理
int ip_route_output_flow(struct rtable **rp, struct flowi *flp, struct sock *sk, int flags)
{
	int err;

	// 进程输出路由缓存的查询，查询失败则返回相应错误
	if ((err = __ip_route_output_key(rp, flp)) != 0)
		return err;

	// 进行相关IPsec方面的路由查询
	if (flp->proto) {
		if (!flp->fl4_src)
			flp->fl4_src = (*rp)->rt_src;
		if (!flp->fl4_dst)
			flp->fl4_dst = (*rp)->rt_dst;
		return xfrm_lookup((struct dst_entry **)rp, flp, sk, flags);
	}

	return 0;
}

EXPORT_SYMBOL_GPL(ip_route_output_flow);

int ip_route_output_key(struct rtable **rp, struct flowi *flp)
{
	return ip_route_output_flow(rp, flp, NULL, 0);
}

static int rt_fill_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			int nowait, unsigned int flags)
{
	struct rtable *rt = (struct rtable*)skb->dst;
	struct rtmsg *r;
	struct nlmsghdr *nlh;
	long expires;
	u32 id = 0, ts = 0, tsage = 0, error;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*r), flags);
	if (nlh == NULL)
		return -ENOBUFS;

	r = nlmsg_data(nlh);
	r->rtm_family	 = AF_INET;
	r->rtm_dst_len	= 32;
	r->rtm_src_len	= 0;
	r->rtm_tos	= rt->fl.fl4_tos;
	r->rtm_table	= RT_TABLE_MAIN;
	NLA_PUT_U32(skb, RTA_TABLE, RT_TABLE_MAIN);
	r->rtm_type	= rt->rt_type;
	r->rtm_scope	= RT_SCOPE_UNIVERSE;
	r->rtm_protocol = RTPROT_UNSPEC;
	r->rtm_flags	= (rt->rt_flags & ~0xFFFF) | RTM_F_CLONED;
	if (rt->rt_flags & RTCF_NOTIFY)
		r->rtm_flags |= RTM_F_NOTIFY;

	NLA_PUT_BE32(skb, RTA_DST, rt->rt_dst);

	if (rt->fl.fl4_src) {
		r->rtm_src_len = 32;
		NLA_PUT_BE32(skb, RTA_SRC, rt->fl.fl4_src);
	}
	if (rt->u.dst.dev)
		NLA_PUT_U32(skb, RTA_OIF, rt->u.dst.dev->ifindex);
#ifdef CONFIG_NET_CLS_ROUTE
	if (rt->u.dst.tclassid)
		NLA_PUT_U32(skb, RTA_FLOW, rt->u.dst.tclassid);
#endif
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	if (rt->rt_multipath_alg != IP_MP_ALG_NONE)
		NLA_PUT_U32(skb, RTA_MP_ALGO, rt->rt_multipath_alg);
#endif
	if (rt->fl.iif)
		NLA_PUT_BE32(skb, RTA_PREFSRC, rt->rt_spec_dst);
	else if (rt->rt_src != rt->fl.fl4_src)
		NLA_PUT_BE32(skb, RTA_PREFSRC, rt->rt_src);

	if (rt->rt_dst != rt->rt_gateway)
		NLA_PUT_BE32(skb, RTA_GATEWAY, rt->rt_gateway);

	if (rtnetlink_put_metrics(skb, rt->u.dst.metrics) < 0)
		goto nla_put_failure;

	error = rt->u.dst.error;
	expires = rt->u.dst.expires ? rt->u.dst.expires - jiffies : 0;
	if (rt->peer) {
		id = rt->peer->ip_id_count;
		if (rt->peer->tcp_ts_stamp) {
			ts = rt->peer->tcp_ts;
			tsage = xtime.tv_sec - rt->peer->tcp_ts_stamp;
		}
	}

	if (rt->fl.iif) {
#ifdef CONFIG_IP_MROUTE
		__be32 dst = rt->rt_dst;

		if (MULTICAST(dst) && !LOCAL_MCAST(dst) &&
		    ipv4_devconf.mc_forwarding) {
			int err = ipmr_get_route(skb, r, nowait);
			if (err <= 0) {
				if (!nowait) {
					if (err == 0)
						return 0;
					goto nla_put_failure;
				} else {
					if (err == -EMSGSIZE)
						goto nla_put_failure;
					error = err;
				}
			}
		} else
#endif
			NLA_PUT_U32(skb, RTA_IIF, rt->fl.iif);
	}

	if (rtnl_put_cacheinfo(skb, &rt->u.dst, id, ts, tsage,
			       expires, error) < 0)
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	return nlmsg_cancel(skb, nlh);
}

int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtmsg *rtm;
	struct nlattr *tb[RTA_MAX+1];
	struct rtable *rt = NULL;
	__be32 dst = 0;
	__be32 src = 0;
	u32 iif;
	int err;
	struct sk_buff *skb;

	err = nlmsg_parse(nlh, sizeof(*rtm), tb, RTA_MAX, rtm_ipv4_policy);
	if (err < 0)
		goto errout;

	rtm = nlmsg_data(nlh);

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		err = -ENOBUFS;
		goto errout;
	}

	/* Reserve room for dummy headers, this skb can pass
	   through good chunk of routing engine.
	 */
	skb->mac.raw = skb->nh.raw = skb->data;

	/* Bugfix: need to give ip_route_input enough of an IP header to not gag. */
	skb->nh.iph->protocol = IPPROTO_ICMP;
	skb_reserve(skb, MAX_HEADER + sizeof(struct iphdr));

	src = tb[RTA_SRC] ? nla_get_be32(tb[RTA_SRC]) : 0;
	dst = tb[RTA_DST] ? nla_get_be32(tb[RTA_DST]) : 0;
	iif = tb[RTA_IIF] ? nla_get_u32(tb[RTA_IIF]) : 0;

	if (iif) {
		struct net_device *dev;

		dev = __dev_get_by_index(iif);
		if (dev == NULL) {
			err = -ENODEV;
			goto errout_free;
		}

		skb->protocol	= htons(ETH_P_IP);
		skb->dev	= dev;
		local_bh_disable();
		err = ip_route_input(skb, dst, src, rtm->rtm_tos, dev);
		local_bh_enable();

		rt = (struct rtable*) skb->dst;
		if (err == 0 && rt->u.dst.error)
			err = -rt->u.dst.error;
	} else {
		struct flowi fl = {
			.nl_u = {
				.ip4_u = {
					.daddr = dst,
					.saddr = src,
					.tos = rtm->rtm_tos,
				},
			},
			.oif = tb[RTA_OIF] ? nla_get_u32(tb[RTA_OIF]) : 0,
		};
		err = ip_route_output_key(&rt, &fl);
	}

	if (err)
		goto errout_free;

	skb->dst = &rt->u.dst;
	if (rtm->rtm_flags & RTM_F_NOTIFY)
		rt->rt_flags |= RTCF_NOTIFY;

	err = rt_fill_info(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
				RTM_NEWROUTE, 0, 0);
	if (err <= 0)
		goto errout_free;

	err = rtnl_unicast(skb, NETLINK_CB(in_skb).pid);
errout:
	return err;

errout_free:
	kfree_skb(skb);
	goto errout;
}

int ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb)
{
	struct rtable *rt;
	int h, s_h;
	int idx, s_idx;

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];
	for (h = 0; h <= rt_hash_mask; h++) {
		if (h < s_h) continue;
		if (h > s_h)
			s_idx = 0;
		rcu_read_lock_bh();
		for (rt = rcu_dereference(rt_hash_table[h].chain), idx = 0; rt;
		     rt = rcu_dereference(rt->u.rt_next), idx++) {
			if (idx < s_idx)
				continue;
			skb->dst = dst_clone(&rt->u.dst);
			if (rt_fill_info(skb, NETLINK_CB(cb->skb).pid,
					 cb->nlh->nlmsg_seq, RTM_NEWROUTE, 
					 1, NLM_F_MULTI) <= 0) {
				dst_release(xchg(&skb->dst, NULL));
				rcu_read_unlock_bh();
				goto done;
			}
			dst_release(xchg(&skb->dst, NULL));
		}
		rcu_read_unlock_bh();
	}

done:
	cb->args[0] = h;
	cb->args[1] = idx;
	return skb->len;
}

void ip_rt_multicast_event(struct in_device *in_dev)
{
	rt_cache_flush(0);
}

#ifdef CONFIG_SYSCTL
static int flush_delay;

static int ipv4_sysctl_rtcache_flush(ctl_table *ctl, int write,
					struct file *filp, void __user *buffer,
					size_t *lenp, loff_t *ppos)
{
	if (write) {
		proc_dointvec(ctl, write, filp, buffer, lenp, ppos);
		rt_cache_flush(flush_delay);
		return 0;
	} 

	return -EINVAL;
}

static int ipv4_sysctl_rtcache_flush_strategy(ctl_table *table,
						int __user *name,
						int nlen,
						void __user *oldval,
						size_t __user *oldlenp,
						void __user *newval,
						size_t newlen)
{
	int delay;
	if (newlen != sizeof(int))
		return -EINVAL;
	if (get_user(delay, (int __user *)newval))
		return -EFAULT; 
	rt_cache_flush(delay); 
	return 0;
}

ctl_table ipv4_route_table[] = {
        {
		.ctl_name 	= NET_IPV4_ROUTE_FLUSH,
		.procname	= "flush",
		.data		= &flush_delay,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= &ipv4_sysctl_rtcache_flush,
		.strategy	= &ipv4_sysctl_rtcache_flush_strategy,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_DELAY,
		.procname	= "min_delay",
		.data		= &ip_rt_min_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_DELAY,
		.procname	= "max_delay",
		.data		= &ip_rt_max_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_THRESH,
		.procname	= "gc_thresh",
		.data		= &ipv4_dst_ops.gc_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_SIZE,
		.procname	= "max_size",
		.data		= &ip_rt_max_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		/*  Deprecated. Use gc_min_interval_ms */
 
		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL,
		.procname	= "gc_min_interval",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS,
		.procname	= "gc_min_interval_ms",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_ms_jiffies,
		.strategy	= &sysctl_ms_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_TIMEOUT,
		.procname	= "gc_timeout",
		.data		= &ip_rt_gc_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_INTERVAL,
		.procname	= "gc_interval",
		.data		= &ip_rt_gc_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_LOAD,
		.procname	= "redirect_load",
		.data		= &ip_rt_redirect_load,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_NUMBER,
		.procname	= "redirect_number",
		.data		= &ip_rt_redirect_number,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_SILENCE,
		.procname	= "redirect_silence",
		.data		= &ip_rt_redirect_silence,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_COST,
		.procname	= "error_cost",
		.data		= &ip_rt_error_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_BURST,
		.procname	= "error_burst",
		.data		= &ip_rt_error_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_ELASTICITY,
		.procname	= "gc_elasticity",
		.data		= &ip_rt_gc_elasticity,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MTU_EXPIRES,
		.procname	= "mtu_expires",
		.data		= &ip_rt_mtu_expires,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_PMTU,
		.procname	= "min_pmtu",
		.data		= &ip_rt_min_pmtu,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_ADVMSS,
		.procname	= "min_adv_mss",
		.data		= &ip_rt_min_advmss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_SECRET_INTERVAL,
		.procname	= "secret_interval",
		.data		= &ip_rt_secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{ .ctl_name = 0 }
};
#endif

#ifdef CONFIG_NET_CLS_ROUTE
struct ip_rt_acct *ip_rt_acct;

/* This code sucks.  But you should have seen it before! --RR */

/* IP route accounting ptr for this logical cpu number. */
#define IP_RT_ACCT_CPU(i) (ip_rt_acct + i * 256)

#ifdef CONFIG_PROC_FS
static int ip_rt_acct_read(char *buffer, char **start, off_t offset,
			   int length, int *eof, void *data)
{
	unsigned int i;

	if ((offset & 3) || (length & 3))
		return -EIO;

	if (offset >= sizeof(struct ip_rt_acct) * 256) {
		*eof = 1;
		return 0;
	}

	if (offset + length >= sizeof(struct ip_rt_acct) * 256) {
		length = sizeof(struct ip_rt_acct) * 256 - offset;
		*eof = 1;
	}

	offset /= sizeof(u32);

	if (length > 0) {
		u32 *src = ((u32 *) IP_RT_ACCT_CPU(0)) + offset;
		u32 *dst = (u32 *) buffer;

		/* Copy first cpu. */
		*start = buffer;
		memcpy(dst, src, length);

		/* Add the other cpus in, one int at a time */
		for_each_possible_cpu(i) {
			unsigned int j;

			src = ((u32 *) IP_RT_ACCT_CPU(i)) + offset;

			for (j = 0; j < length/4; j++)
				dst[j] += src[j];
		}
	}
	return length;
}
#endif /* CONFIG_PROC_FS */
#endif /* CONFIG_NET_CLS_ROUTE */

static __initdata unsigned long rhash_entries;
static int __init set_rhash_entries(char *str)
{
	if (!str)
		return 0;
	rhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("rhash_entries=", set_rhash_entries);

// IPv4路由模块是由ip_rt_init()进行初始化的，该函数在系统启动时，被初始化IP模块的ip_init接口调用
int __init ip_rt_init(void)
{
	int rc = 0;

	// 初始化rt_hash_rnd：根据numberpages和jiffies初始化rt_hash_rnd
	// 在刷新路由缓存之后，会重新选择随机值来设置该值，这是路由缓存中表项分布
	// 算法的一个部分，使得表项不具有确定性，以防止DOS攻击
	rt_hash_rnd = (int) ((num_physpages ^ (num_physpages>>8)) ^
			     (jiffies ^ (jiffies >> 7)));

// 路由表的classifier标签相关
#ifdef CONFIG_NET_CLS_ROUTE
	{
	int order;
	for (order = 0;
	     (PAGE_SIZE << order) < 256 * sizeof(struct ip_rt_acct) * NR_CPUS; order++)
		/* NOTHING */;
	ip_rt_acct = (struct ip_rt_acct *)__get_free_pages(GFP_KERNEL, order);
	if (!ip_rt_acct)
		panic("IP: failed to allocate ip_rt_acct\n");
	memset(ip_rt_acct, 0, PAGE_SIZE << order);
	}
#endif

	// 创建用于分配路由缓存项的缓存池ipv4_dst_ops.kmem_cachep
	ipv4_dst_ops.kmem_cachep =
		kmem_cache_create("ip_dst_cache", sizeof(struct rtable), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	// 创建rt_hash_table散列表，用于存储路由缓存项。缓存容量依赖于主机
	// 可用的物理内存的大小，在创建的同时初始化rt_hash_mask和rt_hash_log
	// 分别表示散列表的容量（即散列桶的数量）和该容量以2为对数所得的值
	// 当一个值必须通过比特位数量来移位时这种做法通常很有用，内核指定的默认
	// 容量，可以被用户启动项rhash_entries覆盖
	rt_hash_table = (struct rt_hash_bucket *)
		alloc_large_system_hash("IP route cache",
					sizeof(struct rt_hash_bucket),
					rhash_entries,
					(num_physpages >= 128 * 1024) ?
					15 : 17,
					0,
					&rt_hash_log,
					&rt_hash_mask,
					0);
	memset(rt_hash_table, 0, (rt_hash_mask + 1) * sizeof(struct rt_hash_bucket));
	rt_hash_lock_init();

	// 确定由垃圾回收算法使用的gc_thresh门限值
	ipv4_dst_ops.gc_thresh = (rt_hash_mask + 1);
	ip_rt_max_size = (rt_hash_mask + 1) * 16;

	// 初始化网络设备IPv4相关的IP编址
	devinet_init();
	// 初始化路由表
	ip_fib_init();

	// 初始化用于刷新路由缓存的定时器rt_flush_timer和rt_secret_timer
	init_timer(&rt_flush_timer);
	rt_flush_timer.function = rt_run_flush;
	init_timer(&rt_periodic_timer);
	rt_periodic_timer.function = rt_check_expire;
	init_timer(&rt_secret_timer);
	rt_secret_timer.function = rt_secret_rebuild;

	/* All the timers, started at system startup tend
	   to synchronize. Perturb it a bit.
	 */
	// 初始化用于删除路由缓存中旧表项的定时器rt_periodic_timer
	rt_periodic_timer.expires = jiffies + net_random() % ip_rt_gc_interval +
					ip_rt_gc_interval;
	// 启动rt_periodic_timer定时器
	add_timer(&rt_periodic_timer);

	rt_secret_timer.expires = jiffies + net_random() % ip_rt_secret_interval +
		ip_rt_secret_interval;
	// 启动rt_secret_timer定时器
	add_timer(&rt_secret_timer);

#ifdef CONFIG_PROC_FS
	{
	struct proc_dir_entry *rtstat_pde = NULL; /* keep gcc happy */
	if (!proc_net_fops_create("rt_cache", S_IRUGO, &rt_cache_seq_fops) ||
	    !(rtstat_pde = create_proc_entry("rt_cache", S_IRUGO, 
			    		     proc_net_stat))) {
		return -ENOMEM;
	}
	rtstat_pde->proc_fops = &rt_cpu_seq_fops;
	}
#ifdef CONFIG_NET_CLS_ROUTE
	create_proc_read_entry("rt_acct", 0, proc_net, ip_rt_acct_read, NULL);
#endif
#endif
#ifdef CONFIG_XFRM
	xfrm_init();
	xfrm4_init();
#endif
	return rc;
}

EXPORT_SYMBOL(__ip_select_ident);
EXPORT_SYMBOL(ip_route_input);
EXPORT_SYMBOL(ip_route_output_key);
