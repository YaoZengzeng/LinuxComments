#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>

// 定时器状态，表示邻居项在此类状态下设置一个定时器
#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
// 有效状态，表示在这些状态下该邻居项是有效的 
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
// 连接状态，在这些状态下可以直接发送数据包给该邻居 
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

// 邻居协议参数配置块，用于存储可调解的邻居协议参数，一个邻居协议对应一个参数配置块
// 而每个网络设备的IPv4的配置块中也存在一个存放默认值的邻居配置块
struct neigh_parms
{
	// 指向该neigh_parms实例所对应的网络设备，在通过neigh_parms_alloc()创建
	// neigh_parms实例时设置
	struct net_device *dev;
	// 通过next将属于同一个协议族的所有neigh_parms实例链接在一起，每个neigh_table实例
	// 都有各自的neigh_parms队列
	struct neigh_parms *next;
	// 提供给那些仍在使用老式接口设备的初始化和销毁接口，net_device结构中也有一个neigh_setup
	// 成员函数指针，不要与之混淆
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_destructor)(struct neighbour *);
	// 指向该neigh_parms实例所属的邻居表
	struct neigh_table *tbl;

	// 邻居表的sysctl表，对ARP是在ARP模块初始化函数arp_init()中对其初始化的，这样用户可以通过
	// proc文件系统来读写邻居表的参数
	void	*sysctl_table;

	// 该字段值如果为1，则该邻居参数实例正在被删除，不能使用，也不能再创建对应网络设备的邻居项
	// 例如，在网络设备禁用时调用neigh_parms_release()设置
	int dead;
	atomic_t refcnt;
	// 为控制同步访问而设置的参数
	struct rcu_head rcu_head;

	// base_reachable_time为计算reachable_time的基准值；而reachable_time为NUD_REACHABLE
	// 状态超时时间，该值为随机值，介于base_reachable_time和1.5倍的base_reachable_time之间
	// 通常每300s在neigh_periodic_timer()中更新
	int	base_reachable_time;
	// 用于重传ARP请求报文的超时时间，主机在输出一个ARP请求报文之后的retrans_time个jiffies内
	// 如果没有接收到应答报文，则会重新输出一个新的ARP请求报文
	int	retrans_time;
	// 一个邻居项如果持续闲置（没有被使用）时间达到gc_staletime，且没有被引用，则会将被删除
	int	gc_staletime;
	// 邻居项维持在NUD_DELAY状态delay_probe_time之后进入NUD_PROBE状态，或者，处于NUD_REACHABLE
	// 状态的邻居项闲置时间超过delay_probe_time后，直接进入NUD_DELAY状态
	int	reachable_time;
	int	delay_probe_time;

	// proxy_queue队列长度
	int	queue_len;
	// 发送并确认可达的单播ARP请求报文数目
	int	ucast_probes;
	// 地址解析时，应用程序(通常是arpd)可发送ARP请求报文的数目
	int	app_probes;
	// 为了解析一个邻居地址，可发送的广播ARP请求报文数目，需要注意的是app_probes和mcast_probes
	// 之间是互斥的，ARP发送的是多播报文，而非广播报文
	int	mcast_probes;
	// 未使用
	int	anycast_delay;
	// 处理代理请求报文可延时的时间
	int	proxy_delay;
	// proxy_queue队列的长度上限
	int	proxy_qlen;
	// 当邻居项最近两次更新的时间间隔小于该值时，用覆盖的方式来更新邻居项，例如，当有多个在同一
	// 网段的代理ARP服务器答复对相同地址的查询
	int	locktime;
};

// neigh_statistics结构用来存储统计信息，一个该结构实例对应一个网络设备上的一种邻居协议
struct neigh_statistics
{
	// 记录已分配的neighbour结构实例总数，包括已释放的实例
	unsigned long allocs;		/* number of allocated neighs */
	// 在neigh_destroy()中删除的邻居项总数
	unsigned long destroys;		/* number of destroyed neighs */
	// 扩容hash_buckets散列表的次数
	unsigned long hash_grows;	/* number of hash resizes */

	// 尝试解析一个邻居地址的失败次数，这并不是发送ARP请求报文的次数，而是对于一个邻居来说
	// 在neigh_timer_handler()中所有尝试都失败之后才进行计数
	unsigned long res_failed;	/* nomber of failed resolutions */

	// 调用neigh_lookup()的总次数
	unsigned long lookups;		/* number of lookups */
	// 调用neigh_lookup()成功返回总次数
	unsigned long hits;		/* number of hits (among lookups) */

	// IPv6分别用来标识接收到发往组播或单播地址的ARP请求报文总数
	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	// 分别记录调用neigh_periodic_timer()或neigh_forced_gc()的次数
	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

// 邻居项使用neighbour结构来描述，该结构存储了邻居的相关信息，包括状态、二层和三层协议地址
// 提供给三层协议的函数指针，还有定时器和缓存的二层首部，需要注意的是，一个邻居并不代表一个主机
// 而是一个三层协议地址，对于配置了多接口的主机，一个主机将对应多个三层地址	
struct neighbour
{
	// 通过next把邻居项插入到散列表桶链表上，总在桶的前部插入新的邻居项
	struct neighbour	*next;
	// 指向相关协议的neigh_table结构实例，即该邻居项所在的邻居表，如果该邻居项对应的是一个IPv4
	// 地址，则该字段指向arp_tbl
	struct neigh_table	*tbl;
	// 用于调解邻居协议的参数，在创建邻居项函数neigh_create()中，首先调用neigh_alloc()分配一个
	// 邻居项，在该函数中使用邻居表的parms对该邻居项的该字段进行初始化，接着neigh_create()调用
	// 邻居表的constructor()，对于arp_tbl是arp_constructor()，对邻居项作特定的设置时将该字段
	// 修改为协议相关设备的参数
	struct neigh_parms	*parms;
	// 通过此网络设备可访问到该邻居，对于每个邻居来说，只能有一个可用来访问该邻居的设备
	struct net_device		*dev;
	// 最近一次被使用的时间，该字段并不总是与数据传输同步更新，当邻居不处于NUD_CONNECTED状态时，
	// 该值在neigh_event_send()更新中；当邻居项处于NUD_CONNECTED状态时，该值有时会通过gc_timer
	// 定时器处理函数更新
	unsigned long		used;
	// 记录最近一次确定该邻居可达性的时间，用于描述邻居的可达性，通常是接收到来自该邻居的报文后更新
	// 传输层通过neigh_confirm()来更新，邻居子系统则通过neigh_update()更新
	unsigned long		confirmed;
	// 记录最近一次被neigh_update()更新的时间，updated和confirmed各自针对不同的特性，该字段值在
	// 邻居状态发生变化时更新
	unsigned long		updated;
	// 记录邻居项的一些标志和特性
	// NTF_ROUTER:此标志只使用于IPv6，标识该邻居项为一个路由器
	__u8			flags;
	// 标识邻居项的状态
	__u8			nud_state;
	// 邻居项地址的类型，对于ARP，是在创建邻居项时arp_constructor()中设置的，该类型与路由表项类型
	// 意义相同，最经常使用的类型如RTN_UNICAST、RTN_LOCAL、RTN_BROADCAST、RTN_ANYCAST和RTN_MULTICAST
	__u8			type;
	// 生存标志，如果该值设置为1，则意味着该邻居项正在被删除，最终通过垃圾回收将其删除
	__u8			dead;
	// 尝试发送请求报文而未能得到应答的次数，该值在定时器处理函数中被检测，当该值达到指定的上限时
	// 该邻居项便进入NUD_FAILED状态
	atomic_t		probes;
	// 用来控制访问邻居项的读写锁
	rwlock_t		lock;
	// 与存储在primary_key中的三层协议地址相对应的二进制二层硬件地址，以太网地址长度为6B
	// 而其他链路层协议地址也许会更长，到哪通常不会超过32B，因此该数组长度设定为MAX_ADDR_LEN
	// 即32
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	// 指向缓存的二层协议首部hh_cache结构实例链表
	struct hh_cache		*hh;
	// 引用计数
	atomic_t		refcnt;
	// 输出函数，用来将该报文输出到该邻居，在邻居项的整个生命周期中，由于其状态是不断变化的
	// 从而导致该函数指针会指向不同的邻居输出函数，例如，当该邻居可达时会调用neigh_connect()
	// 将output设置为neigh_ops->connected_output
	int			(*output)(struct sk_buff *skb);
	// 当邻居项状态处于无效时，用来缓存要发送的报文，如当邻居项处于NUD_INCOMPLETE状态时，发送
	// 第一个报文需要新的邻居项，调用neigh_resolve_output()，要发送的报文被缓存到arp_queue
	// 队列中，在该邻居可达后，再从arp_queue队列中取出报文输出到该邻居
	struct sk_buff_head	arp_queue;
	// 用来管理多种超时情况的定时器
	struct timer_list	timer;
	// 指向邻居项函数指针表实例，每一种邻居协议都提供3到4中不同的邻居项函数指针表，实际用哪一种
	// 还需要根据三层协议地址的类型、网络设备的类型等
	struct neigh_ops	*ops;
	// 存储哈希函数使用的三层协议地址，该实际使用空间是根据三层协议地址长度动态分配的
	// 例如，IPv4为32位目标IP地址
	u8			primary_key[0];
};

// 邻居项函数指针表由在邻居的生存周期中不同时期被调用的多个函数指针组成，其中有多个函数指针是实现
// 三层(IPv4中的IP层)与dev_queue_xmit()之间的调用桥梁，适用于不同的状态
struct neigh_ops
{
	// 标识所属的地址族，比如ARP为AF_INET等
	int			family;
	// 发送请求报文函数，在发送第一个报文时，需要新的邻居项，发送报文被缓存到arp_queue队列中
	// 然后会调用solicit()发送请求报文
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	// 当邻居项缓存着未发送的报文，而该邻居项又不可达时，被调用来向三层报告错误的函数
	// ARP中为arp_error_report()，最终会给报文发送方发送一个主机不可达的ICMP差错报文
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	// 最通用的输出函数，可用于所有情况，此输出函数实现了完整的输出过程，因此存在较多的
	// 校验与操作，以确保报文的输出，因此该函数相对较消耗资源，此外，不要将neigh_ops->output()
	// 和neighbour->output()混淆
	int			(*output)(struct sk_buff*);
	// 在确定邻居可达时，即状态为NUD_CONNECTED时使用的输出函数，由于所有输出所需要的信息都已经具备
	// 因此该函数只是简单地添加二层首部，因此比output()快得多
	int			(*connected_output)(struct sk_buff*);
	// 在已缓存了二层首部的情况下使用的输出函数
	int			(*hh_output)(struct sk_buff*);
	// 实际上，以上几个输出接口，除了hh_output外，并不真正传输数据报，只是在准备好二层首部之后，
	// 调用queue_xmit接口
	int			(*queue_xmit)(struct sk_buff*);
};

// pneigh_entry结构实例用来保存允许代理的条件，只有和结构中的接收设备以及目标地址相匹配
// 才能代理，所有penigh_entry实例都存储在邻居表的phash_buckets散列表中，称之为代理项
// 可通过ip neigh add proxy命令添加
struct pneigh_entry
{
	// 将pneigh_entry结构实例链接到phash_buckets散列表的一个桶内
	struct pneigh_entry	*next;
	// 通过该网络设备接收到的ARP请求报文才能被代理
	struct net_device		*dev;
	// 标志
	// NTF_PROXY:代理表项标志，用ip命令在代理的邻居时会添加此标志
	// 比如ip neigh add proxy 10.0.0.4 dev eth0
	u8			flags;
	// 存储三层协议地址，存储空间根据neigh_table结构的key_len字段分配，只有目标地址和
	// 该三层协议地址匹配的ARP请求报文才能处理
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

// neigh_table结构用来存储与邻居协议相关的参数、功能函数，以及邻居项散列表
// 一个neigh_table结构实例对应一个邻居协议，所有的实例都连接在全局链表neigh_tables
// 对于ARP协议，其neigh_table结构实例是arp_tbl 
struct neigh_table
{
	// 用来连接在neigh_tables中，该链表中除了ARP的arp_tbl，还有IPV6T和DECNE所使用
	// 邻居协议的邻居表实例nd_tbl和dn_neigh_table等
	struct neigh_table	*next;
	// 邻居项所属的地址族，ARP为AF_INET
	int			family;
	// 邻居项结构的大小，对arp_tbl来说，初始化为sizeof(neighbour)+4，这是因为在ARP中
	// neighbour结构的最后一个成员零长度数组primary_key，实际指向一个IPv4地址，因此其中
	// 的4是一个IPv4地址的长度
	int			entry_size;
	// 哈希函数所使用的key的长度，实际上哈希函数使用的key是第三层协议地址，因此在IPv4中的
	// key就是IP地址，因此这个值就是4
	int			key_len;
	// 哈希函数，用来计算哈希值，ARP中为arp_hash()
	__u32			(*hash)(const void *pkey, const struct net_device *);
	// 邻居表项初始化函数，用于初始化一个新的neighbour结构实例中与协议相关的字段
	// 在ARP中，该函数为arp_constructor()，由邻居表项创建函数neigh_create()中调用
	int			(*constructor)(struct neighbour *);
	// 这两个函数分别在创建和释放一个代理项时被调用，IPv4并没有使用，只在IPv6中被使用
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	// 用来处理在neigh_table->proxy_queue缓存队列中的代理ARP报文
	void			(*proxy_redo)(struct sk_buff *skb);
	// 用来分配neighbour结构实例的缓冲池名字符串，arp_tlb的该字段为"arp_cache"
	char			*id;
	// 存储一些与协议相关的可调节参数，如重传超时时间，proxy_queue队列长度等
	struct neigh_parms	parms;
	/* HACK. gc_* shoul follow parms without a gap! */
	// 垃圾回收时钟gc_timer的到期间隔时间，每当该时钟到期即触发一次垃圾回收，该字段初始值为30s
	int			gc_interval;
	// 如果缓存池中的邻居项数少于gc_thresh1，则不会执行垃圾回收
	int			gc_thresh1;
	// 如果邻居项数目超过gc_thresh2，则在新建邻居项时若超过五秒未刷新，必须立即刷新并强制垃圾回收
	int			gc_thresh2;
	// 如果邻居项数目超过gc_thresh3，则在新建邻居项时，必须立即刷新并强制垃圾回收
	int			gc_thresh3;
	// 记录最近一次调用neigh_forced_gc()强制刷新邻居表的时间，用来作为是否进行垃圾回收的判断条件
	unsigned long		last_flush;
	// 垃圾回收定时器
	struct timer_list 	gc_timer;
	// 处理proxy_queue队列的定时器，当proxy_queue队列为空，第一个ARP报文加入到队列就会启动该定时器
	// 该定时器在neigh_table_init()中初始化，处理例程为neigh_proxy_process()
	struct timer_list 	proxy_timer;
	// 对于接收到的需要进行处理的ARP报文，会先将其缓存到proxy_queue队列中，在定时器处理函数中再对
	// 其进行处理
	struct sk_buff_head	proxy_queue;
	// 整个表中邻居项的数目，在用neigh_alloc()创建和用neigh_destroy()释放邻居项时计数
	atomic_t		entries;
	// 用来控制邻居表的读写锁，例如neigh_lookup()只需要读邻居表，而neigh_periodic_timer()则需要
	// 读写邻居表
	rwlock_t		lock;
	// 用于记录neigh_parms结构中reachable_time成员最近一次被更新的时间
	unsigned long		last_rand;
	// 用来分配neighbour结构实例的slab缓存，在neigh_table_init()中初始化
	struct kmem_cache		*kmem_cachep;
	// 有关邻居表中邻居项的各类统计数据
	struct neigh_statistics	*stats;
	// 用于存储邻居表项的散列表，该散列表在分配邻居项时，如果邻居项数超过散列表容量，可以动态扩容
	struct neighbour	**hash_buckets;
	// 邻居项散列表桶数减1，以方便用来计算关键字
	unsigned int		hash_mask;
	// 随机数，用来在hash_buckets散列表扩容时计算关键字，以免受到ARP攻击
	__u32			hash_rnd;
	// 保存下一次将进行垃圾回收处理的桶序号，如果超过最大值hash_mash则从散列表的第一个桶开始
	unsigned int		hash_chain_gc;
	// 存储ARP代理三层协议地址的散列表，在neigh_table_init_no_netlink()中完成初始化
	struct pneigh_entry	**phash_buckets;
#ifdef CONFIG_PROC_FS
	// 如果支持proc文件系统，则用来在/proc/net/stat/下注册arp_cache文件，在neigh_table_init_no_netlink()
	// 中完成注册
	struct proc_dir_entry	*pde;
#endif
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);
extern void			neigh_parms_destroy(struct neigh_parms *parms);
extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, const void *key, struct net_device *dev, int creat);
extern int			pneigh_delete(struct neigh_table *tbl, const void *key, struct net_device *dev);

struct netlink_callback;
struct nlmsghdr;
extern int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern void neigh_app_ns(struct neighbour *n);

extern int neightbl_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neightbl_set(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);

extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler,
						      ctl_handler *strategy);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_is_connected(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_CONNECTED;
}

static inline int neigh_is_valid(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_VALID;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

// __neigh_lookup()在查找失败并允许创建新的邻居项时，根据查找条件创建新邻居项
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

// __neigh_lookup_errno()则是查找失败直接创建新邻居项
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
