#ifndef __NET_SCHED_GENERIC_H
#define __NET_SCHED_GENERIC_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <net/gen_stats.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;

struct qdisc_rate_table
{
	struct tc_ratespec rate;
	u32		data[256];
	struct qdisc_rate_table *next;
	int		refcnt;
};

struct Qdisc
{
	// 指向排队规则提供的enqueue操作接口
	int 			(*enqueue)(struct sk_buff *skb, struct Qdisc *dev);
	// 指向排队规则提供的dequeue操作接口
	struct sk_buff *	(*dequeue)(struct Qdisc *dev);
	// 排队规则的标志
	unsigned		flags;
// 标示排队规则是空的排队规则，在释放时不需要做过多的资源释放
#define TCQ_F_BUILTIN	1
// 标示排队规则正处于限制而延时出队的状态中
#define TCQ_F_THROTTLED	2
// 标示排队规则是输入排队规则
#define TCQ_F_INGRESS	4
	// 存储排队规则的内存需要32字节对齐
	int			padded;
	// 排队规则提供的操作接口
	struct Qdisc_ops	*ops;
	// 排队规则，类和过滤器都有一个32位的标示，称为句柄
	// 排队规则实例的标识分为主编号部分和副编号部分。主编号由用户分配，范围从0x0001到0x7FFF
	// 如果用户指定的主变号为0，那么内核将在0x8000和0xFFFF之间分配一个主编号
	// 除了输入根排队规则编号为FFFF:FFF1和输出根排队规则编号为FFFF:FFFF外，其他排队规则的
	// 副编号总为空。
	// 标识在单个网络设备的唯一的，但在多个网络设备之间可以重复
	u32			handle;
	// 父节点的句柄
	u32			parent;
	// 引用计数
	atomic_t		refcnt;
	// 队列中当前数据包数
	struct sk_buff_head	q;
	// 所属网络设备
	struct net_device	*dev;
	// 通过链接方式链接到所配置的网络设备上
	struct list_head	list;

	// 记录入队报文总字节数和入队报文总数
	struct gnet_stats_basic	bstats;
	// 记录队列相关的统计数据
	struct gnet_stats_queue	qstats;
	// 队列当前速率
	struct gnet_stats_rate_est	rate_est;
	// 信息统计操作自旋锁，防止多CPU并发
	spinlock_t		*stats_lock;
	// 通过本字段在没有对象再使用该排队规则时释放该排队规则
	struct rcu_head 	q_rcu;
	// 用于实现更复杂的流量控制机制，很少排队规则会实现此接口
	int			(*reshape_fail)(struct sk_buff *skb,
					struct Qdisc *q);

	/* This field is deprecated, but it is still used by CBQ
	 * and it will live until better solution will be invented.
	 */
	struct Qdisc		*__parent;
};

// Qdisc_class_ops结构用于类操作的接口，排队规则实现了分类就必须实现该接口
struct Qdisc_class_ops
{
	/* Child qdisc manipulation */
	// 将一个排队规则绑定到一个类，并返回先前绑定到这个类的排队规则
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **);
	// 获取当前绑定到所在类的排队规则
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);
	// 用于响应队列长度变化
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
	// 根据给定的类标识符从排队规则中查找对应的类，并引用该类，该类的引用计数递增1
	unsigned long		(*get)(struct Qdisc *, u32 classid);
	// 递减指定类的引用计数，如果引用计数为0，则删除释放此类
	void			(*put)(struct Qdisc *, unsigned long);
	// 用于变更指定类的参数，如果该类不存在则新建之
	int			(*change)(struct Qdisc *, u32, u32,
					struct rtattr **, unsigned long *);
	// 用于删除并释放指定的类。首先会递减该类的引用计数，然后如果引用技术递减为0，删除并释放之
	int			(*delete)(struct Qdisc *, unsigned long);
	// 遍历一个排队规则的所有类，取回实现了回调函数类的配置数据及统计信息
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);

	/* Filter manipulation */
	// 获取绑定到该类的过滤器所在链表的首节点
	struct tcf_proto **	(*tcf_chain)(struct Qdisc *, unsigned long);
	// 在一个过滤器正准备绑定到指定的类之前被调用，通过类标识获取类，首先递增类引用计数
	// 然后是其他一些检查
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid);
	// 在过滤完到指定的类后被调用，递减类引用技术
	void			(*unbind_tcf)(struct Qdisc *, unsigned long);

	/* rtnetlink specific */
	// 用于输出类的配置参数和统计数据
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

// Qdisc_ops结构用来描述队列操作的接口，每个排队规则都必须实现该接口
struct Qdisc_ops
{
	// 用于链接已注册的各种排队规则的操作接口
	struct Qdisc_ops	*next;
	// 所在规则提供的类操作接口
	struct Qdisc_class_ops	*cl_ops;
	// 内部使用的标识符，通常是排队规则名
	char			id[IFNAMSIZ];
	// 附属在排队规则上的私有信息块大小。该信息块通常与排队规则一起分配内存
	// 紧跟在排队规则之后，可由qdisc_priv()获取
	int			priv_size;

	// 将待输出数据包加入到排队规则中的函数
	// 返回值如下：
	// NET_XMIT_SUCCESS:报文被排队规则接收，成功入队
	// NET_XMIT_DROP:报文入队失败，被丢弃
	// NET_XMIT_CN:报文入队失败，由于拥塞而被丢弃，比如缓冲区溢出
	// NET_XMIT_POLICED:报文入队失败，由于限制机制检测到违背了某条规则而被丢弃，比如超出了允许的速率
	// NET_XMIT_BYPASS:报文排队规则接收，成功入队，但是它将不通过正常的dequeue()离开排队规则
	int 			(*enqueue)(struct sk_buff *, struct Qdisc *);
	// 数据包从指定的排队规则队列中出队函数，返回值指向下一个可能被发送的报文
	// 当返回值为NULL时，有可能排队规则队列中已不再有等待的报文，或者是没有预备好发送的数据包
	// 当一个排队规则存在多个队列时，等待报文总数Qdisc->q.qlen必须是有效的
	struct sk_buff *	(*dequeue)(struct Qdisc *);
	// 将先前出队的报文重新排入到队列中的函数，不同于enqueue()的是，重新入队的报文需要被放置到
	// 它出队前在排队规则队列中所处的位置上
	int 			(*requeue)(struct sk_buff *, struct Qdisc *);
	// 从队列中移除并丢弃一个报文的函数
	unsigned int		(*drop)(struct Qdisc *);

	// 初始化新实例化的排队规则的函数
	int			(*init)(struct Qdisc *, struct rtattr *arg);
	// 重置排队规则函数，虚完成清空队列，重置计数器，删除定时器等。如果所属排队规则内部还有其他的排队规则
	// 那么它们的reset()也会被地柜调用
	void			(*reset)(struct Qdisc *);
	// 用于释放排队规则在初始化和运行时申请资源的函数
	void			(*destroy)(struct Qdisc *);
	// 用来改变排队规则参数的函数
	int			(*change)(struct Qdisc *, struct rtattr *arg);

	// 用于输出排队规则的配置参数和统计数据的函数
	int			(*dump)(struct Qdisc *, struct sk_buff *);
	int			(*dump_stats)(struct Qdisc *, struct gnet_dump *);

	struct module		*owner;
};


struct tcf_result
{
	unsigned long	class;
	u32		classid;
};

// 如果排队规则实现了分类，则必须使用过滤器来分类
struct tcf_proto_ops
{
	// 将已注册的过滤器链接到tcf_proto_base链表上
	struct tcf_proto_ops	*next;
	// 过滤器标识符，通常是过滤器名
	char			kind[IFNAMSIZ];

	// 报文分类函数，返回值为
	int			(*classify)(struct sk_buff*, struct tcf_proto*,
					struct tcf_result *);
	// 过滤器初始化函数，通常在创建过滤器后被调用
	int			(*init)(struct tcf_proto*);
	// 删除并释放过滤器函数
	void			(*destroy)(struct tcf_proto*);

	// 将一个过滤器元素的句柄映射到一个内部过滤器标识符，实际上是一个过滤器实例指针，并将其返回
	unsigned long		(*get)(struct tcf_proto*, u32 handle);
	void			(*put)(struct tcf_proto*, unsigned long);
	// 配置一个新过滤器或者变更一个已经存在的过滤器配置
	int			(*change)(struct tcf_proto*, unsigned long,
					u32 handle, struct rtattr **,
					unsigned long *);

	// 删除一个过滤器的某个函数
	int			(*delete)(struct tcf_proto*, unsigned long);
	// 遍历所有的元素并且调用回调函数取得配置数据和统计数据
	void			(*walk)(struct tcf_proto*, struct tcf_walker *arg);

	/* rtnetlink specific */
	// 用于输出过滤器或过滤器元素的配置参数统计数据
	int			(*dump)(struct tcf_proto*, unsigned long,
					struct sk_buff *skb, struct tcmsg*);

	struct module		*owner;
};

// 过滤器在逻辑上是独立于类的，在排队规则中入队的报文其所属的类是由过滤器决定的
// 通过过滤器，将入队的报文根据条件分配到符合条件的类中
struct tcf_proto
{
	/* Fast access part */
	struct tcf_proto	*next;
	void			*root;
	int			(*classify)(struct sk_buff*, struct tcf_proto*,
					struct tcf_result *);
	// 进行报文过滤的网络层协议号，用的最多的是IP协议，即ETH_P_IP
	__be16			protocol;

	/* All the rest */
	// 优先级，用来对于同一个协议的过滤器进行排序，按prio从小到大的次序遍历
	u32			prio;
	// 父排队规则的类标识符
	u32			classid;
	// 父排队规则
	struct Qdisc		*q;
	// 存储与特定过滤器相关的数据
	void			*data;
	// 过滤器对应的操作接口
	struct tcf_proto_ops	*ops;
};


extern void qdisc_lock_tree(struct net_device *dev);
extern void qdisc_unlock_tree(struct net_device *dev);

#define sch_tree_lock(q)	qdisc_lock_tree((q)->dev)
#define sch_tree_unlock(q)	qdisc_unlock_tree((q)->dev)
#define tcf_tree_lock(tp)	qdisc_lock_tree((tp)->q->dev)
#define tcf_tree_unlock(tp)	qdisc_unlock_tree((tp)->q->dev)

extern struct Qdisc noop_qdisc;
extern struct Qdisc_ops noop_qdisc_ops;

extern void dev_init_scheduler(struct net_device *dev);
extern void dev_shutdown(struct net_device *dev);
extern void dev_activate(struct net_device *dev);
extern void dev_deactivate(struct net_device *dev);
extern void qdisc_reset(struct Qdisc *qdisc);
extern void qdisc_destroy(struct Qdisc *qdisc);
extern void qdisc_tree_decrease_qlen(struct Qdisc *qdisc, unsigned int n);
extern struct Qdisc *qdisc_alloc(struct net_device *dev, struct Qdisc_ops *ops);
extern struct Qdisc *qdisc_create_dflt(struct net_device *dev,
				       struct Qdisc_ops *ops, u32 parentid);

static inline void
tcf_destroy(struct tcf_proto *tp)
{
	tp->ops->destroy(tp);
	module_put(tp->ops->owner);
	kfree(tp);
}

static inline int __qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	__skb_queue_tail(list, skb);
	sch->qstats.backlog += skb->len;
	sch->bstats.bytes += skb->len;
	sch->bstats.packets++;

	return NET_XMIT_SUCCESS;
}

static inline int qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch)
{
	return __qdisc_enqueue_tail(skb, sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_head(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue(list);

	if (likely(skb != NULL))
		sch->qstats.backlog -= skb->len;

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_head(struct Qdisc *sch)
{
	return __qdisc_dequeue_head(sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_tail(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue_tail(list);

	if (likely(skb != NULL))
		sch->qstats.backlog -= skb->len;

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_tail(struct Qdisc *sch)
{
	return __qdisc_dequeue_tail(sch, &sch->q);
}

static inline int __qdisc_requeue(struct sk_buff *skb, struct Qdisc *sch,
				  struct sk_buff_head *list)
{
	__skb_queue_head(list, skb);
	sch->qstats.backlog += skb->len;
	sch->qstats.requeues++;

	return NET_XMIT_SUCCESS;
}

static inline int qdisc_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
	return __qdisc_requeue(skb, sch, &sch->q);
}

static inline void __qdisc_reset_queue(struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	/*
	 * We do not know the backlog in bytes of this list, it
	 * is up to the caller to correct it
	 */
	skb_queue_purge(list);
}

static inline void qdisc_reset_queue(struct Qdisc *sch)
{
	__qdisc_reset_queue(sch, &sch->q);
	sch->qstats.backlog = 0;
}

static inline unsigned int __qdisc_queue_drop(struct Qdisc *sch,
					      struct sk_buff_head *list)
{
	struct sk_buff *skb = __qdisc_dequeue_tail(sch, list);

	if (likely(skb != NULL)) {
		unsigned int len = skb->len;
		kfree_skb(skb);
		return len;
	}

	return 0;
}

static inline unsigned int qdisc_queue_drop(struct Qdisc *sch)
{
	return __qdisc_queue_drop(sch, &sch->q);
}

static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch)
{
	kfree_skb(skb);
	sch->qstats.drops++;

	return NET_XMIT_DROP;
}

static inline int qdisc_reshape_fail(struct sk_buff *skb, struct Qdisc *sch)
{
	sch->qstats.drops++;

#ifdef CONFIG_NET_CLS_POLICE
	if (sch->reshape_fail == NULL || sch->reshape_fail(skb, sch))
		goto drop;

	return NET_XMIT_SUCCESS;

drop:
#endif
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

#endif
