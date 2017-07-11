/*
 * net/sched/sch_generic.c	Generic packet scheduler routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *              Jamal Hadi Salim, <hadi@cyberus.ca> 990601
 *              - Ingress support
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/pkt_sched.h>

/* Main transmission queue. */

/* Main qdisc structure lock. 

   However, modifications
   to data, participating in scheduling must be additionally
   protected with dev->queue_lock spinlock.

   The idea is the following:
   - enqueue, dequeue are serialized via top level device
     spinlock dev->queue_lock.
   - tree walking is protected by read_lock(qdisc_tree_lock)
     and this lock is used only in process context.
   - updates to tree are made only under rtnl semaphore,
     hence this lock may be made without local bh disabling.

   qdisc_tree_lock must be grabbed BEFORE dev->queue_lock!
 */
DEFINE_RWLOCK(qdisc_tree_lock);

void qdisc_lock_tree(struct net_device *dev)
{
	write_lock(&qdisc_tree_lock);
	spin_lock_bh(&dev->queue_lock);
}

void qdisc_unlock_tree(struct net_device *dev)
{
	spin_unlock_bh(&dev->queue_lock);
	write_unlock(&qdisc_tree_lock);
}

/* 
   dev->queue_lock serializes queue accesses for this device
   AND dev->qdisc pointer itself.

   netif_tx_lock serializes accesses to device driver.

   dev->queue_lock and netif_tx_lock are mutually exclusive,
   if one is grabbed, another must be free.
 */


/* Kick device.
   Note, that this procedure can be called by a watchdog timer, so that
   we do not check dev->tbusy flag here.

   Returns:  0  - queue is empty.
            >0  - queue is not empty, but throttled.// 由于网络设备拥塞导致发送失败而需等待下次发送
	    <0  - queue is not empty. Device is throttled, if dev->tbusy != 0.

   NOTE: Called under dev->queue_lock with locally disabled BH.
*/
// qdisc_restart()的主要作用是从排队规则中获取一个可以输出的报文，然后将其输出到网络设备
static inline int qdisc_restart(struct net_device *dev)
{
	struct Qdisc *q = dev->qdisc;
	struct sk_buff *skb;

	/* Dequeue packet */
	// 如果还有上次没发送完的GSO数据包，则将其取出，否则从排队规则的队列中取出待输出的数据包
	if (((skb = dev->gso_skb)) || ((skb = q->dequeue(q)))) {
		// 获取网络设备输出数据包时是否需要上锁的标志
		unsigned nolock = (dev->features & NETIF_F_LLTX);

		dev->gso_skb = NULL;

		/*
		 * When the driver has LLTX set it does its own locking
		 * in start_xmit. No need to add additional overhead by
		 * locking again. These checks are worth it because
		 * even uncongested locks can be quite expensive.
		 * The driver can do trylock like here too, in case
		 * of lock congestion it should return -1 and the packet
		 * will be requeued.
		 */
		if (!nolock) {
			// 如果输出网络设备设置了输出数据包时需要上锁的标志，则调用netif_tx_trylock()上锁
			if (!netif_tx_trylock(dev)) {
			collision:
				/* So, someone grabbed the driver. */
				
				/* It may be transient configuration error,
				   when hard_start_xmit() recurses. We detect
				   it by checking xmit owner and drop the
				   packet when deadloop is detected.
				*/
				// 如果正在通过该网络设备发送数据包的CPU是当前CPU，则说明代码有bug，
				// 需要提示并释放待输出的数据包
				if (dev->xmit_lock_owner == smp_processor_id()) {
					kfree_skb(skb);
					if (net_ratelimit())
						printk(KERN_DEBUG "Dead loop on netdevice %s, fix it urgently!\n", dev->name);
					return -1;
				}
				// 其他情况（如由于其他CPU的锁定等）则统计相应数据后，将报文缓存起来或重新排入队列
				__get_cpu_var(netdev_rx_stat).cpu_collision++;
				goto requeue;
			}
		}
		
		{
			/* And release queue */
			spin_unlock(&dev->queue_lock);

			if (!netif_queue_stopped(dev)) {
				int ret;

				// 将数据包从输出网络设备中输出
				ret = dev_hard_start_xmit(skb, dev);
				if (ret == NETDEV_TX_OK) { 
					if (!nolock) {
						netif_tx_unlock(dev);
					}
					spin_lock(&dev->queue_lock);
					// 输出成功则返回-1，表示队列中还有数据包等待发送
					return -1;
				}
				// 如果由于输出锁已上锁而发送失败，且输出数据包时无需上锁
				// 则跳转到collision标签处处理，或者是代码有bug，或者是
				// 由于其他CPU锁定而需等待
				if (ret == NETDEV_TX_LOCKED && nolock) {
					spin_lock(&dev->queue_lock);
					goto collision; 
				}
			}

			/* NETDEV_TX_BUSY - we need to requeue */
			/* Release the driver */
			// 如果由于缓存不够，网络设备硬件错误等原因而关闭排队功能
			// 则获取网络设备当前使用的排队规则
			if (!nolock) { 
				netif_tx_unlock(dev);
			} 
			spin_lock(&dev->queue_lock);
			q = dev->qdisc;
		}

		/* Device kicked us out :(
		   This is possible in three cases:

		   0. driver is locked
		   1. fastroute is enabled
		   2. device cannot determine busy state
		      before start of transmission (f.e. dialout)
		   3. device is buggy (ppp)
		 */

requeue:
		// 将由于其他CPU锁定而不能输出的GSO数据包缓存到输出网络设备上
		if (skb->next)
			dev->gso_skb = skb;
		else
		// 而其他数据包则重新排入队列
			q->ops->requeue(skb, q);
		// 再次调度数据包输出软中断，进行下一次数据包的输出
		netif_schedule(dev);
		return 1;
	}
	BUG_ON((int) q->q.qlen < 0);
	return q->q.qlen;
}

// 真正实现调度数据包输出软中断的是__qdisc_run()
void __qdisc_run(struct net_device *dev)
{
	// 如果输出网络设备的排队规则还处于初始状态，则没必要调度数据包输出软中断
	// 退出流量控制调度队列过程状态
	if (unlikely(dev->qdisc == &noop_qdisc))
		goto out;

	// 调用qdisc_restart()进行发送，直到发送完毕或网络设备为停止状态为止
	while (qdisc_restart(dev) < 0 && !netif_queue_stopped(dev))
		/* NOTHING */;

out:
	// 如果输出网络设备没有设置排队规则，则退出流量控制调度队列过程状态
	clear_bit(__LINK_STATE_QDISC_RUNNING, &dev->state);
}

static void dev_watchdog(unsigned long arg)
{
	struct net_device *dev = (struct net_device *)arg;

	netif_tx_lock(dev);
	if (dev->qdisc != &noop_qdisc) {
		if (netif_device_present(dev) &&
		    netif_running(dev) &&
		    netif_carrier_ok(dev)) {
			if (netif_queue_stopped(dev) &&
			    time_after(jiffies, dev->trans_start + dev->watchdog_timeo)) {

				printk(KERN_INFO "NETDEV WATCHDOG: %s: transmit timed out\n",
				       dev->name);
				dev->tx_timeout(dev);
			}
			if (!mod_timer(&dev->watchdog_timer, jiffies + dev->watchdog_timeo))
				dev_hold(dev);
		}
	}
	netif_tx_unlock(dev);

	dev_put(dev);
}

static void dev_watchdog_init(struct net_device *dev)
{
	init_timer(&dev->watchdog_timer);
	dev->watchdog_timer.data = (unsigned long)dev;
	dev->watchdog_timer.function = dev_watchdog;
}

void __netdev_watchdog_up(struct net_device *dev)
{
	if (dev->tx_timeout) {
		if (dev->watchdog_timeo <= 0)
			dev->watchdog_timeo = 5*HZ;
		if (!mod_timer(&dev->watchdog_timer, jiffies + dev->watchdog_timeo))
			dev_hold(dev);
	}
}

static void dev_watchdog_up(struct net_device *dev)
{
	__netdev_watchdog_up(dev);
}

static void dev_watchdog_down(struct net_device *dev)
{
	netif_tx_lock_bh(dev);
	if (del_timer(&dev->watchdog_timer))
		dev_put(dev);
	netif_tx_unlock_bh(dev);
}

// 网络设备会定时地侦测网络设备是否处于可传递状态，当状态发生彼岸花时，会调用netif_carrier_on()
// 或netif_carrier_off来通知内核。从网络设备插拔网线或网线另一端的设备（hub，网桥，路由器）关闭
// 或禁止，都会导致连接状态的改变
void netif_carrier_on(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_NOCARRIER, &dev->state))
		// 生成一个连接状态改变事件
		linkwatch_fire_event(dev);
	if (netif_running(dev))
		__netdev_watchdog_up(dev);
}

void netif_carrier_off(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_NOCARRIER, &dev->state))
		linkwatch_fire_event(dev);
}

/* "NOOP" scheduler: the best scheduler, recommended for all interfaces
   under all circumstances. It is difficult to invent anything faster or
   cheaper.
 */

static int noop_enqueue(struct sk_buff *skb, struct Qdisc * qdisc)
{
	kfree_skb(skb);
	return NET_XMIT_CN;
}

static struct sk_buff *noop_dequeue(struct Qdisc * qdisc)
{
	return NULL;
}

static int noop_requeue(struct sk_buff *skb, struct Qdisc* qdisc)
{
	if (net_ratelimit())
		printk(KERN_DEBUG "%s deferred output. It is buggy.\n",
		       skb->dev->name);
	kfree_skb(skb);
	return NET_XMIT_CN;
}

struct Qdisc_ops noop_qdisc_ops = {
	.id		=	"noop",
	.priv_size	=	0,
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.requeue	=	noop_requeue,
	.owner		=	THIS_MODULE,
};

struct Qdisc noop_qdisc = {
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.flags		=	TCQ_F_BUILTIN,
	.ops		=	&noop_qdisc_ops,	
	.list		=	LIST_HEAD_INIT(noop_qdisc.list),
};

static struct Qdisc_ops noqueue_qdisc_ops = {
	.id		=	"noqueue",
	.priv_size	=	0,
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.requeue	=	noop_requeue,
	.owner		=	THIS_MODULE,
};

static struct Qdisc noqueue_qdisc = {
	.enqueue	=	NULL,
	.dequeue	=	noop_dequeue,
	.flags		=	TCQ_F_BUILTIN,
	.ops		=	&noqueue_qdisc_ops,
	.list		=	LIST_HEAD_INIT(noqueue_qdisc.list),
};


static const u8 prio2band[TC_PRIO_MAX+1] =
	{ 1, 2, 2, 2, 1, 2, 0, 0 , 1, 1, 1, 1, 1, 1, 1, 1 };

/* 3-band FIFO queue: old style, but should be a bit faster than
   generic prio+fifo combination.
 */

#define PFIFO_FAST_BANDS 3

static inline struct sk_buff_head *prio2list(struct sk_buff *skb,
					     struct Qdisc *qdisc)
{
	struct sk_buff_head *list = qdisc_priv(qdisc);
	return list + prio2band[skb->priority & TC_PRIO_MAX];
}

static int pfifo_fast_enqueue(struct sk_buff *skb, struct Qdisc* qdisc)
{
	struct sk_buff_head *list = prio2list(skb, qdisc);

	if (skb_queue_len(list) < qdisc->dev->tx_queue_len) {
		qdisc->q.qlen++;
		return __qdisc_enqueue_tail(skb, qdisc, list);
	}

	return qdisc_drop(skb, qdisc);
}

static struct sk_buff *pfifo_fast_dequeue(struct Qdisc* qdisc)
{
	int prio;
	struct sk_buff_head *list = qdisc_priv(qdisc);

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++) {
		if (!skb_queue_empty(list + prio)) {
			qdisc->q.qlen--;
			return __qdisc_dequeue_head(qdisc, list + prio);
		}
	}

	return NULL;
}

static int pfifo_fast_requeue(struct sk_buff *skb, struct Qdisc* qdisc)
{
	qdisc->q.qlen++;
	return __qdisc_requeue(skb, qdisc, prio2list(skb, qdisc));
}

static void pfifo_fast_reset(struct Qdisc* qdisc)
{
	int prio;
	struct sk_buff_head *list = qdisc_priv(qdisc);

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++)
		__qdisc_reset_queue(qdisc, list + prio);

	qdisc->qstats.backlog = 0;
	qdisc->q.qlen = 0;
}

static int pfifo_fast_dump(struct Qdisc *qdisc, struct sk_buff *skb)
{
	struct tc_prio_qopt opt = { .bands = PFIFO_FAST_BANDS };

	memcpy(&opt.priomap, prio2band, TC_PRIO_MAX+1);
	RTA_PUT(skb, TCA_OPTIONS, sizeof(opt), &opt);
	return skb->len;

rtattr_failure:
	return -1;
}

static int pfifo_fast_init(struct Qdisc *qdisc, struct rtattr *opt)
{
	int prio;
	struct sk_buff_head *list = qdisc_priv(qdisc);

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++)
		skb_queue_head_init(list + prio);

	return 0;
}

static struct Qdisc_ops pfifo_fast_ops = {
	.id		=	"pfifo_fast",
	.priv_size	=	PFIFO_FAST_BANDS * sizeof(struct sk_buff_head),
	.enqueue	=	pfifo_fast_enqueue,
	.dequeue	=	pfifo_fast_dequeue,
	.requeue	=	pfifo_fast_requeue,
	.init		=	pfifo_fast_init,
	.reset		=	pfifo_fast_reset,
	.dump		=	pfifo_fast_dump,
	.owner		=	THIS_MODULE,
};

// 分配内存建立排队规则，并初始化排队规则的相关成员，然后将排队规则与排队规则的操作接口
// 绑定起来，设置排队规则的enqueue和dequeue接口以及排队规则安装的网络设备，最后返回
// 已建立的排队规则。本函数在qdisc_create()和qdisc_create_dflt()中被调用
struct Qdisc *qdisc_alloc(struct net_device *dev, struct Qdisc_ops *ops)
{
	void *p;
	struct Qdisc *sch;
	unsigned int size;
	int err = -ENOBUFS;

	/* ensure that the Qdisc and the private data are 32-byte aligned */
	size = QDISC_ALIGN(sizeof(*sch));
	size += ops->priv_size + (QDISC_ALIGNTO - 1);

	p = kzalloc(size, GFP_KERNEL);
	if (!p)
		goto errout;
	sch = (struct Qdisc *) QDISC_ALIGN((unsigned long) p);
	sch->padded = (char *) sch - (char *) p;

	INIT_LIST_HEAD(&sch->list);
	skb_queue_head_init(&sch->q);
	sch->ops = ops;
	sch->enqueue = ops->enqueue;
	sch->dequeue = ops->dequeue;
	sch->dev = dev;
	dev_hold(dev);
	sch->stats_lock = &dev->queue_lock;
	atomic_set(&sch->refcnt, 1);

	return sch;
errout:
	return ERR_PTR(-err);
}

// 用于创建默认的排队规则
struct Qdisc * qdisc_create_dflt(struct net_device *dev, struct Qdisc_ops *ops,
				 unsigned int parentid)
{
	struct Qdisc *sch;
	
	// 通过qdisc_alloc()建立起排队规则并与操作接口绑定
	sch = qdisc_alloc(dev, ops);
	if (IS_ERR(sch))
		goto errout;
	// 设置新排队规则的父规则
	sch->parent = parentid;

	// 最后调用init()接口初始化
	if (!ops->init || ops->init(sch, NULL) == 0)
		return sch;

	qdisc_destroy(sch);
errout:
	return NULL;
}

/* Under dev->queue_lock and BH! */

void qdisc_reset(struct Qdisc *qdisc)
{
	struct Qdisc_ops *ops = qdisc->ops;

	if (ops->reset)
		ops->reset(qdisc);
}

/* this is the rcu callback function to clean up a qdisc when there 
 * are no further references to it */

static void __qdisc_destroy(struct rcu_head *head)
{
	struct Qdisc *qdisc = container_of(head, struct Qdisc, q_rcu);
	kfree((char *) qdisc - qdisc->padded);
}

/* Under dev->queue_lock and BH! */

void qdisc_destroy(struct Qdisc *qdisc)
{
	struct Qdisc_ops  *ops = qdisc->ops;

	if (qdisc->flags & TCQ_F_BUILTIN ||
	    !atomic_dec_and_test(&qdisc->refcnt))
		return;

	list_del(&qdisc->list);
#ifdef CONFIG_NET_ESTIMATOR
	gen_kill_estimator(&qdisc->bstats, &qdisc->rate_est);
#endif
	if (ops->reset)
		ops->reset(qdisc);
	if (ops->destroy)
		ops->destroy(qdisc);

	module_put(ops->owner);
	dev_put(qdisc->dev);
	call_rcu(&qdisc->q_rcu, __qdisc_destroy);
}

// 初始化用于流量控制的排队规则，并启动监视定时器
void dev_activate(struct net_device *dev)
{
	/* No queueing discipline is attached to device;
	   create default one i.e. pfifo_fast for devices,
	   which need queueing and noqueue_qdisc for
	   virtual interfaces
	 */

	// 安装默认的排队规则
	if (dev->qdisc_sleeping == &noop_qdisc) {
		struct Qdisc *qdisc;
		if (dev->tx_queue_len) {
			// 网络设备支持排队时，安装默认排队规则pfifo
			qdisc = qdisc_create_dflt(dev, &pfifo_fast_ops,
						  TC_H_ROOT);
			if (qdisc == NULL) {
				printk(KERN_INFO "%s: activation failed\n", dev->name);
				return;
			}
			write_lock(&qdisc_tree_lock);
			list_add_tail(&qdisc->list, &dev->qdisc_list);
			write_unlock(&qdisc_tree_lock);
		} else {
			// 不支持排队时，安装默认排队规则noqueue，noqueue是不支持队列的排队规则
			// 因为它不支持enqueue接口。当通过dev_queue_xmit()输出报文时，发现不支持
			// enqueue接口，就直接发送报文，不再进行排队操作
			qdisc =  &noqueue_qdisc;
		}
		write_lock(&qdisc_tree_lock);
		dev->qdisc_sleeping = qdisc;
		write_unlock(&qdisc_tree_lock);
	}

	// 检测网络设备是否处于可传递数据包状态。如果不是，则延迟应用已安装的排队规则
	// 直到转变为可传递数据包状态
	if (!netif_carrier_ok(dev))
		/* Delay activation until next carrier-on event */
		return;

	spin_lock_bh(&dev->queue_lock);
	rcu_assign_pointer(dev->qdisc, dev->qdisc_sleeping);
	if (dev->qdisc != &noqueue_qdisc) {
		dev->trans_start = jiffies;
		dev_watchdog_up(dev);
	}
	spin_unlock_bh(&dev->queue_lock);
}

// 将网络设备的排队规则设置为空规则，停止发送报文及监视报文发送是否超时
void dev_deactivate(struct net_device *dev)
{
	struct Qdisc *qdisc;

	spin_lock_bh(&dev->queue_lock);
	qdisc = dev->qdisc;
	dev->qdisc = &noop_qdisc;

	qdisc_reset(qdisc);

	spin_unlock_bh(&dev->queue_lock);

	dev_watchdog_down(dev);

	/* Wait for outstanding dev_queue_xmit calls. */
	synchronize_rcu();

	/* Wait for outstanding qdisc_run calls. */
	// 如果网络设备还在进行流量控制的调度队列过程中，尽量让出处理器，尽可能块地
	// 完成qdisc_run()的调用
	while (test_bit(__LINK_STATE_QDISC_RUNNING, &dev->state))
		yield();

	if (dev->gso_skb) {
		kfree_skb(dev->gso_skb);
		dev->gso_skb = NULL;
	}
}

// 初始化排队规则的相关数据结构，在注册网络设备的register_netdevice()中被调用
void dev_init_scheduler(struct net_device *dev)
{
	qdisc_lock_tree(dev);
	// 排队规则为noop_qdisc,对应的noop_enqueue(),noop_dequeue(),noop_requeue()
	// 并没有对数据包进行任何分类或排队，而是直接丢弃待发送的数据包
	// 所以此时网络设备还不能发送任何数据包，必须等网络设备启用之后才能发送数据包
	dev->qdisc = &noop_qdisc;
	dev->qdisc_sleeping = &noop_qdisc;
	INIT_LIST_HEAD(&dev->qdisc_list);
	qdisc_unlock_tree(dev);

	dev_watchdog_init(dev);
}

void dev_shutdown(struct net_device *dev)
{
	struct Qdisc *qdisc;

	qdisc_lock_tree(dev);
	qdisc = dev->qdisc_sleeping;
	dev->qdisc = &noop_qdisc;
	dev->qdisc_sleeping = &noop_qdisc;
	qdisc_destroy(qdisc);
#if defined(CONFIG_NET_SCH_INGRESS) || defined(CONFIG_NET_SCH_INGRESS_MODULE)
        if ((qdisc = dev->qdisc_ingress) != NULL) {
		dev->qdisc_ingress = NULL;
		qdisc_destroy(qdisc);
        }
#endif
	BUG_TRAP(!timer_pending(&dev->watchdog_timer));
	qdisc_unlock_tree(dev);
}

EXPORT_SYMBOL(netif_carrier_on);
EXPORT_SYMBOL(netif_carrier_off);
EXPORT_SYMBOL(noop_qdisc);
EXPORT_SYMBOL(qdisc_create_dflt);
EXPORT_SYMBOL(qdisc_destroy);
EXPORT_SYMBOL(qdisc_reset);
EXPORT_SYMBOL(qdisc_lock_tree);
EXPORT_SYMBOL(qdisc_unlock_tree);
