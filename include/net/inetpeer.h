/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Version:	$Id: inetpeer.h,v 1.2 2002/01/12 07:54:56 davem Exp $
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

// 对端信息块，用来保存对端的一些信息，包括对端的地址以及传输层使用的时间戳
// 主要用来在组装IP数据报时防止分片攻击，在建立TCP连接时检测连接请求是否有效
// 以及其序号是否回绕
// 对端信息块以v4addr为关键字，peer_root为根，组成AVL树
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	struct inet_peer	*avl_left, *avl_right;
	// 对端的IP地址
	__be32			v4daddr;	/* peer's address */
	__u16			avl_height;
	// 一个单调递增只，用来设置IP分片首部中的ID域，根据对端地址初始化为随机值
	__u16			ip_id_count;	/* IP ID for the next packet */
	// 用来链接到inet_peer_unused_head链表上，该链表上的对端信息块都是闲置的，可回收
	struct inet_peer	*unused_next, **unused_prevp;
	// 记录该对端数据块引用计数为0的时间，当闲置的时间超出指定的时间，就会被回收
	__u32			dtime;		/* the time of last use of not
						 * referenced entries */
	atomic_t		refcnt;
	// 递增ID，对端发送分片的计数器
	atomic_t		rid;		/* Frag reception counter */
	// TCP中，记录最后一个ACK段到达的时间
	__u32			tcp_ts;
	// TCP中，记录接收到的段中的时间戳，设置ts_recent的时间
	unsigned long		tcp_ts_stamp;
};

void			inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(__be32 daddr, int create);

/* can be called from BH context or outside */
extern void inet_putpeer(struct inet_peer *p);

extern spinlock_t inet_peer_idlock;
/* can be called with or without local BH being disabled */
static inline __u16	inet_getid(struct inet_peer *p, int more)
{
	__u16 id;

	spin_lock_bh(&inet_peer_idlock);
	id = p->ip_id_count;
	p->ip_id_count += 1 + more;
	spin_unlock_bh(&inet_peer_idlock);
	return id;
}

#endif /* _NET_INETPEER_H */
