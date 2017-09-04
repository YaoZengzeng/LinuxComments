/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

// request_sock_ops结构为处理连接请求的函数指针表，其中包含用于发送syn+ack段，ack段，rst段的函数
// 该结构作为request_sock结构的一个成员，可以很方便地通过连接请求块索引到这些结构，tcp中，指向的实例
// 为tcp_request_sock_ops
struct request_sock_ops {
	// 所属协议族
	int		family;
	// obj_size是tcp_request_sock结构长度，用于创建分配连接请求块的高速缓存slab，该缓存在注册传输层
	// 协议时建立，参见proto_register()
	int		obj_size;
	struct kmem_cache	*slab;
	// 发送syn+ack段的函数指针，tcp中为tcp_v4_send_synack()
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req,
				       struct dst_entry *dst);
	// 发送ack段的函数指针，tcp中为tcp_v4_reqsk_send_ack()
	void		(*send_ack)(struct sk_buff *skb,
				    struct request_sock *req);
	// 发送rst段的函数指针，tcp中为tcp_v4_send_reset()
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	// 析构函数，在释放连接请求块时被调用，用来清理释放资源，tcp中为tcp_v4_reqsk_destructor()
	void		(*destructor)(struct request_sock *req);
};

/* struct request_sock - mini sock to represent a connection request
 */
struct request_sock {
	struct request_sock		*dl_next; /* Must be first member! */
	// 客户端连接请求段中通知的mss，如果无通告，则为初始值，即rfc中建议的536
	u16				mss;
	// 发送syn+ack段的次数，在达到系统设定的上限时，取消连接操作
	u8				retrans;
	// 未使用
	u8				__pad;
	/* The following two fields can be easily recomputed I think -AK */
	// 标识本端的最大通告窗口，在生成syn+ack段时计算该值
	u32				window_clamp; /* window clamp at creation time */
	// 标识在连接建立时本端接收窗口大小，初始化为0，在生成syn+ack段时计算该值
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	// 下一个将要发送的ack中的时间戳值，当一个包含最后发送ack确认序号的段到达时，该段中的时间戳
	// 被保存在ts_recent中
	u32				ts_recent;
	// 服务端接收到连接请求，并发送syn+ack段作为应答后，等待客户端确认的超时时间，一旦超时，会重新发送
	// syn+ack段，直到连接建立或重发次数达到上限
	unsigned long			expires;
	// 处理连接请求的函数指针表，tcp中指向tcp_request_sock_ops
	const struct request_sock_ops	*rsk_ops;
	// 指向对应状态的传输控制块，在连接建立之前无效，三次握手后会创建对应的传输控制块
	// 而此时连接请求块也完成了历史使命，调用accept()将该连接请求块取走并释放
	struct sock			*sk;
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
// listen_sock结构用来存储连接请求块，该结构的实例在listen系统调用之后才会被创建
// request_sock_queue结构的listen_opt成员指向该实例
struct listen_sock {
	// 实际分配用来保存syn请求连接的request_sock结构数组的长度，其值为nr_table_entries以2为底的对数
	u8			max_qlen_log;
	/* 3 bytes hole, try to use */
	// 当前连接请求块的数目
	int			qlen;
	// 当前未重传过syn+ack段的请求块数目，如果每次建立连接都很顺利，三次握手的段没有重传
	// 则qlen_young和qlen是一致的，有syn+ack段重传时会递减
	int			qlen_young;
	// 用来记录连接建立定时器处理函数下次被激活时需处理的连接请求块散列表入口。在本次处理结束时
	// 将当前的入口保存到该字段中，在下次处理时就从该入口开始处理
	int			clock_hand;
	// 用来计算syn请求块散列表键值的随机数，该值在reqsk_queue_alloc()中随机生成
	u32			hash_rnd;
	// 实际分配用来保存syn请求连接的request_sock结构数组的长度
	u32			nr_table_entries;
	// 指向request_sock结构散列表，在listen系统调用中生成
	struct request_sock	*syn_table[0];
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
// 由于tcp连接的建立要经过三次握手，因此需要在服务端保存待建立连接的相关信息并控制连接，request_sock_queue等结构就是用来
// 存储这些信息的
// 在request_sock_queue结构中，rskq_accept_head和rskq_accept_tail只保存已连接但未被accept的传输控制块
// SYN_RECV状态传输控制块存放在listen_opt指向的listen_sock结构实例中，而该实例在listen系统调用后被创建
struct request_sock_queue {
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;
	rwlock_t		syn_wait_lock;
	// 保存相关套接口tcp层的选项TCP_DEFER_ACCEPT的值
	u8			rskq_defer_accept;
	/* 3 bytes hole, try to pack */
	// 指向一个listen_sock结构实例，该实例在侦听时建立
	struct listen_sock	*listen_opt;
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

static inline struct listen_sock *reqsk_queue_yank_listen_sk(struct request_sock_queue *queue)
{
	struct listen_sock *lopt;

	write_lock_bh(&queue->syn_wait_lock);
	lopt = queue->listen_opt;
	queue->listen_opt = NULL;
	write_unlock_bh(&queue->syn_wait_lock);

	return lopt;
}

static inline void __reqsk_queue_destroy(struct request_sock_queue *queue)
{
	kfree(reqsk_queue_yank_listen_sk(queue));
}

extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	BUG_TRAP(req != NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

// reqsk_queue_get_child()从已连接队列上取走第一个连接请求块，然后由该连接请求块获得已创建的子传输控制块
// 接着释放已完成建立连接的连接请求块，同时更新父传输控制块上已建立连接的数目，最后返回子传输控制块
static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
	struct request_sock *req = reqsk_queue_remove(queue);
	struct sock *child = req->sk;

	BUG_TRAP(child != NULL);

	sk_acceptq_removed(parent);
	__reqsk_free(req);
	return child;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
