/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/list.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/security.h>

#include <linux/filter.h>

#include <asm/atomic.h>
#include <net/dst.h>
#include <net/checksum.h>

/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the SOCK_DBG debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)
#else
#define SOCK_DEBUG(sk, msg...) do { } while (0)
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
struct sock_iocb;
typedef struct {
	spinlock_t		slock;
	struct sock_iocb	*owner;
	wait_queue_head_t	wq;
	/*
	 * We express the mutex-alike socket_lock semantics
	 * to the lock validator by explicitly managing
	 * the slock as a lock variant (in addition to
	 * the slock itself):
	 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} socket_lock_t;

struct sock;
struct proto;

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_refcnt: reference count
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_prot: protocol handlers inside a network family
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
// sock_common结构是传输控制块信息的最小集合，由sock和inet_timeout_sock结构前面
// 相同部分单独构成，因此只用来构成这两种结构
struct sock_common {
	// 所属协议族，如IPv4的地址族为AF_INET
	unsigned short		skc_family;
	// 等同于TCP的状态，虽然UDP不存在连接或传输状态，但在实现中用到了一些状态值
	// 例如TCP_CLOSE
	volatile unsigned char	skc_state;
	// 标识是否可以重用地址和端口，参见SO_REUSEADDR选项
	unsigned char		skc_reuse;
	// 如果不为0，即为输出报文的网络设备索引号
	int			skc_bound_dev_if;
	// TCP维护一个所有TCP传输控制块的散列表tcp_hashinfo，而skc_node用来将所属TCP
	// 传输控制块链接到该散列表
	// UDP维护一个已经绑定端口的UDP控制块的散列表udp_hash，而skc_node用来将所属
	// UDP传输控制块链接到该散列表
	struct hlist_node	skc_node;
	// 已绑定端口的传输控制块利用该字段插入到与之绑定端口信息结构为头节点的链表中，释放
	// 端口时，会从中删除，仅用于基于连接的传输控制块，如TCP
	struct hlist_node	skc_bind_node;
	// 引用计数
	atomic_t		skc_refcnt;
	// 存储TCP状态的established时加入到散列表的关键字值，由于计算值相对耗时，因此用一个
	// 成员来存储键值有利于提高效率
	unsigned int		skc_hash;
	// 指向网络接口层的指针
	struct proto		*skc_prot;
};

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_sleep: sock wait queue
  *	@sk_dst_cache: destination cache
  *	@sk_dst_lock: destination cache lock
  *	@sk_policy: flow policy
  *	@sk_rmem_alloc: receive queue bytes committed
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_write_queue: Packet sending queue
  *	@sk_async_wait_queue: DMA copied packets
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_allocation: allocation mode
  *	@sk_sndbuf: size of send buffer in bytes
  *	@sk_flags: %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE, %SO_OOBINLINE settings
  *	@sk_no_check: %SO_NO_CHECK setting, wether or not checkup packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt, IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a persistent failure not just 'timed out'
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peercred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_filter: socket filtering instructions
  *	@sk_protinfo: private area, net family specific, when not using slab
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_sndmsg_page: cached page for sendmsg
  *	@sk_sndmsg_off: cached offset for sendmsg
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
 */
// sock结构是构成传输控制块的基础，跟具体的协议族无关，包含各协议族传输层协议的公共信息
// 因此不能直接作为传输层的控制块来使用，不同协议族的传输层在使用sock结构时都会对其进行
// 扩展，使其适合各自的传输特性，例如，inet_sock结构就是由sock结构和其他一些特性组成的
// 是IPv4协议族传输控制块的基础
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_node			__sk_common.skc_node
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_refcnt		__sk_common.skc_refcnt
#define sk_hash			__sk_common.skc_hash
#define sk_prot			__sk_common.skc_prot
	// 关闭套接口的标志
	// RCV_SHUTDOWN:接收通道关闭，不允许继续接收数据
	// SEND_SHUTDOWN:发送通道关闭，不允许继续发送数据
	// SHUTDOWN_MASK:表示完全关闭
	unsigned char		sk_shutdown : 2,
				// 标识是否对RAW和UDP进行校验和
				// UDP_CSUM_NOXMIT:不执行校验和
				// UDP_CSUM_DEFAULT:默认执行校验和
				// ...
				sk_no_check : 2,
				// 标识传输层的一些状态
				// SOCK_SNDBUF_LOCK:用户通过套接口选项设置了发送缓冲区大小
				// SOCK_RCVBUF_LOCK:用户通过套接口选项设置了接收缓冲区大小
				// SOCK_BINDADDR_LOCK:已经绑定了本地地址
				// SOCK_BINDPORT_LOCK:已经绑定了本地端口
				sk_userlocks : 4;
	// 当前域中套接字所属的协议			
	unsigned char		sk_protocol;
	// 所属套接口类型，比如SOCK_STREAM
	unsigned short		sk_type;
	// 接收缓冲区大小的上限，参见SO_RCVBUF选项
	int			sk_rcvbuf;
	// 同步锁，其中包括了两种锁：一种是用于用户进程读取数据和网络层向传输层传递数据之间的
	// 同步锁；二是控制Linux下半部访问本传输控制块的同步锁，以免多个下半部同时访问本传输
	// 控制块
	socket_lock_t		sk_lock;	
	// 进程等待队列，进程等待连接，等待输出缓冲区，等待读数据时，都会将进程暂存到此队列中
	wait_queue_head_t	*sk_sleep;
	// 目的路由项缓存，一般都是在创建传输控制块发送数据报文时，发现未设置该字段才从路由表
	// 或路由缓存中查询到相应的路由项来设置该字段，这样可以加速数据的输出，后续数据的输出
	// 不必再查询目的路由，某些情况下会刷新此目的路由缓存，比如端口连接、重新进行了连接、
	// TCP重传、重新绑定端口等操作
	struct dst_entry	*sk_dst_cache;
	// 与IPSec相关的传输策略
	struct xfrm_policy	*sk_policy[2];
	// 操作目的路由缓存的读写锁
	rwlock_t		sk_dst_lock;
	// 接收队列sk_receive_queue中所有报文数据的总长度
	atomic_t		sk_rmem_alloc;
	// 所在传输控制块中，为发送而分配的所有SKB数据区的总大小
	atomic_t		sk_wmem_alloc;
	// 分配辅助缓冲区的上限，辅助数据包括进行设置选项、设置过滤时分配的内存和组播设置等
	atomic_t		sk_omem_alloc;
	// 接收队列，等待用户进程读取，TCP比较特别，当接收到的数据不能直接复制到用户空间时
	// 才会缓存至此
	struct sk_buff_head	sk_receive_queue;
	// 发送队列，在TCP中，此队列同时也是重传队列，在sk_send_head之前为重传队列，之后
	// 为发送队列
	struct sk_buff_head	sk_write_queue;
	// 用DMA方式传送数据包的队列
	struct sk_buff_head	sk_async_wait_queue;
	// 发送队列中所有报文数据的总长度，目前只用于TCP
	int			sk_wmem_queued;
	// 预分配缓存长度，这只是一个标识，目前只用于TCP，当分配的缓存小于该值时，分配必然成功
	// 否则需要重新确认分配的缓存是否有效
	int			sk_forward_alloc;
	// 内存分配方式
	// __GFP_ATOMIC、__GFP_KERNEL、__GFP_USER...
	gfp_t			sk_allocation;
	// 发送缓冲区长度的上限，发送队列中报文数据总长度不能超过该值，参见SO_SNDBUF选项
	int			sk_sndbuf;
	// 目的路由网络设备的特性，在sk_setup_caps()中根据net_device结构的features成员设置
	int			sk_route_caps;
	// 传输层支持的GSO类型，例如SKB_GSO_TCPV4等
	int			sk_gso_type;
	// 标识接收缓存下限值
	int			sk_rcvlowat;
	// 一些状态和标志，这个标志是一个杂集，SOCK_DEAD，SOCK_DONE等等
	unsigned long 		sk_flags;
	// 关闭套接口前发送剩余数据的时间，参见SO_LINGER选项
	unsigned long	        sk_lingertime;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 */
	// 后备接收队列，目前只用于TCP，传输控制块被上锁之后（如应用层读取数据），当有新的
	// 报文传输到传输控制块时，只能把报文放到后备接收队列中，之后有用户进程读取TCP数据时
	// 再从该队列中取出复制到用户空间中
	struct {
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	// 错误链表，存放详细的出错信息,应用程序通过setsockopt系统调用设置IP_RECVERR
	// 选项，即需获取详细出错信息，当有错误发生时，可通过recvmsg()，参数flags为
	// MSG_ERRQUEUE来获取详细的出错信息
	struct sk_buff_head	sk_error_queue;
	// 原始网络协议块指针，因为传输控制块中的另一个网络协议块指针sk_prot在IPv6的
	// IPV6_ADDRFROM套接口选项设置时被修改
	struct proto		*sk_prot_creator;
	// 确保传输控制块中一些成员同步访问的锁，因为有些成员在软中断中被访问，存在异步
	// 访问的问题
	rwlock_t		sk_callback_lock;
	// 记录当前传输层中发生的最后一次致命错误的错误码，但应用层读取后会自动恢复为
	// 初始正常状态
	int			sk_err,
				// 用于记录非致命性错误，或者用作在传输控制块被锁定时记录错误的后备成员
				sk_err_soft;
	// 当前已建立的连接数
	unsigned short		sk_ack_backlog;
	// 连接队列长度的上限
	unsigned short		sk_max_ack_backlog;
	// 用于设置由此套接口输出数据报的QoS类别，参见SO_PRIORITY和IP_TOS选项
	__u32			sk_priority;
	// 返回连接至该套接字的外部进程的身份验证，目前主要用于PF_UNIX协议族，参见SO_PEERCRED选项
	struct ucred		sk_peercred;
	// 套接口层接收超时，参见SO_RCVTIMEO选项
	long			sk_rcvtimeo;
	// 套接口发送超时，参见SO_SNDTIMEO选项
	long			sk_sndtimeo;
	// 套接口过滤器，在传输层对输入的数据包通过BPF过滤代码进行过滤，只对设置了套接口过滤器的进程有效
	// 参见SO_ATTACH_FILTER选项
	struct sk_filter      	*sk_filter;
	// 传输控制块存放私有数据的指针
	void			*sk_protinfo;
	// 通过TCP的不同状态，来实现连接定时器，FIN_WAIT_2定时器以及TCP保活定时器，在tcp_keepalive_timer()
	// 中实现
	struct timer_list	sk_timer;
	// 在未启用SOCK_RCVTSTAMP套接口选项时，记录报文接收数据到应用层的时间戳，在用SOCK_RCVTSTAMP套接口选项
	// 时，接收数据到应用层的时间戳记录在SKB的tstamp中
	struct timeval		sk_stamp;
	// 指向对应套接口的指针
	struct socket		*sk_socket;
	// RPC层存放私有数据的指针，IPv4未使用
	void			*sk_user_data;
	// sk_sndmsg_page指向为本传输控制块最近一次分配的页面，通常是当前套接口发送队列中最后一个SKB的分页数据的
	// 最后一页，但在某种特殊的状态下也有可能不是（比如，在tcp_sendmsg()中成功分配了页面，但复制数据失败了）。
	// 同时还用于区分系统的页面和主动分配的页面，如果是系统的页面，是不能在页面中做修改的，而如果是在发送过程中
	// 主动分配的页面，则可以对页面中的数据进行修改或添加，参见tcp_sendmsg()
	struct page		*sk_sndmsg_page;
	// 指向sk_write_queue队列中第一个未发送的节点，如果sk_send_head为空，则表示发送队列是空的，发送队列上的
	// 报文已经全部发送
	struct sk_buff		*sk_send_head;
	// sk_sndmsg_off表示数据尾端在最后一页分片内的页内偏移，新的数据可以直接从这个位置复制到该分片中
	// 这两个成员主要起缓存的作用，可以直接找到最后一个页面，然后尝试把数据追加到该页中，如果不行，则分配
	// 新页面，然后向新页复制数据，并更新sk_sndmsg_page和sk_sndmsg_off的值
	__u32			sk_sndmsg_off;
	// 标识有数据即将写入套接口，也就是有写数据的请求
	int			sk_write_pending;
	// 指向sk_security_struct结构，安全模块使用
	void			*sk_security;
	// 当传输控制块的状态发生变化时，唤醒那些等待本套接口的进程，在创建套接口时初始化
	// IPv4中为sock_def_wakeup()
	void			(*sk_state_change)(struct sock *sk);
	// 当有数据到达接收处理时，唤醒或发信号通知准备读本套接口的进程，在创建套接口时初始化
	// IPv4中为sock_def_readable()
	void			(*sk_data_ready)(struct sock *sk, int bytes);
	// 在发送缓存大小发生变化或套接口被释放时，唤醒因等待本套接口而处于睡眠状态的进程
	// 包括sk_sleep队列以及fasync_list队列上的进程，创建套接口时被初始化，IPv4中默认为
	// sock_def_write_space()，TCP中为sk_stream_write_space()
	void			(*sk_write_space)(struct sock *sk);
	// 报告错误的回调函数，如果等待该传输控制块的进程正在睡眠，则将其唤醒（例如MSG_ERRQUEUE）
	// 在创建套接口时被初始化，IPv4中为sock_def_error_report()
	void			(*sk_error_report)(struct sock *sk);
	// 在TCP中，用于接收预备队列和后备队列中的TCP段，TCP的sk_backlog_rcv接口为tcp_v4_do_rcv()
	// 如果预备队列中还存在TCP段，则调用tcp_prequeue_process()预处理，在该函数中会调用sk_backlog_rcv()
	// 如果后备队列中还存在TCP段，则调用release_sock()处理，也会调用sk_backlog_rcv()，该函数指针在创建
	// 套接口的传输控制块时由传输层backlog_rcv接口初始化
  	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);  
  	// 进行传输控制块的销毁，在释放传输控制块前释放一些其他资源，在sk_free()释放传输控制块时调用
  	// 当传输控制块的引用计数为0时，才真正释放，IPv4中为inet_sock_destruct()
	void                    (*sk_destruct)(struct sock *sk);
};

/*
 * Hashed lists helper routines
 */
static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return sk->sk_node.next ?
		hlist_entry(sk->sk_node.next, struct sock, sk_node) : NULL;
}

static inline int sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline int sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static __inline__ void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static __inline__ void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

static __inline__ int __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return 1;
	}
	return 0;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static inline void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt);
}

static __inline__ int sk_del_node_init(struct sock *sk)
{
	int rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static __inline__ void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static __inline__ void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static __inline__ void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static __inline__ void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_node)
#define sk_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_from(__sk, node, sk_node)
#define sk_for_each_continue(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_continue(__sk, node, sk_node)
#define sk_for_each_safe(__sk, node, tmp, list) \
	hlist_for_each_entry_safe(__sk, node, tmp, list, sk_node)
#define sk_for_each_bound(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_bind_node)

/* Sock flags */
enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
};

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

static inline int sk_acceptq_is_full(struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(struct sock *sk)
{
	return sk->sk_wmem_queued / 2;
}

static inline int sk_stream_wspace(struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

extern void sk_stream_write_space(struct sock *sk);

static inline int sk_stream_memory_free(struct sock *sk)
{
	return sk->sk_wmem_queued < sk->sk_sndbuf;
}

extern void sk_stream_rfree(struct sk_buff *skb);

// 当TCP段的SKB传递到TCP传输控制块中，便会调用sk_stream_set_owner_r()设置
// 该SKB的宿主，并设置SKB的销毁函数，还要更新接收队列中所有报文数据的总长度以及
// 预分配缓存长度
static inline void sk_stream_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb->sk = sk;
	skb->destructor = sk_stream_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk->sk_forward_alloc -= skb->truesize;
}

// sk_stream_free_skb()设置到用于输入的TCP段的SKB的销毁函数接口上，当释放该SKB时
// 被调用，用于更新接收队列中所有报文数据报的总长度，以及预分配缓存长度
static inline void sk_stream_free_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_truesize_check(skb);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued   -= skb->truesize;
	sk->sk_forward_alloc += skb->truesize;
	__kfree_skb(skb);
}

/* The per-socket spinlock must be held here. */
static inline void sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	if (!sk->sk_backlog.tail) {
		sk->sk_backlog.head = sk->sk_backlog.tail = skb;
	} else {
		sk->sk_backlog.tail->next = skb;
		sk->sk_backlog.tail = skb;
	}
	skb->next = NULL;
}

#define sk_wait_event(__sk, __timeo, __condition)		\
({	int rc;							\
	release_sock(__sk);					\
	rc = __condition;					\
	if (!rc) {						\
		*(__timeo) = schedule_timeout(*(__timeo));	\
	}							\
	lock_sock(__sk);					\
	rc = __condition;					\
	rc;							\
})

extern int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
extern int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
extern void sk_stream_wait_close(struct sock *sk, long timeo_p);
extern int sk_stream_error(struct sock *sk, int flags, int err);
extern void sk_stream_kill_queues(struct sock *sk);

extern int sk_wait_data(struct sock *sk, long *timeo);

struct request_sock_ops;
struct timewait_sock_ops;

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 * transport -> network interface is defined by struct inet_proto
 */
// proto结构为网络接口层，结构中的操作实现传输层的操作和从传输层到网络层调用
// 的跳转，在proto结构中的某些成员跟proto_ops结构中的成员对应，比如connect()等
// 这里可以称之为传输层接口，如果对有关数据操作的函数调用(如sendmsg())通过此接口后
// 进入网络层，在IPv4协议族中，则进入IP层的处理
// struct proto数据结构中的函数用于套接字层与传输层之间在内核地址空间的通信
struct proto {
	// 传输层接口初始化接口，在创建套接口时，在inet_create()中被调用
	void			(*close)(struct sock *sk, 
					long timeout);
	int			(*connect)(struct sock *sk,
				        struct sockaddr *uaddr, 
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept) (struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	int			(*init)(struct sock *sk);
	// 没有与之对应的系统调用，当关闭套接口时被调用
	int			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval,
					int optlen);
	int			(*getsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval, 
					int __user *option);  	 
	int			(*compat_setsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int optlen);
	int			(*compat_getsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int __user *option);
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					size_t len, int noblock, int flags, 
					int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk, 
					struct sockaddr *uaddr, int addr_len);
	// 用于接收预备队列和后备队列中的TCP段
	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	// hash为添加到管理传输控制块散列表的接口，unhash为从管理传输控制块散列表中删除的接口
	// 由于不同的传输层协议组织管理传输控制块也不一样，因此需要提供不同的方法，比如在TCP中
	// 实现接口函数分别为tcp_v4_hash()和tcp_unhash()，而UDP传输控制块的管理相对比较简单
	// 只有绑定端口的传输控制块才会添加到散列表中，这由绑定过程来完成，因此不需要实现hash接口
	// 只需实现unhash接口即可
	void			(*hash)(struct sock *sk);
	void			(*unhash)(struct sock *sk);
	// 实现地址与端口的绑定，参数sk为进行绑定操作的传输控制块，snum为进行绑定的端口号
	// (如果为0，端口号在绑定时自动选择)。TCP中为tcp_v4_get_port(),UDP中为udp_v4_get_port()
	int			(*get_port)(struct sock *sk, unsigned short snum);

	/* Memory pressure */
	// 目前只有TCP使用，当前整个TCP传输层中为缓冲区分配的内存超过tcp_mem[1]，便进入警告状态
	// 会调用此接口设置告警状态，在TCP中它指向tcp_enter_memory_pressure()
	void			(*enter_memory_pressure)(void);
	// 目前只有TCP使用，表示当前整个TCP传输层中为缓冲区分配的内存（包括输入缓冲队列）
	// 在TCP中它指向变量tcp_memory_allocated
	atomic_t		*memory_allocated;	/* Current allocated memory. */
	// 表示当前整个TCP传输层中已创建的套接口的数目，目前只在TCP中使用，它指向变量
	// tcp_sockets_allocated
	atomic_t		*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the sk_stream_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	// 目前只在TCP中使用，在TCP传输层中缓冲大小进入警告状态时，它置1，否则置0
	// 目前只在TCP中使用，它指向变量tcp_memory_pressure
	int			*memory_pressure;
	// 指向sysctl_tcp_mem数组，参见tcp_mem系统参数
	int			*sysctl_mem;
	// 指向sysctl_tcp_wmem数组，参见tcp_wmem系统参数
	int			*sysctl_wmem;
	// 指向sysctl_tcp_rmem数组，参见tcp_rmem系统参数
	int			*sysctl_rmem;
	// 目前只有TCP使用，TCP首部的最大长度，考虑了所有选项
	int			max_header;

	// 用于分配传输控制块的slab高速缓存，在注册对应传输层协议时建立
	struct kmem_cache		*slab;
	// 标识传输控制块的大小，如果在初始化时建立分配传输控制块的slab缓存失败，则通过
	// kmalloc分配obj_size大小的空间来完成传输控制块的分配
	unsigned int		obj_size;

	// 目前只在TCP中使用，表示整个TCP传输层中待销毁的套接口的数目
	// 在TCP中，它指向变量tcp_orphan_count
	atomic_t		*orphan_count;

	// 目前只在TCP中使用，指向连接请求处理接口集合，包括发送SYN_ACK等实现
	struct request_sock_ops	*rsk_prot;
	// 目前只在TCP中使用，指向timewait控制块操作接口，TCP中的实例为
	// tcp_timewait_sock_ops。timewait_sock_ops结构提供了两个
	// 操作接口，tcp_twsk_unique()用于检测被timewait控制块绑定的
	// 端口是否可用，而twsk_destructor()用于在释放timewait控制块时
	// 在启用MD5数字签名的情况下做一些清理工作
	struct timewait_sock_ops *twsk_prot;

	struct module		*owner;

	// 标识传输控制块的名称，TCP协议为"TCP"，UDP协议为"UDP"
	char			name[32];

	// 通过node注册到proto_list中
	struct list_head	node;
#ifdef SOCK_REFCNT_DEBUG
	atomic_t		socks;
#endif
	// 统计每个CPU的proto状态
	struct {
		int inuse;
		u8  __pad[SMP_CACHE_BYTES - sizeof(int)];
	} stats[NR_CPUS];
};

extern int proto_register(struct proto *prot, int alloc_slab);
extern void proto_unregister(struct proto *prot);

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (atomic_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, atomic_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */

/* Called with local bh disabled */
static __inline__ void sock_prot_inc_use(struct proto *prot)
{
	prot->stats[smp_processor_id()].inuse++;
}

static __inline__ void sock_prot_dec_use(struct proto *prot)
{
	prot->stats[smp_processor_id()].inuse--;
}

/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline void __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	sk->sk_prot->hash(sk);
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
#define PROT_SOCK	1024

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

/* sock_iocb: used to kick off async processing of socket ios */
struct sock_iocb {
	struct list_head	list;

	int			flags;
	int			size;
	struct socket		*sock;
	struct sock		*sk;
	struct scm_cookie	*scm;
	struct msghdr		*msg, async_msg;
	struct kiocb		*kiocb;
};

static inline struct sock_iocb *kiocb_to_siocb(struct kiocb *iocb)
{
	return (struct sock_iocb *)iocb->private;
}

static inline struct kiocb *siocb_to_kiocb(struct sock_iocb *si)
{
	return si->kiocb;
}

// 套接口文件系统的i节点和套接口是一一对应的，因此套接口文件系统的i节点的分配
// 是比较特殊的，分配的并不是一个单纯的i节点，而是i节点和socket结构的组合体
// 即socket_alloc结构，这样可以使套接口的分配及与之绑定的套接口文件的i节点
// 的分配同时进行。在应用层访问套接口要通过文件描述符，这样可以快速地通过文件
// 描述符定位与之绑定的套接口
struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

extern void __sk_stream_mem_reclaim(struct sock *sk);
extern int sk_stream_mem_schedule(struct sock *sk, int size, int kind);

#define SK_STREAM_MEM_QUANTUM ((int)PAGE_SIZE)

static inline int sk_stream_pages(int amt)
{
	return (amt + SK_STREAM_MEM_QUANTUM - 1) / SK_STREAM_MEM_QUANTUM;
}

static inline void sk_stream_mem_reclaim(struct sock *sk)
{
	if (sk->sk_forward_alloc >= SK_STREAM_MEM_QUANTUM)
		__sk_stream_mem_reclaim(sk);
}

static inline void sk_stream_writequeue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL)
		sk_stream_free_skb(sk, skb);
	sk_stream_mem_reclaim(sk);
}

static inline int sk_stream_rmem_schedule(struct sock *sk, struct sk_buff *skb)
{
	return (int)skb->truesize <= sk->sk_forward_alloc ||
		sk_stream_mem_schedule(sk, skb->truesize, 1);
}

static inline int sk_stream_wmem_schedule(struct sock *sk, int size)
{
	return size <= sk->sk_forward_alloc ||
	       sk_stream_mem_schedule(sk, size, 0);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */
#define sock_owned_by_user(sk)	((sk)->sk_lock.owner)

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key) 	\
do {									\
	sk->sk_lock.owner = NULL;					\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
		       	(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

extern void FASTCALL(lock_sock_nested(struct sock *sk, int subclass));

static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

extern void FASTCALL(release_sock(struct sock *sk));

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

extern struct sock		*sk_alloc(int family,
					  gfp_t priority,
					  struct proto *prot, int zero_it);
extern void			sk_free(struct sock *sk);
extern struct sock		*sk_clone(const struct sock *sk,
					  const gfp_t priority);

extern struct sk_buff		*sock_wmalloc(struct sock *sk,
					      unsigned long size, int force,
					      gfp_t priority);
extern struct sk_buff		*sock_rmalloc(struct sock *sk,
					      unsigned long size, int force,
					      gfp_t priority);
extern void			sock_wfree(struct sk_buff *skb);
extern void			sock_rfree(struct sk_buff *skb);

extern int			sock_setsockopt(struct socket *sock, int level,
						int op, char __user *optval,
						int optlen);

extern int			sock_getsockopt(struct socket *sock, int level,
						int op, char __user *optval, 
						int __user *optlen);
extern struct sk_buff 		*sock_alloc_send_skb(struct sock *sk,
						     unsigned long size,
						     int noblock,
						     int *errcode);
extern void *sock_kmalloc(struct sock *sk, int size,
			  gfp_t priority);
extern void sock_kfree_s(struct sock *sk, void *mem, int size);
extern void sk_send_sigurg(struct sock *sk);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
extern int                      sock_no_bind(struct socket *, 
					     struct sockaddr *, int);
extern int                      sock_no_connect(struct socket *,
						struct sockaddr *, int, int);
extern int                      sock_no_socketpair(struct socket *,
						   struct socket *);
extern int                      sock_no_accept(struct socket *,
					       struct socket *, int);
extern int                      sock_no_getname(struct socket *,
						struct sockaddr *, int *, int);
extern unsigned int             sock_no_poll(struct file *, struct socket *,
					     struct poll_table_struct *);
extern int                      sock_no_ioctl(struct socket *, unsigned int,
					      unsigned long);
extern int			sock_no_listen(struct socket *, int);
extern int                      sock_no_shutdown(struct socket *, int);
extern int			sock_no_getsockopt(struct socket *, int , int,
						   char __user *, int __user *);
extern int			sock_no_setsockopt(struct socket *, int, int,
						   char __user *, int);
extern int                      sock_no_sendmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t);
extern int                      sock_no_recvmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t, int);
extern int			sock_no_mmap(struct file *file,
					     struct socket *sock,
					     struct vm_area_struct *vma);
extern ssize_t			sock_no_sendpage(struct socket *sock,
						struct page *page,
						int offset, size_t size, 
						int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
extern int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
extern int sock_common_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags);
extern int sock_common_setsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int optlen);
extern int compat_sock_common_getsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int __user *optlen);
extern int compat_sock_common_setsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int optlen);

extern void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */
 
/* Initialise core socket variables */
extern void sock_init_data(struct socket *sock, struct sock *sk);

/**
 *	sk_filter - run a packet through a socket filter
 *	@sk: sock associated with &sk_buff
 *	@skb: buffer to filter
 *	@needlock: set to 1 if the sock is not locked by caller.
 *
 * Run the filter code and then cut skb->data to correct size returned by
 * sk_run_filter. If pkt_len is 0 we toss packet. If skb->len is smaller
 * than pkt_len we keep whole skb->data. This is the socket level
 * wrapper to sk_run_filter. It returns 0 if the packet should
 * be accepted or -EPERM if the packet should be tossed.
 *
 */

static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	int err;
	struct sk_filter *filter;
	
	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;
	
	rcu_read_lock_bh();
	filter = sk->sk_filter;
	if (filter) {
		unsigned int pkt_len = sk_run_filter(skb, filter->insns,
				filter->len);
		err = pkt_len ? pskb_trim(skb, pkt_len) : -EPERM;
	}
 	rcu_read_unlock_bh();

	return err;
}

/**
 * 	sk_filter_rcu_free: Free a socket filter
 *	@rcu: rcu_head that contains the sk_filter to free
 */
static inline void sk_filter_rcu_free(struct rcu_head *rcu)
{
	struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);
	kfree(fp);
}

/**
 *	sk_filter_release: Release a socket filter
 *	@sk: socket
 *	@fp: filter to remove
 *
 *	Remove a filter from a socket and release its resources.
 */

static inline void sk_filter_release(struct sock *sk, struct sk_filter *fp)
{
	unsigned int size = sk_filter_len(fp);

	atomic_sub(size, &sk->sk_omem_alloc);

	if (atomic_dec_and_test(&fp->refcnt))
		call_rcu_bh(&fp->rcu, sk_filter_rcu_free);
}

static inline void sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
	atomic_inc(&fp->refcnt);
	atomic_add(sk_filter_len(fp), &sk->sk_omem_alloc);
}

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}

extern int sk_receive_skb(struct sock *sk, struct sk_buff *skb,
			  const int nested);

/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk->sk_socket = NULL;
	sk->sk_sleep  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_sleep = &parent->wait;
	parent->sk = sk;
	sk->sk_socket = parent;
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_copy(struct sock *nsk, const struct sock *osk)
{
#ifdef CONFIG_SECURITY_NETWORK
	void *sptr = nsk->sk_security;
#endif

	memcpy(nsk, osk, osk->sk_prot->obj_size);
#ifdef CONFIG_SECURITY_NETWORK
	nsk->sk_security = sptr;
	security_sk_clone(osk, nsk);
#endif
}

extern int sock_i_uid(struct sock *sk);
extern unsigned long sock_i_ino(struct sock *sk);

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return sk->sk_dst_cache;
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	read_lock(&sk->sk_dst_lock);
	dst = sk->sk_dst_cache;
	if (dst)
		dst_hold(dst);
	read_unlock(&sk->sk_dst_lock);
	return dst;
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	old_dst = sk->sk_dst_cache;
	sk->sk_dst_cache = dst;
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	write_lock(&sk->sk_dst_lock);
	__sk_dst_set(sk, dst);
	write_unlock(&sk->sk_dst_lock);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	struct dst_entry *old_dst;

	old_dst = sk->sk_dst_cache;
	sk->sk_dst_cache = NULL;
	dst_release(old_dst);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	write_lock(&sk->sk_dst_lock);
	__sk_dst_reset(sk);
	write_unlock(&sk->sk_dst_lock);
}

extern struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

extern struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

static inline int sk_can_gso(const struct sock *sk)
{
	return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

static inline void sk_setup_caps(struct sock *sk, struct dst_entry *dst)
{
	__sk_dst_set(sk, dst);
	sk->sk_route_caps = dst->dev->features;
	if (sk->sk_route_caps & NETIF_F_GSO)
		sk->sk_route_caps |= NETIF_F_GSO_MASK;
	if (sk_can_gso(sk)) {
		if (dst->header_len)
			sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
		else 
			sk->sk_route_caps |= NETIF_F_SG | NETIF_F_HW_CSUM;
	}
}

static inline void sk_charge_skb(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_wmem_queued   += skb->truesize;
	sk->sk_forward_alloc -= skb->truesize;
}

static inline int skb_copy_to_page(struct sock *sk, char __user *from,
				   struct sk_buff *skb, struct page *page,
				   int off, int copy)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		__wsum csum = csum_and_copy_from_user(from,
						     page_address(page) + off,
							    copy, 0, &err);
		if (err)
			return err;
		skb->csum = csum_block_add(skb->csum, csum, skb->len);
	} else if (copy_from_user(page_address(page) + off, from, copy))
		return -EFAULT;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk->sk_forward_alloc -= copy;
	return 0;
}

/*
 * 	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 * 	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
// 每个用于输出的SKB都要关联到一个传输控制块上，这样可以调整该传输控制块为发送
// 而分配的所有SKB数据区的大小，并设置此SKB的销毁函数
static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = sock_wfree;
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);
}

// 当UDP数据报的SKB传递并添加到UDP传输控制块的接收队列中，便会调用skb_set_owner_r()
// 设置该SKB的宿主，并设置此SKB的销毁函数，还要更新接收队列中所有报文数据的总长度
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
}

extern void sk_reset_timer(struct sock *sk, struct timer_list* timer,
			   unsigned long expires);

extern void sk_stop_timer(struct sock *sk, struct timer_list* timer);

extern int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

static inline int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
	/* Cast skb->rcvbuf to unsigned... It's pointless, but reduces
	   number of warnings when compiling with -W --ANK
	 */
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned)sk->sk_rcvbuf)
		return -ENOMEM;
	skb_set_owner_r(skb, sk);
	skb_queue_tail(&sk->sk_error_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb->len);
	return 0;
}

/*
 *	Recover an error report and clear atomically
 */
 
static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
		if (amt < 0) 
			amt = 0;
	}
	return amt;
}

// sk_wake_async()用来将SIGIO或SIGURG信号发送给在该套接口上的进程，通知该
// 进程可以对该文件进行读或写
// how：通知进程的方式：
// 0->检测标识应用程序通过recv等调用，是否在等待数据的接收
// 1->检测传输控制块的发送队列是否曾经到达上限
// 2->不做任何检测，直接向等待进程发送SIGIO信号
// 3->向等待进程发送SIGURG信号
// bind:通知进程的IO读写类型
// POLL_IN->输入数据有效，可以读
// POLL_OUT->输出缓冲区有效，可以写
// ...
static inline void sk_wake_async(struct sock *sk, int how, int band)
{
	if (sk->sk_socket && sk->sk_socket->fasync_list)
		sock_wake_async(sk->sk_socket, how, band);
}

#define SOCK_MIN_SNDBUF 2048
#define SOCK_MIN_RCVBUF 256

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued / 2);
		sk->sk_sndbuf = max(sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

static inline struct sk_buff *sk_stream_alloc_pskb(struct sock *sk,
						   int size, int mem,
						   gfp_t gfp)
{
	struct sk_buff *skb;
	int hdr_len;

	hdr_len = SKB_DATA_ALIGN(sk->sk_prot->max_header);
	skb = alloc_skb_fclone(size + hdr_len, gfp);
	if (skb) {
		skb->truesize += mem;
		if (sk_stream_wmem_schedule(sk, skb->truesize)) {
			skb_reserve(skb, hdr_len);
			return skb;
		}
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure();
		sk_stream_moderate_sndbuf(sk);
	}
	return NULL;
}

static inline struct sk_buff *sk_stream_alloc_skb(struct sock *sk,
						  int size,
						  gfp_t gfp)
{
	return sk_stream_alloc_pskb(sk, size, 0, gfp);
}

static inline struct page *sk_stream_alloc_page(struct sock *sk)
{
	struct page *page = NULL;

	page = alloc_pages(sk->sk_allocation, 0);
	if (!page) {
		sk->sk_prot->enter_memory_pressure();
		sk_stream_moderate_sndbuf(sk);
	}
	return page;
}

#define sk_stream_for_retrans_queue(skb, sk)				\
		for (skb = (sk)->sk_write_queue.next;			\
		     (skb != (sk)->sk_send_head) &&			\
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)

/*from STCP for fast SACK Process*/
#define sk_stream_for_retrans_queue_from(skb, sk)			\
		for (; (skb != (sk)->sk_send_head) &&                   \
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline int sock_writeable(const struct sock *sk) 
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf / 2);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

static __inline__ void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	struct timeval stamp;

	skb_get_timestamp(skb, &stamp);
	if (sock_flag(sk, SOCK_RCVTSTAMP)) {
		/* Race occurred between timestamp enabling and packet
		   receiving.  Fill in the current time for now. */
		if (stamp.tv_sec == 0)
			do_gettimeofday(&stamp);
		skb_set_timestamp(skb, &stamp);
		put_cmsg(msg, SOL_SOCKET, SO_TIMESTAMP, sizeof(struct timeval),
			 &stamp);
	} else
		sk->sk_stamp = stamp;
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 * @copied_early: flag indicating whether DMA operations copied this data early
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
#ifdef CONFIG_NET_DMA
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	if (!copied_early)
		__kfree_skb(skb);
	else
		__skb_queue_tail(&sk->sk_async_wait_queue, skb);
}
#else
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}
#endif

extern void sock_enable_timestamp(struct sock *sk);
extern int sock_get_timestamp(struct sock *, struct timeval __user *);

/* 
 *	Enable debug/info messages 
 */

#ifdef CONFIG_NETDEBUG
#define NETDEBUG(fmt, args...)	printk(fmt,##args)
#define LIMIT_NETDEBUG(fmt, args...) do { if (net_ratelimit()) printk(fmt,##args); } while(0)
#else
#define NETDEBUG(fmt, args...)	do { } while (0)
#define LIMIT_NETDEBUG(fmt, args...) do { } while(0)
#endif

/*
 * Macros for sleeping on a socket. Use them like this:
 *
 * SOCK_SLEEP_PRE(sk)
 * if (condition)
 * 	schedule();
 * SOCK_SLEEP_POST(sk)
 *
 * N.B. These are now obsolete and were, afaik, only ever used in DECnet
 * and when the last use of them in DECnet has gone, I'm intending to
 * remove them.
 */

#define SOCK_SLEEP_PRE(sk) 	{ struct task_struct *tsk = current; \
				DECLARE_WAITQUEUE(wait, tsk); \
				tsk->state = TASK_INTERRUPTIBLE; \
				add_wait_queue((sk)->sk_sleep, &wait); \
				release_sock(sk);

#define SOCK_SLEEP_POST(sk)	tsk->state = TASK_RUNNING; \
				remove_wait_queue((sk)->sk_sleep, &wait); \
				lock_sock(sk); \
				}

static inline void sock_valbool_flag(struct sock *sk, int bit, int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

#ifdef CONFIG_NET
int siocdevprivate_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
#else
static inline int siocdevprivate_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	return -ENODEV;
}
#endif

extern void sk_init(void);

#ifdef CONFIG_SYSCTL
extern struct ctl_table core_table[];
#endif

extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

#endif	/* _SOCK_H */
