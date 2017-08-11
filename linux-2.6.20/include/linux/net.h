/*
 * NET		An implementation of the SOCKET network access protocol.
 *		This is the master header file for the Linux NET layer,
 *		or, in plain English: the networking handling part of the
 *		kernel.
 *
 * Version:	@(#)net.h	1.0.3	05/25/93
 *
 * Authors:	Orest Zborowski, <obz@Kodak.COM>
 *		Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_NET_H
#define _LINUX_NET_H

#include <linux/wait.h>
#include <asm/socket.h>

struct poll_table_struct;
struct inode;

#define NPROTO		32		/* should be enough for now..	*/

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/

typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;

#define __SO_ACCEPTCON	(1 << 16)	/* performed a listen		*/

#ifdef __KERNEL__
#include <linux/stringify.h>
#include <linux/random.h>

#define SOCK_ASYNC_NOSPACE	0
#define SOCK_ASYNC_WAITDATA	1
#define SOCK_NOSPACE		2
#define SOCK_PASSCRED		3
#define SOCK_PASSSEC		4

#ifndef ARCH_HAS_SOCKET_TYPES
/**
 * enum sock_type - Socket types
 * @SOCK_STREAM: stream (connection) socket
 * @SOCK_DGRAM: datagram (conn.less) socket
 * @SOCK_RAW: raw socket
 * @SOCK_RDM: reliably-delivered message
 * @SOCK_SEQPACKET: sequential packet socket
 * @SOCK_DCCP: Datagram Congestion Control Protocol socket
 * @SOCK_PACKET: linux specific way of getting packets at the dev level.
 *		  For writing rarp and other similar things on the user level.
 *
 * When adding some new socket type please
 * grep ARCH_HAS_SOCKET_TYPE include/asm-* /socket.h, at least MIPS
 * overrides this enum for binary compat reasons.
 */
enum sock_type {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};

#define SOCK_MAX (SOCK_PACKET + 1)

#endif /* ARCH_HAS_SOCKET_TYPES */

/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @flags: socket flags (%SOCK_ASYNC_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @fasync_list: Asynchronous wake up list
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wait: wait queue for several uses
 *  @type: socket type (%SOCK_STREAM, etc)
 */
// 套接口代表了一条通信链路的一端，存储了该端所有与通信有关的信息
// 这些信息包括：使用的协议、套接口的状态、源和目的地址、到达的
// 连接队列、数据缓存和可选标志等
// 每个打开的套接字都有一个struct socket数据结构的实例
// struct socket数据结构中还包含一个文件描述符可由应用程序代码引用
struct socket {
	// 用于表示所在套接口所处的状态的标志，该标志有些状态只对TCP套接口有意义
	// 因为只有TCP是面向连接的协议，有状态转换的过程，而UDP和RAW则不需要维护
	// 套接口状态
	// SS_FREE:该套接口尚未分配，未使用
	// SS_UNCONNECTED:该套接口未连接任何一个对端的套接口
	// SS_CONNECTING:正在连接过程中
	// SS_CONNECTED:已连接一个套接口
	// SS_DISCONNECTING:正在断开连接的过程中
	// state与传输层建立的连接和关闭毫无关系，它反映的是内核外部
	// (用户地址空间)的常规套接字状态
	socket_state		state;
	// 一组标志位：
	// SOCK_ASYNC_NOSPACE:标识该套接口的发送队列是否已满
	// SOCK_ASYNC_WAITDATA:标识应用程序通过recv调用时，是否在等待数据的接收
	// SOCK_NOSPACE:标识非异步条件下该套接口的发送队列是否已满
	// ...
	unsigned long		flags;
	// 指向套接口系统调用中选择对应类型的套接口层接口，用来将套接口层系统调用映射到
	//　相应的传输层协议实现
	// TCP->inet_stream_ops
	// UDP->inet_dgram_ops
	// RAW->inet_sockraw_ops
	const struct proto_ops	*ops;
	// 存储了异步的通知队列，等待被唤醒的套接字列表
	struct fasync_struct	*fasync_list;
	// 指向了与该套接口相关联的file结构的指针
	// 在创建和打开套接字时，套接字层向应用程序返回该文件描述符
	// 应用程序通过文件描述符访问套接字
	struct file		*file;
	// 指向了与该套接口关联的传输控制块
	struct sock		*sk;
	// 等待该套接口的进程队列
	wait_queue_head_t	wait;
	// 套接口类型
	// SOCK_STREAM:基于连接的套接口
	// SOCK_DGRAM:基于数据报的套接口
	// SOCK_RAW:原始套接口
	// SOCK_PACKET:混杂模式套接口
	// ...
	short			type;
};

struct vm_area_struct;
struct page;
struct kiocb;
struct sockaddr;
struct msghdr;
struct module;

// proto_ops结构除了family和owner之外，是一组与套接口系统调用相对应的传输层函数指针
// 因此整个proto_ops结构可以看做是一张套接口系统调用到传输层函数的跳转表，其中的某些
// 操作会继续通过proto结构跳转表，进入具体的传输层或网络层的处理
struct proto_ops {
	int		family;
	struct module	*owner;
	int		(*release)   (struct socket *sock);
	int		(*bind)	     (struct socket *sock,
				      struct sockaddr *myaddr,
				      int sockaddr_len);
	int		(*connect)   (struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags);
	int		(*socketpair)(struct socket *sock1,
				      struct socket *sock2);
	int		(*accept)    (struct socket *sock,
				      struct socket *newsock, int flags);
	int		(*getname)   (struct socket *sock,
				      struct sockaddr *addr,
				      int *sockaddr_len, int peer);
	unsigned int	(*poll)	     (struct file *file, struct socket *sock,
				      struct poll_table_struct *wait);
	int		(*ioctl)     (struct socket *sock, unsigned int cmd,
				      unsigned long arg);
	int	 	(*compat_ioctl) (struct socket *sock, unsigned int cmd,
				      unsigned long arg);
	int		(*listen)    (struct socket *sock, int len);
	int		(*shutdown)  (struct socket *sock, int flags);
	int		(*setsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int optlen);
	int		(*getsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int __user *optlen);
	int		(*compat_setsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int optlen);
	int		(*compat_getsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int __user *optlen);
	int		(*sendmsg)   (struct kiocb *iocb, struct socket *sock,
				      struct msghdr *m, size_t total_len);
	int		(*recvmsg)   (struct kiocb *iocb, struct socket *sock,
				      struct msghdr *m, size_t total_len,
				      int flags);
	int		(*mmap)	     (struct file *file, struct socket *sock,
				      struct vm_area_struct * vma);
	ssize_t		(*sendpage)  (struct socket *sock, struct page *page,
				      int offset, size_t size, int flags);
};

// net_proto_family结构提供了一个协议族到套接口之间的接口
// 屏蔽了不同的协议族在传输层的结构和实现的巨大差异，使得各协议族
// 在初始化时，可以统一使用sock_register()注册到net_family数组中
// 内核中所有传输层协议的套接字创建函数结构块组织在
// struct net_proto_family　*net_families[NPROTO]中，数组中的每个
// 成员是各协议的套接字创建、初始化函数
struct net_proto_family {
	// 协议族对应的协议族常量，Internet协议族是PF_INET
	int		family;
	// 协议族的套接口创建函数指针，每个协议族都有不同的实现方式
	// Internet协议族的net_proto_family结构实例为inet_family_ops
	// 套接口创建函数为inet_create()
	int		(*create)(struct socket *sock, int protocol);
	struct module	*owner;
};

struct iovec;
struct kvec;

extern int	     sock_wake_async(struct socket *sk, int how, int band);
extern int	     sock_register(const struct net_proto_family *fam);
extern void	     sock_unregister(int family);
extern int	     sock_create(int family, int type, int proto,
				 struct socket **res);
extern int	     sock_create_kern(int family, int type, int proto,
				      struct socket **res);
extern int	     sock_create_lite(int family, int type, int proto,
				      struct socket **res); 
extern void	     sock_release(struct socket *sock);
extern int   	     sock_sendmsg(struct socket *sock, struct msghdr *msg,
				  size_t len);
extern int	     sock_recvmsg(struct socket *sock, struct msghdr *msg,
				  size_t size, int flags);
extern int 	     sock_map_fd(struct socket *sock);
extern struct socket *sockfd_lookup(int fd, int *err);
#define		     sockfd_put(sock) fput(sock->file)
extern int	     net_ratelimit(void);

#define net_random()		random32()
#define net_srandom(seed)	srandom32((__force u32)seed)

extern int   	     kernel_sendmsg(struct socket *sock, struct msghdr *msg,
				    struct kvec *vec, size_t num, size_t len);
extern int   	     kernel_recvmsg(struct socket *sock, struct msghdr *msg,
				    struct kvec *vec, size_t num,
				    size_t len, int flags);

extern int kernel_bind(struct socket *sock, struct sockaddr *addr,
		       int addrlen);
extern int kernel_listen(struct socket *sock, int backlog);
extern int kernel_accept(struct socket *sock, struct socket **newsock,
			 int flags);
extern int kernel_connect(struct socket *sock, struct sockaddr *addr,
			  int addrlen, int flags);
extern int kernel_getsockname(struct socket *sock, struct sockaddr *addr,
			      int *addrlen);
extern int kernel_getpeername(struct socket *sock, struct sockaddr *addr,
			      int *addrlen);
extern int kernel_getsockopt(struct socket *sock, int level, int optname,
			     char *optval, int *optlen);
extern int kernel_setsockopt(struct socket *sock, int level, int optname,
			     char *optval, int optlen);
extern int kernel_sendpage(struct socket *sock, struct page *page, int offset,
			   size_t size, int flags);
extern int kernel_sock_ioctl(struct socket *sock, int cmd, unsigned long arg);

#ifndef CONFIG_SMP
#define SOCKOPS_WRAPPED(name) name
#define SOCKOPS_WRAP(name, fam)
#else

#define SOCKOPS_WRAPPED(name) __unlocked_##name

#define SOCKCALL_WRAP(name, call, parms, args)		\
static int __lock_##name##_##call  parms		\
{							\
	int ret;					\
	lock_kernel();					\
	ret = __unlocked_##name##_ops.call  args ;\
	unlock_kernel();				\
	return ret;					\
}

#define SOCKCALL_UWRAP(name, call, parms, args)		\
static unsigned int __lock_##name##_##call  parms	\
{							\
	int ret;					\
	lock_kernel();					\
	ret = __unlocked_##name##_ops.call  args ;\
	unlock_kernel();				\
	return ret;					\
}


#define SOCKOPS_WRAP(name, fam)					\
SOCKCALL_WRAP(name, release, (struct socket *sock), (sock))	\
SOCKCALL_WRAP(name, bind, (struct socket *sock, struct sockaddr *uaddr, int addr_len), \
	      (sock, uaddr, addr_len))				\
SOCKCALL_WRAP(name, connect, (struct socket *sock, struct sockaddr * uaddr, \
			      int addr_len, int flags), 	\
	      (sock, uaddr, addr_len, flags))			\
SOCKCALL_WRAP(name, socketpair, (struct socket *sock1, struct socket *sock2), \
	      (sock1, sock2))					\
SOCKCALL_WRAP(name, accept, (struct socket *sock, struct socket *newsock, \
			 int flags), (sock, newsock, flags)) \
SOCKCALL_WRAP(name, getname, (struct socket *sock, struct sockaddr *uaddr, \
			 int *addr_len, int peer), (sock, uaddr, addr_len, peer)) \
SOCKCALL_UWRAP(name, poll, (struct file *file, struct socket *sock, struct poll_table_struct *wait), \
	      (file, sock, wait)) \
SOCKCALL_WRAP(name, ioctl, (struct socket *sock, unsigned int cmd, \
			 unsigned long arg), (sock, cmd, arg)) \
SOCKCALL_WRAP(name, compat_ioctl, (struct socket *sock, unsigned int cmd, \
			 unsigned long arg), (sock, cmd, arg)) \
SOCKCALL_WRAP(name, listen, (struct socket *sock, int len), (sock, len)) \
SOCKCALL_WRAP(name, shutdown, (struct socket *sock, int flags), (sock, flags)) \
SOCKCALL_WRAP(name, setsockopt, (struct socket *sock, int level, int optname, \
			 char __user *optval, int optlen), (sock, level, optname, optval, optlen)) \
SOCKCALL_WRAP(name, getsockopt, (struct socket *sock, int level, int optname, \
			 char __user *optval, int __user *optlen), (sock, level, optname, optval, optlen)) \
SOCKCALL_WRAP(name, sendmsg, (struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len), \
	      (iocb, sock, m, len)) \
SOCKCALL_WRAP(name, recvmsg, (struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len, int flags), \
	      (iocb, sock, m, len, flags)) \
SOCKCALL_WRAP(name, mmap, (struct file *file, struct socket *sock, struct vm_area_struct *vma), \
	      (file, sock, vma)) \
	      \
static const struct proto_ops name##_ops = {			\
	.family		= fam,				\
	.owner		= THIS_MODULE,			\
	.release	= __lock_##name##_release,	\
	.bind		= __lock_##name##_bind,		\
	.connect	= __lock_##name##_connect,	\
	.socketpair	= __lock_##name##_socketpair,	\
	.accept		= __lock_##name##_accept,	\
	.getname	= __lock_##name##_getname,	\
	.poll		= __lock_##name##_poll,		\
	.ioctl		= __lock_##name##_ioctl,	\
	.compat_ioctl	= __lock_##name##_compat_ioctl,	\
	.listen		= __lock_##name##_listen,	\
	.shutdown	= __lock_##name##_shutdown,	\
	.setsockopt	= __lock_##name##_setsockopt,	\
	.getsockopt	= __lock_##name##_getsockopt,	\
	.sendmsg	= __lock_##name##_sendmsg,	\
	.recvmsg	= __lock_##name##_recvmsg,	\
	.mmap		= __lock_##name##_mmap,		\
};

#endif

#define MODULE_ALIAS_NETPROTO(proto) \
	MODULE_ALIAS("net-pf-" __stringify(proto))

#define MODULE_ALIAS_NET_PF_PROTO(pf, proto) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto))

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
extern ctl_table net_table[];
extern int net_msg_cost;
extern int net_msg_burst;
#endif

#endif /* __KERNEL__ */
#endif	/* _LINUX_NET_H */
