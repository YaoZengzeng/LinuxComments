/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_INET protocol family socket handler.
 *
 * Version:	$Id: af_inet.c,v 1.137 2002/02/01 22:01:03 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 * Changes (see also sock.c)
 *
 *		piggy,
 *		Karl Knutson	:	Socket protocol table
 *		A.N.Kuznetsov	:	Socket death error in accept().
 *		John Richardson :	Fix non blocking error in connect()
 *					so sockets that fail to connect
 *					don't return -EINPROGRESS.
 *		Alan Cox	:	Asynchronous I/O support
 *		Alan Cox	:	Keep correct socket pointer on sock
 *					structures
 *					when accept() ed
 *		Alan Cox	:	Semantics of SO_LINGER aren't state
 *					moved to close when you look carefully.
 *					With this fixed and the accept bug fixed
 *					some RPC stuff seems happier.
 *		Niibe Yutaka	:	4.4BSD style write async I/O
 *		Alan Cox,
 *		Tony Gale 	:	Fixed reuse semantics.
 *		Alan Cox	:	bind() shouldn't abort existing but dead
 *					sockets. Stops FTP netin:.. I hope.
 *		Alan Cox	:	bind() works correctly for RAW sockets.
 *					Note that FreeBSD at least was broken
 *					in this respect so be careful with
 *					compatibility tests...
 *		Alan Cox	:	routing cache support
 *		Alan Cox	:	memzero the socket structure for
 *					compactness.
 *		Matt Day	:	nonblock connect error handler
 *		Alan Cox	:	Allow large numbers of pending sockets
 *					(eg for big web sites), but only if
 *					specifically application requested.
 *		Alan Cox	:	New buffering throughout IP. Used
 *					dumbly.
 *		Alan Cox	:	New buffering now used smartly.
 *		Alan Cox	:	BSD rather than common sense
 *					interpretation of listen.
 *		Germano Caronni	:	Assorted small races.
 *		Alan Cox	:	sendmsg/recvmsg basic support.
 *		Alan Cox	:	Only sendmsg/recvmsg now supported.
 *		Alan Cox	:	Locked down bind (see security list).
 *		Alan Cox	:	Loosened bind a little.
 *		Mike McLagan	:	ADD/DEL DLCI Ioctls
 *	Willy Konynenberg	:	Transparent proxying support.
 *		David S. Miller	:	New socket lookup architecture.
 *					Some other random speedups.
 *		Cyrus Durgin	:	Cleaned up file for kmod hacks.
 *		Andi Kleen	:	Fix inet_stream_connect TCP race.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/netfilter_ipv4.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/smp_lock.h>
#include <linux/inet.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/ipip.h>
#include <net/inet_common.h>
#include <net/xfrm.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#endif

DEFINE_SNMP_STAT(struct linux_mib, net_statistics) __read_mostly;

extern void ip_mc_drop_socket(struct sock *sk);

/* The inetsw table contains everything that inet_create needs to
 * build a new socket.
 */
// inetsw[SOCK_MAX]是协议交换表数组，数组中的每个成员都是一个协议族的交换表
// 用于存放某个协议族中各个协议实例的套接字系统调用函数与协议套接字函数的对应关系
static struct list_head inetsw[SOCK_MAX];
static DEFINE_SPINLOCK(inetsw_lock);

/* New destruction routine */

void inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		printk("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		printk("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	BUG_TRAP(!atomic_read(&sk->sk_rmem_alloc));
	BUG_TRAP(!atomic_read(&sk->sk_wmem_alloc));
	BUG_TRAP(!sk->sk_wmem_queued);
	BUG_TRAP(!sk->sk_forward_alloc);

	kfree(inet->opt);
	dst_release(sk->sk_dst_cache);
	sk_refcnt_debug_dec(sk);
}

/*
 *	The routines beyond this point handle the behaviour of an AF_INET
 *	socket object. Mostly it punts to the subprotocols of IP to do
 *	the work.
 */

/*
 *	Automatically bind an unbound socket.
 */

static int inet_autobind(struct sock *sk)
{
	struct inet_sock *inet;
	/* We may need to bind the socket. */
	lock_sock(sk);
	inet = inet_sk(sk);
	if (!inet->num) {
		if (sk->sk_prot->get_port(sk, 0)) {
			release_sock(sk);
			return -EAGAIN;
		}
		inet->sport = htons(inet->num);
	}
	release_sock(sk);
	return 0;
}

/*
 *	Move a socket into listening state.
 */
// inet_listen()函数为listen系统调用套接口层的实现
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	// 检测调用listen的套接口的当前状态和类型，如果套接口状态不是SS_UNCONNECTED或
	// 套接口类型不是SOCK_STREAM，则不允许进行侦听操作，返回相应错误码
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	// 进行listen调用的传输控制块的状态，如果该传输控制块在TCP_CLOSE或TCP_LISTEN
	// 状态，则不能进行侦听操作，返回相应错误码
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	// 如果传输控制块不在LISTEN状态，则调用inet_csk_listen_start()进行侦听操作
	if (old_state != TCP_LISTEN) {
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	// 最后，无论是否在LISTEN状态都需设置传输控制块的连接队列长度上限
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}

/*
 *	Create an inet socket.
 */
// 用于创建与该套接口对应的传输控制块，并与之关联起来
static int inet_create(struct socket *sock, int protocol)
{
	struct sock *sk;
	struct list_head *p;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	char answer_no_check;
	int try_loading_module = 0;
	int err;

	// 初始化套接口为SS_UNCONNECTED状态
	sock->state = SS_UNCONNECTED;

	/* Look for the requested type/protocol pair. */
	answer = NULL;
// 查询协议交换表，根据协议族套接字创建类型type获取要创建的协议实例
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	// 以套接口类型(sock->type)为关键字遍历inetsw散列表
	list_for_each_rcu(p, &inetsw[sock->type]) {
		// 通过计算偏移的方法获取指向inet_protosw结构的指针
		answer = list_entry(p, struct inet_protosw, list);

		/* Check the non-wild match. */
		// 根据协议类型获取匹配的inet_protosw结构的实例
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
		answer = NULL;
	}

	// 如果未能在inetsw中获取匹配的inet_protosw结构的实例，则需要加载
	// 相应的内核模块，之后再回到lookup_protocol标签处，获取匹配的inet_protosw
	// 结构实例
	if (unlikely(answer == NULL)) {
		// 尝试加载模块最多不超过两次，且第一次要求模块的协议及套接口类型与参数中给定的
		// 值相符，而第二次只需协议相同即可，以加大可选择的范围，如果两次尝试后还是未能
		// 获取匹配的inet_protosw结构实例，则创建套接口以失败告终
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INET, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INET, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	// 在进程描述符中有成员为cap_effective，主要用来标识当前进程的能力，其中
	// 每种能力用一位来表示，1表示具有某种能力，0表示没有，在这里主要判断当前
	// 进程是否有answer->capability这种能力，如果没有则不能创建套接口
	if (answer->capability > 0 && !capable(answer->capability))
		goto out_rcu_unlock;

	// 设置套接口中的套接口层和传输层之间的接口ops
	sock->ops = answer->ops;
	// 临时获取inet_protosw中的一些参数，以备后用
	answer_prot = answer->prot;
	answer_no_check = answer->no_check;
	answer_flags = answer->flags;
	rcu_read_unlock();

	BUG_TRAP(answer_prot->slab != NULL);

	err = -ENOBUFS;
	// 调用sk_alloc()，根据协议族等参数，分配一个传输控制块
	sk = sk_alloc(PF_INET, GFP_KERNEL, answer_prot, 1);
	if (sk == NULL)
		goto out;

	// 设置传输控制块是否需要校验和以及是否可以重用地址和端口的标志
	err = 0;
	sk->sk_no_check = answer_no_check;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = 1;

	// 设置inet_sock块中的is_icsk，标识是否为面向连接的传输控制块
	inet = inet_sk(sk);
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	// 如果套接口类型为原始套接口，则设置本地端口为协议号，并且如果协议
	// 为RAW协议，则设置inet_sock块中的hdrincl,表示需要自己构建IP首部
	if (SOCK_RAW == sock->type) {
		inet->num = protocol;
		if (IPPROTO_RAW == protocol)
			inet->hdrincl = 1;
	}

	// 根据系统参数ip_no_pmtu_disc设置创建的传输控制块是否支持PMTU
	if (ipv4_config.no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	// 调用sock_init_data()对传输控制块进行初始化
	inet->id = 0;

	sock_init_data(sock, sk);

	// 初始化传输控制块中的sk_destruct成员，inet_sock_destruct在
	// 套接口释放时被回调，进行一些资源回收和清理的工作
	sk->sk_destruct	   = inet_sock_destruct;
	// 设置传输控制块中的协议族和协议号标识
	sk->sk_family	   = PF_INET;
	sk->sk_protocol	   = protocol;
	// 设置传输控制块中的sk_backlog_rcv后备队列接收函数
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	// 设置传输控制块中单播的TTL
	inet->uc_ttl	= -1;
	// 组播是否发向回路标志
	inet->mc_loop	= 1;
	// 组播的TTL
	inet->mc_ttl	= 1;
	// 组播使用的本地设备接口的索引
	inet->mc_index	= 0;
	//　初始化传输控制块组播组列表
	inet->mc_list	= NULL;

	sk_refcnt_debug_inc(sk);

	// 如果传输控制块中的num设置了本地端口号，则设置传输控制块中的sport的
	// 网络字节序格式的本地端口号
	if (inet->num) {
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->sport = htons(inet->num);
		/* Add to protocol hash chains. */
		// 调用传输层接口上的hash()，把传输控制块加入到管理的散列表中
		// TCP中为tcp_v4_hash()，UDP中为udp_lib_hash()
		sk->sk_prot->hash(sk);
	}

	// 如果init()指针已被设置，则调用init()进行具体传输控制块的初始化
	// TCP中为tcp_v4_init_sock()，而UDP中则没有对应的实现，此时，与
	// 协议族有关的套接口及传输控制块创建过程全部结束，将返回到创建套接口
	// 的统一接口中
	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err)
			sk_common_release(sk);
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}


/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
// inet_release()为IPv4协议族中close系统调用的套接口层的实现
int inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		/* Applications forget to leave groups before exiting */
		// 调用ip_mc_drop_socket()离开加入的组播组
		ip_mc_drop_socket(sk);

		/* If linger is set, we don't return until the close
		 * is complete.  Otherwise we return immediately. The
		 * actually closing is done the same either way.
		 *
		 * If the close is due to the process exiting, we never
		 * linger..
		 */
		// 如果当前套接口设置了SOCK_LINGER(若有数据待发送则延时关闭)选项
		// 并且当前进程不在退出过程中，则获取延时关闭的时间
		timeout = 0;
		if (sock_flag(sk, SOCK_LINGER) &&
		    !(current->flags & PF_EXITING))
			timeout = sk->sk_lingertime;
		sock->sk = NULL;
		// 通过传输层接口prot结构，调用close接口，用前面获取延时关闭的时间作参数
		// 进行关闭操作
		sk->sk_prot->close(sk, timeout);
	}
	return 0;
}

/* It is off by default, see below. */
int sysctl_ip_nonlocal_bind __read_mostly;
// inet_bind()为bind系统调用的套接口层实现
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	unsigned short snum;
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	// 如果当前套接口在传输层接口上有bind的实现，则直接调用传输层接口上的bind()
	// 直接进行bind操作即可，否则进行下面的操作。目前只有SOCK_RAW类型的套接口
	// 的传输层接口实现了bind接口，为raw_bind()
	if (sk->sk_prot->bind) {
		err = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}
	err = -EINVAL;
	// 对参数进行合法性校验
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	// 调用inet_addr_type()得到地址的类型
	chk_addr_ret = inet_addr_type(addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	// 根据系统参数结合获取到的地址类型进行校验，以便决定是否可以进行地址和端口的绑定
	err = -EADDRNOTAVAIL;
	if (!sysctl_ip_nonlocal_bind &&	// 是否允许绑定非本机地址
	    !inet->freebind &&		// 是否允许自由绑定
	    addr->sin_addr.s_addr != INADDR_ANY &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	// 对待绑定的端口进行合法性校验，并判断是否允许绑定小于1024的特权端口
	snum = ntohs(addr->sin_port);
	err = -EACCES;
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	// 对传输控制块的状态进行检查，这里使用TCP_CLOSE标识，事实上UDP的传输
	// 控制块也用TCP_CLOSE标识关闭标志
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->num)
		goto out_release_sock;

	// 将地址设置到传输控制块中
	inet->rcv_saddr = inet->saddr = addr->sin_addr.s_addr;
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		// 如果地址类型为组播或广播，则将源地址设置为0
		inet->saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	// 调用传输层接口上的get_port()，进行具体传输层的地址绑定，TCP中对应
	// 的函数为tcp_v4_get_port()，而UDP中为upd_v4_get_port()
	if (sk->sk_prot->get_port(sk, snum)) {
		// 检查失败就清空设置的地址
		inet->saddr = inet->rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	// 标识传输控制块已经绑定了本地地址和本地端口
	if (inet->rcv_saddr)
		// 如果已经设置地址就增加锁标志，表示已经绑定了地址
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		// 如果端口也已经确定也要增加锁标志，表示已经绑定了端口
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	// 设置本地端口（网络字节序），初始化目的地址、目的端口，由于重新进行了绑定
	// 因此需要清除传输控制块的路由缓存项
	inet->sport = htons(inet->num);
	inet->daddr = 0;
	inet->dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}

int inet_dgram_connect(struct socket *sock, struct sockaddr * uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;
	return sk->sk_prot->connect(sk, (struct sockaddr *)uaddr, addr_len);
}

static long inet_wait_for_connect(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	lock_sock(sk);

	if (uaddr->sa_family == AF_UNSPEC) {
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)
			goto out;

		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;

  		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		/* Error code is set above */
		if (!timeo || !inet_wait_for_connect(sk, timeo))
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */

	sock->state = SS_CONNECTED;
	err = 0;
out:
	release_sock(sk);
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */
// inet_accept()为accept系统调用的套接口层接口的实现
int inet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	// 根据套接口获取相应的传输控制块
	struct sock *sk1 = sock->sk;
	int err = -EINVAL;
	// 调用accept的传输接口实现函数inet_csk_accept()获取已完成连接（被接收）的传输控制块
	// 称之为子传输控制块
	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err);

	if (!sk2)
		goto do_err;

	lock_sock(sk2);

	BUG_TRAP((1 << sk2->sk_state) &
		 (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_CLOSE));

	// 如果accept成功，则调用sock_graft()把子套接口和传输控制块关联起来以便这两者之间相互索引
	sock_graft(sk2, newsock);

	// 设置子套接口状态为SS_CONNECTED
	newsock->state = SS_CONNECTED;
	err = 0;
	release_sock(sk2);
do_err:
	return err;
}


/*
 *	This does both peername and sockname.
 */
int inet_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct inet_sock *inet	= inet_sk(sk);
	struct sockaddr_in *sin	= (struct sockaddr_in *)uaddr;

	sin->sin_family = AF_INET;
	if (peer) {
		if (!inet->dport ||
		    (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
		     peer == 1))
			return -ENOTCONN;
		sin->sin_port = inet->dport;
		sin->sin_addr.s_addr = inet->daddr;
	} else {
		__be32 addr = inet->rcv_saddr;
		if (!addr)
			addr = inet->saddr;
		sin->sin_port = inet->sport;
		sin->sin_addr.s_addr = addr;
	}
	memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	*uaddr_len = sizeof(*sin);
	return 0;
}

int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}


static ssize_t inet_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);
	return sock_no_sendpage(sock, page, offset, size, flags);
}


int inet_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	/* This should really check to make sure
	 * the socket is a TCP socket. (WHY AC...)
	 */
	// 使how增加1是为了利用how变量进行位操作
	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	// 校验how的原始值必须为0,1,2
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 */
		return -EINVAL;

	lock_sock(sk);
	// 根据传输控制块的状态重新设置套接口的状态，使套接口的状态在完成关闭之前只有两种
	if (sock->state == SS_CONNECTING) {
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
			sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) {
	case TCP_CLOSE:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	// 如果传输控制块处于其他状态，则设置shutdown的关闭方式后，调用传输层
	// 接口上的shutdown()，进行具体传输层的关闭操作
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	// 如果传输控制块的状态处于TCP_LISTEN，则需要判断关闭的方式，如果有接收方向
	// 的关闭操作，则和SYN_SENT状态处理用于，进行具体传输层的断开连接操作，TCP中
	// 为tcp_disconnect()
	case TCP_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	// 如果传输控制块的状态处于连接状态过程中(SYN_SENT)，则不允许再继续连接
	// 因此调用disconnect()，进行具体传输层的断开连接操作
	case TCP_SYN_SENT:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	// 调用sk_state_change()，唤醒在传输控制块的等待队列上的进程，sk_state_change函数
	// 指针在sock_init_data()中被初始化
	sk->sk_state_change(sk);
	release_sock(sk);
	return err;
}

/*
 *	ioctl() calls you can issue on an INET socket. Most of these are
 *	device configuration and stuff and very rarely used. Some ioctls
 *	pass on to the socket itself.
 *
 *	NOTE: I like the idea of a module for the config stuff. ie ifconfig
 *	loads the devconfigure module does its configuring and unloads it.
 *	There's a good 20K of config code hanging around the kernel.
 */

int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err = 0;

	switch (cmd) {
		case SIOCGSTAMP:
			err = sock_get_timestamp(sk, (struct timeval __user *)arg);
			break;
		case SIOCADDRT:
		case SIOCDELRT:
		case SIOCRTMSG:
			err = ip_rt_ioctl(cmd, (void __user *)arg);
			break;
		case SIOCDARP:
		case SIOCGARP:
		case SIOCSARP:
			err = arp_ioctl(cmd, (void __user *)arg);
			break;
		case SIOCGIFADDR:
		case SIOCSIFADDR:
		case SIOCGIFBRDADDR:
		case SIOCSIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCSIFNETMASK:
		case SIOCGIFDSTADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFPFLAGS:
		case SIOCGIFPFLAGS:
		case SIOCSIFFLAGS:
			err = devinet_ioctl(cmd, (void __user *)arg);
			break;
		default:
			if (sk->sk_prot->ioctl)
				err = sk->sk_prot->ioctl(sk, cmd, arg);
			else
				err = -ENOIOCTLCMD;
			break;
	}
	return err;
}

const struct proto_ops inet_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	//　绑定地址函数
	.bind		   = inet_bind,
	.connect	   = inet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	.poll		   = tcp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = tcp_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

const struct proto_ops inet_dgram_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = udp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

/*
 * For SOCK_RAW sockets; should be the same as inet_dgram_ops but without
 * udp_poll
 */
static const struct proto_ops inet_sockraw_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

static struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};

/* Upon startup we insert all the elements in inetsw_array[] into
 * the linked list inetsw.
 */
static struct inet_protosw inetsw_array[] =
{
        {
                .type =       SOCK_STREAM,
                .protocol =   IPPROTO_TCP,
                // 定义套接口传输层接口为tcp_port
                .prot =       &tcp_prot,
                // 套接口层借口为inet_stream_ops
                .ops =        &inet_stream_ops,
                // 创建STREAM类型接口无需进行capability检验
                .capability = -1,
                // 始终需要进行校验和操作
                .no_check =   0,
                // 标示tcp模块在系统运行过程中不能被替换或卸载
                // tcp套接口为面向连接的套接口，用于在创建传输控制块时初始化is_icsk成员
                .flags =      INET_PROTOSW_PERMANENT |
			      INET_PROTOSW_ICSK,
        },

        {
        		// UDP套接口类型为SOCK_DGRAM
                .type =       SOCK_DGRAM,
                // UDP协议类型为IPPROTO_UDP 
                .protocol =   IPPROTO_UDP,
                // UDP的传输层接口为udp_prot
                .prot =       &udp_prot,
                // UDP的套接口层操作接口为inet_dgram_ops
                .ops =        &inet_dgram_ops,
                // 在创建UDP套接口时需检验创建该套接口的进程是否有这种能力
                // capability为-1表示无需作检验
                .capability = -1,
                // UDP的校验和是课选的,UDP_CSUM_DEFAULT标识UDP需要进行正常的
                // 校验和操作
                .no_check =   UDP_CSUM_DEFAULT,
                // 标识不能作为内核模块进行动态的加载或卸载
                .flags =      INET_PROTOSW_PERMANENT,
       },
        

       {
               .type =       SOCK_RAW,
               // "虚拟的IP协议"类型
               .protocol =   IPPROTO_IP,	/* wild card */
               .prot =       &raw_prot,
               .ops =        &inet_sockraw_ops,
               .capability = CAP_NET_RAW,
               .no_check =   UDP_CSUM_DEFAULT,
               .flags =      INET_PROTOSW_REUSE,
       }
};

#define INETSW_ARRAY_LEN (sizeof(inetsw_array) / sizeof(struct inet_protosw))

void inet_register_protosw(struct inet_protosw *p)
{
	struct list_head *lh;
	struct inet_protosw *answer;
	int protocol = p->protocol;
	struct list_head *last_perm;

	spin_lock_bh(&inetsw_lock);

	if (p->type >= SOCK_MAX)
		goto out_illegal;

	/* If we are trying to override a permanent protocol, bail. */
	answer = NULL;
	last_perm = &inetsw[p->type];
	list_for_each(lh, &inetsw[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (INET_PROTOSW_PERMANENT & answer->flags) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	/* Add the new entry after the last permanent entry if any, so that
	 * the new entry does not override a permanent entry when matched with
	 * a wild-card protocol. But it is allowed to override any existing
	 * non-permanent entry.  This means that when we remove this entry, the 
	 * system automatically returns to the old behavior.
	 */
	list_add_rcu(&p->list, last_perm);
out:
	spin_unlock_bh(&inetsw_lock);

	synchronize_net();

	return;

out_permanent:
	printk(KERN_ERR "Attempt to override permanent protocol %d.\n",
	       protocol);
	goto out;

out_illegal:
	printk(KERN_ERR
	       "Ignoring attempt to register invalid socket type %d.\n",
	       p->type);
	goto out;
}

void inet_unregister_protosw(struct inet_protosw *p)
{
	if (INET_PROTOSW_PERMANENT & p->flags) {
		printk(KERN_ERR
		       "Attempt to unregister permanent protocol %d.\n",
		       p->protocol);
	} else {
		spin_lock_bh(&inetsw_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetsw_lock);

		synchronize_net();
	}
}

/*
 *      Shall we try to damage output packets if routing dev changes?
 */

int sysctl_ip_dynaddr __read_mostly;

static int inet_sk_reselect_saddr(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;
	struct rtable *rt;
	__be32 old_saddr = inet->saddr;
	__be32 new_saddr;
	__be32 daddr = inet->daddr;

	if (inet->opt && inet->opt->srr)
		daddr = inet->opt->faddr;

	/* Query new route. */
	err = ip_route_connect(&rt, daddr, 0,
			       RT_CONN_FLAGS(sk),
			       sk->sk_bound_dev_if,
			       sk->sk_protocol,
			       inet->sport, inet->dport, sk);
	if (err)
		return err;

	sk_setup_caps(sk, &rt->u.dst);

	new_saddr = rt->rt_src;

	if (new_saddr == old_saddr)
		return 0;

	if (sysctl_ip_dynaddr > 1) {
		printk(KERN_INFO "%s(): shifting inet->"
				 "saddr from %d.%d.%d.%d to %d.%d.%d.%d\n",
		       __FUNCTION__,
		       NIPQUAD(old_saddr),
		       NIPQUAD(new_saddr));
	}

	inet->saddr = inet->rcv_saddr = new_saddr;

	/*
	 * XXX The only one ugly spot where we need to
	 * XXX really change the sockets identity after
	 * XXX it has entered the hashes. -DaveM
	 *
	 * Besides that, it does not check for connection
	 * uniqueness. Wait for troubles.
	 */
	__sk_prot_rehash(sk);
	return 0;
}

int inet_sk_rebuild_header(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
	__be32 daddr;
	int err;

	/* Route is OK, nothing to do. */
	if (rt)
		return 0;

	/* Reroute. */
	daddr = inet->daddr;
	if (inet->opt && inet->opt->srr)
		daddr = inet->opt->faddr;
{
	struct flowi fl = {
		.oif = sk->sk_bound_dev_if,
		.nl_u = {
			.ip4_u = {
				.daddr	= daddr,
				.saddr	= inet->saddr,
				.tos	= RT_CONN_FLAGS(sk),
			},
		},
		.proto = sk->sk_protocol,
		.uli_u = {
			.ports = {
				.sport = inet->sport,
				.dport = inet->dport,
			},
		},
	};
						
	security_sk_classify_flow(sk, &fl);
	err = ip_route_output_flow(&rt, &fl, sk, 0);
}
	if (!err)
		sk_setup_caps(sk, &rt->u.dst);
	else {
		/* Routing failed... */
		sk->sk_route_caps = 0;
		/*
		 * Other protocols have to map its equivalent state to TCP_SYN_SENT.
		 * DCCP maps its DCCP_REQUESTING state to TCP_SYN_SENT. -acme
		 */
		if (!sysctl_ip_dynaddr ||
		    sk->sk_state != TCP_SYN_SENT ||
		    (sk->sk_userlocks & SOCK_BINDADDR_LOCK) ||
		    (err = inet_sk_reselect_saddr(sk)) != 0)
			sk->sk_err_soft = -err;
	}

	return err;
}

EXPORT_SYMBOL(inet_sk_rebuild_header);

static int inet_gso_send_check(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct net_protocol *ops;
	int proto;
	int ihl;
	int err = -EINVAL;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	iph = skb->nh.iph;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	skb->h.raw = __skb_pull(skb, ihl);
	iph = skb->nh.iph;
	proto = iph->protocol & (MAX_INET_PROTOS - 1);
	err = -EPROTONOSUPPORT;

	rcu_read_lock();
	ops = rcu_dereference(inet_protos[proto]);
	if (likely(ops && ops->gso_send_check))
		err = ops->gso_send_check(skb);
	rcu_read_unlock();

out:
	return err;
}

static struct sk_buff *inet_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct iphdr *iph;
	struct net_protocol *ops;
	int proto;
	int ihl;
	int id;

	if (unlikely(skb_shinfo(skb)->gso_type &
		     ~(SKB_GSO_TCPV4 |
		       SKB_GSO_UDP |
		       SKB_GSO_DODGY |
		       SKB_GSO_TCP_ECN |
		       0)))
		goto out;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	iph = skb->nh.iph;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	skb->h.raw = __skb_pull(skb, ihl);
	iph = skb->nh.iph;
	id = ntohs(iph->id);
	proto = iph->protocol & (MAX_INET_PROTOS - 1);
	segs = ERR_PTR(-EPROTONOSUPPORT);

	rcu_read_lock();
	ops = rcu_dereference(inet_protos[proto]);
	if (likely(ops && ops->gso_segment))
		segs = ops->gso_segment(skb, features);
	rcu_read_unlock();

	if (!segs || unlikely(IS_ERR(segs)))
		goto out;

	skb = segs;
	do {
		iph = skb->nh.iph;
		iph->id = htons(id++);
		iph->tot_len = htons(skb->len - skb->mac_len);
		iph->check = 0;
		iph->check = ip_fast_csum(skb->nh.raw, iph->ihl);
	} while ((skb = skb->next));

out:
	return segs;
}

#ifdef CONFIG_IP_MULTICAST
static struct net_protocol igmp_protocol = {
	.handler =	igmp_rcv,
};
#endif

// 由于tcp支持差错处理以及TSO，因此不仅定义了tcp接收函数，而且还定义了差错处理以及TSO分段处理函数
static struct net_protocol tcp_protocol = {
	.handler =	tcp_v4_rcv,
	// 在icmp模块接收到差错报文后，如果传输层协议是tcp，则该函数会被调用
	.err_handler =	tcp_v4_err,
	.gso_send_check = tcp_v4_gso_send_check,
	.gso_segment =	tcp_tso_segment,
	.no_policy =	1,
};

// ip层与udp协议之间接收数据包的接口由udp_protocol来描述
// udp协议与ip层之间没有定义发送接口，为了通过ip层发送数据
// udp协议实例在udp_sendmsg函数中调用ip层发送数据包的回调函数ip_append_data
// 或在udp_sendpage函数中调用IP层的回调函数ip_append_page
// 将udp数据报放入ip层
static struct net_protocol udp_protocol = {
	.handler =	udp_rcv,
	// udp_err()函数处理icmp错误消息
	.err_handler =	udp_err,
	.no_policy =	1,
};

// ICMP的net_protocol结构为icmp_protocol，定义了接收ICMP报文例程为icmp_rcv()
static struct net_protocol icmp_protocol = {
	.handler =	icmp_rcv,
};

static int __init init_ipv4_mibs(void)
{
	net_statistics[0] = alloc_percpu(struct linux_mib);
	net_statistics[1] = alloc_percpu(struct linux_mib);
	ip_statistics[0] = alloc_percpu(struct ipstats_mib);
	ip_statistics[1] = alloc_percpu(struct ipstats_mib);
	icmp_statistics[0] = alloc_percpu(struct icmp_mib);
	icmp_statistics[1] = alloc_percpu(struct icmp_mib);
	tcp_statistics[0] = alloc_percpu(struct tcp_mib);
	tcp_statistics[1] = alloc_percpu(struct tcp_mib);
	udp_statistics[0] = alloc_percpu(struct udp_mib);
	udp_statistics[1] = alloc_percpu(struct udp_mib);
	udplite_statistics[0] = alloc_percpu(struct udp_mib);
	udplite_statistics[1] = alloc_percpu(struct udp_mib);
	if (!
	    (net_statistics[0] && net_statistics[1] && ip_statistics[0]
	     && ip_statistics[1] && tcp_statistics[0] && tcp_statistics[1]
	     && udp_statistics[0] && udp_statistics[1]
	     && udplite_statistics[0] && udplite_statistics[1]             ) )
		return -ENOMEM;

	(void) tcp_mib_init();

	return 0;
}

static int ipv4_proc_init(void);

/*
 *	IP protocol layer initialiser
 */

static struct packet_type ip_packet_type = {
	.type = __constant_htons(ETH_P_IP),
	.func = ip_rcv,
	.gso_send_check = inet_gso_send_check,
	.gso_segment = inet_gso_segment,
};

// 在内核启动时，会按优先级顺序调用各组件注册在内核中的初始函数
// Internet协议族的初始化函数为inet_init()
// inet_init函数的功能之一就是完成传输层各协议实例的初始化
static int __init inet_init(void)
{
	struct sk_buff *dummy_skb;
	struct inet_protosw *q;
	struct list_head *r;
	int rc = -EINVAL;

	BUILD_BUG_ON(sizeof(struct inet_skb_parm) > sizeof(dummy_skb->cb));

	// 初始化tcp_prot,udp_prot和raw_prot的slab，并把它们加入到proto_list链表中
	// 以便支持/proc/net/文件系统
	rc = proto_register(&tcp_prot, 1);
	if (rc)
		goto out;

	// 注册udp与套接字的接口
	rc = proto_register(&udp_prot, 1);
	if (rc)
		goto out_unregister_tcp_proto;

	rc = proto_register(&raw_prot, 1);
	if (rc)
		goto out_unregister_udp_proto;

	/*
	 *	Tell SOCKET that we are alive... 
	 */
	// 让套接口层支持Internet协议族
	// 将AF_INET协议族套接字创建函数数据结构放入net_families中
  	(void)sock_register(&inet_family_ops);

	/*
	 *	Add all the base protocols.
	 */

	// 将系统中的常用传输层协议以及传输层的报文接收例程注册到inet_protos[]数组中
	if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add ICMP protocol\n");
	// 将udp协议的接口udp_protocol加入全局数组struct net_protocol *inet_protos[MAX_INET_PROTOS]中
	if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add UDP protocol\n");
	if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add TCP protocol\n");
#ifdef CONFIG_IP_MULTICAST
	if (inet_add_protocol(&igmp_protocol, IPPROTO_IGMP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add IGMP protocol\n");
#endif

	/* Register the socket-side information for inet_create. */
	// 初始化协议交换表的套接字层的存放各协议族API的链表
	for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
		// 将数组inetsw_array[]中Internet协议族所有的inet_protosw实例注册到inetsw散列表中
		inet_register_protosw(q);

	/*
	 *	Set the ARP module up
	 */
	// 注册传输层协议数据包处理数据结构实体，加入tcp/ip协议栈各基础协议
	// 建立协议栈运行环境，初始化各协议实例
	arp_init();		// 建立arp协议模块

  	/*
  	 *	Set the IP module up
  	 */

	ip_init();		// 建立ip协议模块

	// 创建一个内部的TCP套接口，主要用来发送RST段和ACK段
	tcp_v4_init(&inet_family_ops);

	// 建立tcp/ip内存槽等
	/* Setup TCP slab cache for open requests. */
	tcp_init();

	/* Add UDP-Lite (RFC 3828) */
	udplite4_register();

	/*
	 *	Set the ICMP layer up
	 */

	icmp_init(&inet_family_ops);

	/*
	 *	Initialise the multicast router
	 */
#if defined(CONFIG_IP_MROUTE)
	ip_mr_init();
#endif
	/*
	 *	Initialise per-cpu ipv4 mibs
	 */ 

	if(init_ipv4_mibs())
		printk(KERN_CRIT "inet_init: Cannot init ipv4 mibs\n"); ;
	
	// 初始化/proc/net文件系统
	ipv4_proc_init();

	ipfrag_init();

	// 注册Internet协议族报文类型及报文接收处理函数
	dev_add_pack(&ip_packet_type);

	rc = 0;
out:
	return rc;
out_unregister_udp_proto:
	proto_unregister(&udp_prot);
out_unregister_tcp_proto:
	proto_unregister(&tcp_prot);
	goto out;
}

fs_initcall(inet_init);

/* ------------------------------------------------------------------------ */

#ifdef CONFIG_PROC_FS
static int __init ipv4_proc_init(void)
{
	int rc = 0;

	if (raw_proc_init())
		goto out_raw;
	if (tcp4_proc_init())
		goto out_tcp;
	if (udp4_proc_init())
		goto out_udp;
	if (fib_proc_init())
		goto out_fib;
	if (ip_misc_proc_init())
		goto out_misc;
out:
	return rc;
out_misc:
	fib_proc_exit();
out_fib:
	udp4_proc_exit();
out_udp:
	tcp4_proc_exit();
out_tcp:
	raw_proc_exit();
out_raw:
	rc = -ENOMEM;
	goto out;
}

#else /* CONFIG_PROC_FS */
static int __init ipv4_proc_init(void)
{
	return 0;
}
#endif /* CONFIG_PROC_FS */

MODULE_ALIAS_NETPROTO(PF_INET);

EXPORT_SYMBOL(inet_accept);
EXPORT_SYMBOL(inet_bind);
EXPORT_SYMBOL(inet_dgram_connect);
EXPORT_SYMBOL(inet_dgram_ops);
EXPORT_SYMBOL(inet_getname);
EXPORT_SYMBOL(inet_ioctl);
EXPORT_SYMBOL(inet_listen);
EXPORT_SYMBOL(inet_register_protosw);
EXPORT_SYMBOL(inet_release);
EXPORT_SYMBOL(inet_sendmsg);
EXPORT_SYMBOL(inet_shutdown);
EXPORT_SYMBOL(inet_sock_destruct);
EXPORT_SYMBOL(inet_stream_connect);
EXPORT_SYMBOL(inet_stream_ops);
EXPORT_SYMBOL(inet_unregister_protosw);
EXPORT_SYMBOL(net_statistics);
EXPORT_SYMBOL(sysctl_ip_nonlocal_bind);
