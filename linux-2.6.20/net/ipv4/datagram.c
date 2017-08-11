/*
 *	common UDP/RAW code
 *	Linux INET implementation
 *
 * Authors:
 * 	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either version
 * 	2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/tcp_states.h>

int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
	// rt将初始化为指向路由高速缓冲区的入口地址
	struct rtable *rt;
	__be32 saddr;
	int oif;
	int err;

	// 对建立连接的信息做正确性检查：地址长度、协议类型
	if (addr_len < sizeof(*usin)) 
	  	return -EINVAL;

	if (usin->sin_family != AF_INET) 
	  	return -EAFNOSUPPORT;

	// 复位套接字中原目标地址在路由缓存中的记录
	sk_dst_reset(sk);

	// 套接字为与网络接口绑定的套接字，将绑定的网络接口信息保存在oif局部变量中
	// 如果套接口没有与网络接口绑定，则oif的值为0
	oif = sk->sk_bound_dev_if;
	saddr = inet->saddr;
	// 如果建立连接的地址是组传送地址，则重新初始化oif和源地址saddr
	if (MULTICAST(usin->sin_addr.s_addr)) {
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}
	// 为连接寻址一个新路由，如果寻址新路由成功，则将新路由放入缓存中
	err = ip_route_connect(&rt, usin->sin_addr.s_addr, saddr,
			       RT_CONN_FLAGS(sk), oif,
			       sk->sk_protocol,
			       inet->sport, usin->sin_port, sk);
	if (err)
		return err;
	// 如果寻址的新路由为广播地址路由，则释放该路由在路由缓存中的入口，返回错误代码
	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		return -EACCES;
	}
	// 用从路由表中获取的信息更新udp连接的源地址和目标地址
  	if (!inet->saddr)
	  	inet->saddr = rt->rt_src;	/* Update source address */
	if (!inet->rcv_saddr)
		inet->rcv_saddr = rt->rt_src;
	inet->daddr = rt->rt_dst;
	// udp连接的目标端口号来自用户程序，设置套接字状态为TCP_ESTABLISHED
	inet->dport = usin->sin_port;
	// 新路由在路由高速缓存中的入口保存于套接字sk->sk_dst_cache数据域
	sk->sk_state = TCP_ESTABLISHED;
	inet->id = jiffies;

	sk_dst_set(sk, &rt->u.dst);
	return(0);
}

EXPORT_SYMBOL(ip4_datagram_connect);

