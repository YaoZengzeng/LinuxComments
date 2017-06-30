/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the UDP protocol.
 *
 * Version:	@(#)udp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_UDP_H
#define _LINUX_UDP_H

#include <linux/types.h>

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

/* UDP socket options */
#define UDP_CORK	1	/* Never send partially complete segments */
#define UDP_ENCAP	100	/* Set the socket to accept encapsulated packets */

/* UDP encapsulation types */
#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define UDP_ENCAP_ESPINUDP	2 /* draft-ietf-ipsec-udp-encaps-06 */

#ifdef __KERNEL__
#include <linux/types.h>

#include <net/inet_sock.h>
#define UDP_HTABLE_SIZE		128

// udp_sock结构为UDP协议的传输控制块，是对inet_sock结构的扩展
struct udp_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
	// 发送状态，其值只能是0或AF_INET
	// 0表示数据已经从UDP套接口发送到IP层，可以继续调用sendmsg()发送数据
	// AF_INET表示UDP正在处理调用sendmsg的发送数据，不需要处理目的地址，路由等信息
	// 直接处理UDP数据
	int		 pending;	/* Any pending frames ? */
	// 标识发送的UDP数据是否组成一个单独的IP数据报发送出去，由UDP的UDP_CORK选项设置
	// 0表示有数据需要发送时，立即发送出去
	// 非0表示将UDP数据组成一个单一64KB的UDP数据报后才将其发送出去，因此会有延迟
	unsigned int	 corkflag;	/* Cork is required */
	// 标识本套接口是否通过IPSEC封装，由UDP的UDP_ENCPA套接口选项设置，一般在IKE程序
	// 打开UDP4500端口时设置
  	__u16		 encap_type;	/* Is this an Encapsulation socket? */
	/*
	 * Following member retains the information to create a UDP header
	 * when the socket is uncorked.
	 */
	// 从UDP套接口发送数据到IP层时，标识待发送数据的长度
	__u16		 len;		/* total length of pending frames */
	/*
	 * Fields specific to UDP-Lite.
	 */
	// 轻量级UDP，通过UDPLITE_SEND_CSCOV和UDPLITE_RECV_CSCOV选项设置，用于实现控制
	// 发送和接收校验和的执行
	__u16		 pcslen;
	__u16		 pcrlen;
/* indicator bits used by pcflag: */
#define UDPLITE_BIT      0x1  		/* set by udplite proto init function */
#define UDPLITE_SEND_CC  0x2  		/* set via udplite setsockopt         */
#define UDPLITE_RECV_CC  0x4		/* set via udplite setsocktopt        */
	// 按位存储，标识是否设置了UDPLITE_SEND_CSCOV或UDPLITE_RECV_CSCOV
	__u8		 pcflag;        /* marks socket as UDP-Lite if > 0    */
};

static inline struct udp_sock *udp_sk(const struct sock *sk)
{
	return (struct udp_sock *)sk;
}
#define IS_UDPLITE(__sk) (udp_sk(__sk)->pcflag)

#endif

#endif	/* _LINUX_UDP_H */
