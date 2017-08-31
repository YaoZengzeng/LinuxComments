/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		// 用于网络拥塞控制
		ece:1,
		// 用于窗口控制
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
// 当设置了该选项后，tcp会立即向外发送数据段，而不会等待数据段中填入更多数据
// 如果设置了TCP_CORK选项，这个选项就失效
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
// 在套接字建立连接之前，该选项指定最大数据段大小的值，送给tcp选项的mss值就是由此选项
// 决定的，但mss的值不能超过接口的mtu，tcp连接两端的站点可以协商数据段的大小
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
// 在tcp开始传送连接是否保持活动的探测数据段之前，连接处于空闲状态的时间值，以秒为单位
// 默认值为两个小时，该选项只有在套接字设置了SO_KEEPALIVE选项时才有效
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
// 设定在两次传送探测连接保持活动数据段之前需要等待多少秒，初始值为75秒
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
// 使用此选项，应用程序调用者可以设置在断开连接之前通过套接字发送多少个保持连接活动(keepalive)
// 的探测数据段，如果要使这个选项有效，则还必须设置套接字的SO_KEEPALIVE选项
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
// 这个选项用于在尝试建立tcp连接时，如果连接没能建立起来，在重发多少次syn后，才放弃建立连接请求
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
// 该选项指定处于FIN_WAIT2状态的孤立套接字还应保持存活多久，如果其值为0，则关闭选项，Linux使用
// 常规方式处理FIN_WAIT_2和TIME_WAIT状态，如果值小于0，则套接字立即从FIN_WAIT_2状态进入CLOSED状态
// 不经过TIME_WAIT，
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
// 应用程序调用者在数据还没到达套接字之前，可以处于休眠状态，但当数据到达套接字时则应用程序被唤醒、
// 如果等待超市应用程序也会被唤醒，调用者可以设置一个时间值来描述应用程序等待数据达到超时时间
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
// 指定套接字窗口大小，窗口的最小值是SOCK_MIN_RCVBUF除以2，等于128个字节
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
// 调用程序使用此选项可以提取大部分套接字的配置信息，在提取配置信息后，返回到struct tcp_info中
#define TCP_INFO		11	/* Information about this connection. */
// 当这个选项的值设置为1时，会关闭延迟回答，或为0时允许延迟回答，延迟回答是Linux tcp操作的一个常规
// 模式，在延迟回答时，ack数据的发送会延迟到可以与一个等待发送到另一端的数据段合并时，才发送出去。如果
// 这个选项的值为1，则将struct tcp_sock结构中的ack部分的pingpong数据域设为0，就可以禁止延迟发送
// TCP_QUICKACK选项只会暂时影响tcp协议的操作行为
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
// 选择并启用指定的拥塞控制算法，设置过程是，首先从用户空间取得拥塞控制算法名，然后调用tcp_set_congestion_control()
// 修改传输控制块当前拥塞控制算法
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	// 第一个数据域tcpi_state中包含的是当前tcp的连接状态，其后的数据直到tcpi_fackets
	// 包含的是连接统计信息
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	// 以下四个数据域是事件的时间戳信息
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	// 最后一部分是tcp协议的度量值，如mtu, 发送门限值，环形传送时间和阻塞窗口
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	u32			 	rcv_isn;
	u32			 	snt_isn;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

// tcp_sock结构是tcp协议的控制块，它在inet_connection_sock结构的基础上扩展了滑动窗口协议，拥塞控制算法
// 等一些tcp专有属性
struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	// struct inet_connection_sock中包含struct inet_connection_sock_af_ops *icsk_af_ops
	// 数据结构，是套接字操作函数指针数据块，各协议实例在初始化时将函数指针初始化为自己的函数实例
	// struct inet_connection_sock inet_conn数据结构必须为tcp_sock的第一个成员
	struct inet_connection_sock	inet_conn;
	// 传送数据段tcp协议头的长度
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	// 记录该套接口发送到网络设备段的长度，在不支持TSO的情况下，其值就等于MSS，而如果网卡支持TSO
	// 且采用TSO进行发送，则需要重新计算，参见tcp_current_mss()
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
 	// tcp协议头预定向完成标志，用该标志确定数据包是否通过"Fast Path"接收
 	// 该标志和时间戳以及序列号等因素一样是判断执行快速路径还是慢速路径的条件之一
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	// 下一个输入数据段的序列号
 	u32	rcv_nxt;	/* What we want to receive next 	*/
 	// 下一个发送数据段的序列号
 	u32	snd_nxt;	/* Next sequence we send		*/

 	// 在输出的段中，最早一个未确认段的序号
 	u32	snd_una;	/* First byte we want an ack for	*/
 	// 最近发送的小包（小于mss的段）的最后一个字节序号，在成功发送段后，如果报文小于mss
 	// 即更新该字段，主要用来判断是否启用Nagle算法
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
 	// 最近依次收到ack段的时间，用于tcp保活
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
 	// 最近一次发送数据包的时间，主要用于拥塞窗口的设置
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user */
 	// struct ucopy数据结构是实现数据段"Fast Path"接收的关键
 	// 用来控制复制数据到用户进程的控制块，包括描述用户空间缓存及其长度
 	// prequeue队列及其占用的内存等
	struct {
		// 输入队列，其中包含等待由"Fast Path"处理的skb链表
		// 如果未启用tcp_low_latency，tcp段将首先缓存到此队列，直到进程主动读取时才真正地接收到
		// 接收队列中并处理
		struct sk_buff_head	prequeue;
		// 用户进程，指向prequeue队列中数据段的用户进程
		struct task_struct	*task;
		// 指向用户地址空间中存放接收数据的数组
		struct iovec		*iov;
		// 在prequeue队列中所有skb中数据长度的总和
		int			memory;
		// prequeue队列中skb缓冲区的个数
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		// 用于数据异步复制，当网络设备支持Scatter/Gather IO功能时，可以利用dma直接内存访问
		// 将数据异步从网络设备硬件缓冲区中复制到应用程序地址空间的缓冲区
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	// 记录更新发送窗口的那个ack段的序号，用来判断是否需要更新窗口，如果后续收到的ack段的序号大于snd_wl1
	// 则说明需更新窗口，否则无需更新
	u32	snd_wl1;	/* Sequence for window update		*/
	// 接收方提供的接收窗口大小，即发送方发送窗口大小
	u32	snd_wnd;	/* The window we expect to receive	*/
	// 接收方通告过的最大接收窗口值
	u32	max_window;	/* Maximal window ever seen from peer	*/
	// 发送方当前有效mss
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

	// 滑动窗口最大值，滑动窗口大小在变化过程中始终不能超出该值，在tcp建立连接时，该字段被初始化
	// 置为最大的16位整数左移窗口的扩大因子的位数，因为滑动窗口在tcp首部中以16位表示，window_clamp
	// 太大会导致滑动窗口不能在tcp首部中表示
	u32	window_clamp;	/* Maximal window to advertise		*/
	// 当前接收窗口大小的阈值，该字段与rcv_wnd两者配合，达到滑动窗口大小缓慢增长的效果，其初始值为rcv_wnd
	// 当本地套接口收到段，并满足一定条件时，会递增该字段；到下一次发送数据组建tcp首部时，需通告对端当前接收窗口大小
	// 此时更新rcv_wnd，而rcv_wnd的取值不能超过rcv_ssthresh的值
	u32	rcv_ssthresh;	/* Current window clamp			*/

	// 当重传超时发生时，在启用F-RTO的情况下，用来保存待发送的下一个tcp段的序号（SND.NXT）
	// 在tcp_process_frto()中处理F-RTO时使用
	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	// 在不支持SACK时，为由于连接收到重复确认而进入快速恢复阶段的重复确认数阈值
	// 在支持SACK时，在没有确认丢失包的情况下，是tcp流中可以重排序的数据段数
	// 由相关路由缓存项中的reordering度量值或系统参数tcp_reordering进行初始化，更新时会同时
	// 更新到目的路由缓存项的reordering度量值
	u8	reordering;	/* Packet reordering metric.		*/
	u8	frto_counter;	/* Number of new acks after RTO */
	// TCP_CORK选项：tcp不立即发送数据段，直到数据段中的数据达到tcp协议数据段的最大长度
	// 标识是否允许Nagle算法，Nagle算法把较小的段组装成更大的段，主要用于解决由于大量的小包导致
	// 网络发生拥塞的问题，参见TCP_NODELAY和TCP_CORK选项
	u8	nonagle;	/* Disable Nagle algorithm?             */
	// 保活探测次数，最大值为127，参见TCP_KEEPCNT选项
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
	// 平滑的RTT，为避免浮点运算，是将其放大8倍后进行存储
	u32	srtt;		/* smoothed round trip time << 3	*/
	// RTT平均偏差，由RTT与RTT均值偏差绝对值加权平均而得到，其值越大说明RTT抖动得越厉害
	u32	mdev;		/* medium deviation			*/
	// 跟踪每次发送窗口内的段被全部确认过程中，RTT平均偏差的最大值，描述RTT抖动的最大范围
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	// 平滑的RTT平均偏差，由mdev计算得到，用来计算RTO
	u32	rttvar;		/* smoothed mdev_max			*/
	// 记录SND.UNA，用来计算RTO时比较SND.UNA是否已经被更新了，如果SND.UNA更新，则需要同时更新rttvar
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	// 从发送队列发出而未得到确认tcp段的数目（即SND.NXT - SND.UNA），该值是同态的，当有新的段发出或有新的
	// 确认收到都会增加或减小该值
	u32	packets_out;	/* Packets which are "in flight"	*/
	// 已离开主机在网络中且未确认的tcp段数，包含两种情况：一是通过sack确认的段，二是已丢失的段
	// 即left_out = sacked_out + lost_out
	// left_out需要与packets_out进行区分，packets_out只是离开发送队列（不一定离开主机），而left_out则必定离开了主机
	u32	left_out;	/* Packets which leaved network	*/
	// 重传还未得到确认的tcp段数目
	u32	retrans_out;	/* Retransmitted packets out		*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
 	// 存储接收到的tcp选项
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	// 拥塞控制时慢启动的阈值
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
 	// 当前拥塞窗口的大小
 	u32	snd_cwnd;	/* Sending congestion window		*/
 	// 自从上次调整拥塞控制窗口到目前为止接收到的总ack段数，如果该字段值为0，则说明已经调整了拥塞控制窗口
 	// 且到目前为止还没有接收到ack段，调整拥塞控制窗口之后，每接收到一个ack段就会使snd_cwnd_cnt增1
 	u16	snd_cwnd_cnt;	/* Linear increase counter		*/
 	// 允许的最大拥塞窗口值，初始值为65535，之后在接收到SYN和ACK段时，会根据条件确定是否从路由配置项读取信息
 	// 更新该字段，最后在tcp链接复位前，将更新后的值根据某种算法计算后再更新回对应的路由配置项，便于连接使用
	u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
 	// 当应用程序限制时，记录当前从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时调解拥塞窗口，避免拥塞窗口失效
	u32	snd_cwnd_used;
	// 记录最近一次检验拥塞窗口的时间，在拥塞期间，接收到ack后会进行拥塞窗口的检验，而在非拥塞期间，为了防止由于应用程序
	// 限制而造成拥塞窗口失效，因此在成功发送段后，如果有必要也会检验拥塞窗口
	u32	snd_cwnd_stamp;

	// 乱序缓存队列，用来暂存接收到的乱序的tcp段
	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	// 当前接收窗口的大小
 	u32	rcv_wnd;	/* Current receiver window		*/
 	// 标识最早接收但为确认的段的序号，即当前接收窗口的左端，在发送ack时，由rcv_nxt更新
 	// 因此rcv_wup的更新常比rcv_nxt之后一些
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	// 已加入到发送队列中的最后一个字节序列号
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	// 通常情况下表示已经真正发送出去的最后一个字节序号，但有时也可能表示期望发送出去的最后一个字节序号
	// 如启用Nagle算法之后，或在发送持续探测段之后
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	// 尚未从内核空间复制到用户空间的段最前面一个字节的序号
	u32	copied_seq;	/* Head of yet unread data		*/

/*	SACKs data	*/
	// 存储用于回复对端SACK的信息，duplicate_sack存储D-SACK信息，selective_acks存储SACK信息
	// 在回复SACK时会从中取出D-SACK和SACK信息，而在处理接收到乱序的段时，会向这两个字段填入相应的信息
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	// 存储收到的SACK选项信息
	struct tcp_sack_block recv_sack_cache[4];

	/* from STCP, retrans queue hinting */
	// 一般在拥塞状态没有撤销或进入Loss状态时，在重传队列中，缓存上一次标记记分牌未丢失的最后一个段
	// 主要是为了加速对重传队列的标记操作
	struct sk_buff* lost_skb_hint;

	// 一般在拥塞状态没有撤销或没有进入Loss状态时，在重传队列中，记录上一次更新记分牌的最后一个SKB，主要也是为了加速
	// 对重传队列的标记操作
	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	// 当支持SACK或FACK时，在重传处于SACK块中的空隙中的段时，用于记录由于满足其他条件而未能重传的位置
	// 下次可以从此位置继续处理，如果重传了，则下次从重传队列队首重新处理
	struct sk_buff *forward_skb_hint;
	struct sk_buff *fastpath_skb_hint;

	// fastpath_skb_hint记录上一次处理SACK选项的最高序号段的SKB，而fastpath_cnt_hint记录上一次计算得到的
	// fackets_out，目的是为了在拥塞状态没有发生变化或接收到的sack没有发生变化等情况下，加速对fackets_out
	// sacked_out等的计算
	int     fastpath_cnt_hint;
	int     lost_cnt_hint;
	// 用于记录当前重传的位置，retransmit_skb_hint位置之前的段经过了重传，当认为重传的段也已经丢失，则将其设置为NULL
	// 这样重传又从sk_write_queue开始，即使该段并未真正丢失，重新排序也正是这个意识，这与系统参数tcp_reordering也有着
	// 密切关系
	int     retransmit_cnt_hint;
	int     forward_cnt_hint;

	// 本端能接受的MSS上限，在建立连接时用来通告对端，此值由路由缓存项中MSS度量值（RTAX_ADVMSS）进行初始化
	// 而路由缓存项中MSS度量值则直接取自网络设备接口的MTU减去IP首部及tcp首部的长度，参见rt_set_nexthop()
	u16	advmss;		/* Advertised MSS			*/
	// 发送后丢失在传输过程中段的数量，目前tcp协议还没有类似“段丢失通知”机制，因此丢失的段数只能通过某种算法进行推测
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	lost_out;	/* Lost packets			*/
	// 启用sack时，通过sack的tcp选项标识已接收到的段的数量，不启用sack时，标识接收到重复确认的次数
	// 此值在接收到确认新数据的段时被清楚
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	// 发送拥塞时的SND.NXT，标识重传队列的尾部
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	// 在主动连接时，记录第一个syn段的发送时间，用来检测ack序号是否回绕
	// 在数据传输阶段，当发送超时重传时，记录上次重传阶段第一个重传段的发送时间，用来判断是否可以进行拥塞撤销
	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	urg_seq;	/* Seq of received urgent pointer */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	urg_mode;	/* In urgent mode		*/
	u8	ecn_flags;	/* ECN status bits.			*/
	u32	snd_up;		/* Urgent pointer		*/

	// 在整个连接中总重传次数
	u32	total_retrans;	/* Total retransmits for entire connection */
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	// tcp发送保活探测前，tcp连接的空闲时间，即保活定时器启动的时间阈值，在启动SO_KEEPALIVE选项的情况下
	// 一个连接空闲了一段时间之后，tcp会发送保活探测到对端系统，如果对端系统没有对保活探测进行回应，tcp会
	// 重复发送保活探测，直到连续发送而没有得到回应的保活探测达到一定数量，才会认为这个连接已经无效了
	// 参见TCP_KEEPIDLE选项
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	// 发送保活探测的时间间隔，参见TCP_KEEPINTVL选项
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	// 标识tcp迁移到关闭CLOSED状态之前保持在FIN_WAIT_2状态的时间，参见TCP_LINGER2选项
	int			linger2;

	// 在启用tcp_syncookie的情况下，建立连接时记录接收SYN段的时间，用来检测建立连接是否超时
	unsigned long last_synq_overflow; 

	u32	tso_deferred;

/* Receiver side RTT estimation */
	// 存储接收方的rtt估算值，用于实现通过调解接收窗口来进行流量控制的功能，接收方rtt估算值用来限制
	// 调整tcp接收缓冲区空间的频率，每次调整tcp接收缓冲区空间的时间间隔不能小于rtt
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	// 用来调整tcp接收缓存空间和接收窗口大小，也用于实现通过调解接收窗口来进行流量控制的功能，每次将数据复制到
	// 用户空间，都会调用tcp_rcv_space_adjust()来计算新的tcp接收缓冲空间的大小
	struct {
		// 用于调整接收缓存的大小
		int	space;
		// 已复制到用户空间的tcp段序号
		u32	seq;
		// 记录最近一次进行调整的时间
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	// 存储已发送mtu发现段的起始序号和结束序号，与发送mtu发现段的skb中tcp_skb_cb结构的seq和end_seq字段
	// 相对应，用来判断路径mtu发现是否成功
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
