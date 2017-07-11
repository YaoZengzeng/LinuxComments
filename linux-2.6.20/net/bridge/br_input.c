/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

/* Bridge group multicast address 802.1d (pg 51). */
const u8 br_group_address[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	br->statistics.rx_packets++;
	br->statistics.rx_bytes += skb->len;

	indev = skb->dev;
	skb->dev = br->dev;

	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
		netif_receive_skb);
}

/* note: already called with rcu_read_lock (preempt_disabled) */
// 入口数据帧是由br_handle_frame_finish函数处理的
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	int passedup = 0;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;
	// 帧的源MAC地址会由br_fdb_update加入到转发数据库
	br_fdb_update(br, p, eth_hdr(skb)->h_source);

	if (p->state == BR_STATE_LEARNING)
		goto drop;

	// 网桥接口处于混杂模式
	// 所有网桥端口绑定的设备都会处于混杂模式，因为网桥运行需要此模式，但除非明确地对其
	// 进行配置，否则网桥自己是不会处在混杂模式的
	if (br->dev->flags & IFF_PROMISC) {
		struct sk_buff *skb2;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 != NULL) {
			passedup = 1;
			// 帧的一个副本由br_pass_frame_up(即传送帧到上层协议的函数)提交至本地
			br_pass_frame_up(br, skb2);
		}
	}

	// 扩散帧
	if (is_multicast_ether_addr(dest)) {
		br->statistics.multicast++;
		br_flood_forward(br, skb, !passedup);
		if (!passedup)
			br_pass_frame_up(br, skb);
		goto out;
	}

	// 在转发数据库中搜索目的MAC地址
	dst = __br_fdb_get(br, dest);
	// 转发数据库显示，目的MAC地址属于本地接口
	if (dst != NULL && dst->is_local) {
		if (!passedup)
			// 帧的一个副本由br_pass_frame_up(即传送帧到上层协议的函数)提交至本地
			br_pass_frame_up(br, skb);
		else
			kfree_skb(skb);
		goto out;
	}

	// 如果找到该地址，帧就会由br_forward转发到正确网桥端口
	if (dst != NULL) {
		br_forward(dst->dst, skb);
		goto out;
	}

	// 否则就通过br_flood_forward将帧扩散到网桥的所有转发端口
	// 目的地是广播或多播链路层地址的帧总是会被扩散
	br_flood_forward(br, skb, 0);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}

/* note: already called with rcu_read_lock (preempt_disabled) */
static int br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);

	if (p && p->state != BR_STATE_DISABLED)
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source);

	return 0;	 /* process further */
}

/* Does address match the link local multicast address.
 * 01:80:c2:00:00:0X
 */
static inline int is_link_local(const unsigned char *dest)
{
	return memcmp(dest, br_group_address, 5) == 0 && (dest[5] & 0xf0) == 0;
}

/*
 * Called via br_handle_frame_hook.
 * Return 0 if *pskb should be processed furthur
 *	  1 if *pskb is handled
 * note: already called with rcu_read_lock (preempt_disabled) 
 */
int br_handle_frame(struct net_bridge_port *p, struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto err;

	if (unlikely(is_link_local(dest))) {
		skb->pkt_type = PACKET_HOST;
		return NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,
			       NULL, br_handle_local_finish) != 0;
	}

	if (p->state == BR_STATE_FORWARDING || p->state == BR_STATE_LEARNING) {
		if (br_should_route_hook) {
			if (br_should_route_hook(pskb)) 
				return 0;
			skb = *pskb;
			dest = eth_hdr(skb)->h_dest;
		}

		if (!compare_ether_addr(p->br->dev->dev_addr, dest))
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);
		return 1;
	}

err:
	kfree_skb(skb);
	return 1;
}
