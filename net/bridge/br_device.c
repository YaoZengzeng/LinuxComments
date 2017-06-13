/*
 *	Device handling code
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_device.c,v 1.6 2001/12/24 00:59:55 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>

#include <asm/uaccess.h>
#include "br_private.h"

static struct net_device_stats *br_dev_get_stats(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	return &br->statistics;
}

/* net device transmit always called with no BH (preempt_disabled) */
// br_dev_xmit只是简单地实现了网桥传输所需的基本逻辑
int br_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	const unsigned char *dest = skb->data;
	struct net_bridge_fdb_entry *dst;

	br->statistics.tx_packets++;
	br->statistics.tx_bytes += skb->len;

	skb->mac.raw = skb->data;
	skb_pull(skb, ETH_HLEN);

	if (dest[0] & 1) 
		br_flood_deliver(br, skb, 0);
	else if ((dst = __br_fdb_get(br, dest)) != NULL)
		// 当网桥转发数据库查询成功时，br_dev_xmit就会从正确的网桥端口
		// 将该帧的拷贝转发出去
		br_deliver(dst->dst, skb);
	else
		// 如果查询失败，或者当目的MAC地址是L2多播或L2广播地址时，就会在
		// 所有符合条件的网桥端口上扩散该帧
		br_flood_deliver(br, skb, 0);

	return 0;
}

static int br_dev_open(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	// 将网桥设备的基本特征初始化为其绑定的设备锁支持的功能的最小常用子集
	br_features_recompute(br);
	// 启动设备进行数据传输
	netif_start_queue(dev);
	// 启动网桥设备，当启动网桥设备时，先前绑定到该设备上的端口也会跟着启动
	br_stp_enable_bridge(br);

	return 0;
}

static void br_dev_set_multicast_list(struct net_device *dev)
{
}

static int br_dev_stop(struct net_device *dev)
{
	br_stp_disable_bridge(netdev_priv(dev));

	netif_stop_queue(dev);

	return 0;
}

static int br_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > br_min_mtu(netdev_priv(dev)))
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

/* Allow setting mac address of pseudo-bridge to be same as
 * any of the bound interfaces
 */
static int br_set_mac_address(struct net_device *dev, void *p)
{
	struct net_bridge *br = netdev_priv(dev);
	struct sockaddr *addr = p;
	struct net_bridge_port *port;
	int err = -EADDRNOTAVAIL;

	spin_lock_bh(&br->lock);
	list_for_each_entry(port, &br->port_list, list) {
		if (!compare_ether_addr(port->dev->dev_addr, addr->sa_data)) {
			br_stp_change_bridge_id(br, addr->sa_data);
			err = 0;
			break;
		}
	}
	spin_unlock_bh(&br->lock);

	return err;
}

static void br_getinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "bridge");
	strcpy(info->version, BR_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, "N/A");
}

static int br_set_sg(struct net_device *dev, u32 data)
{
	struct net_bridge *br = netdev_priv(dev);

	if (data)
		br->feature_mask |= NETIF_F_SG;
	else
		br->feature_mask &= ~NETIF_F_SG;

	br_features_recompute(br);
	return 0;
}

static int br_set_tso(struct net_device *dev, u32 data)
{
	struct net_bridge *br = netdev_priv(dev);

	if (data)
		br->feature_mask |= NETIF_F_TSO;
	else
		br->feature_mask &= ~NETIF_F_TSO;

	br_features_recompute(br);
	return 0;
}

static int br_set_tx_csum(struct net_device *dev, u32 data)
{
	struct net_bridge *br = netdev_priv(dev);

	if (data)
		br->feature_mask |= NETIF_F_NO_CSUM;
	else
		br->feature_mask &= ~NETIF_F_ALL_CSUM;

	br_features_recompute(br);
	return 0;
}

static struct ethtool_ops br_ethtool_ops = {
	.get_drvinfo = br_getinfo,
	.get_link = ethtool_op_get_link,
	.get_sg = ethtool_op_get_sg,
	.set_sg = br_set_sg,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = br_set_tx_csum,
	.get_tso = ethtool_op_get_tso,
	.set_tso = br_set_tso,
};

void br_dev_setup(struct net_device *dev)
{
	// 网桥MAC地址dev_addr会被清除掉，因为这个地址将由br_stp_recalculate_bridge_id
	// 函数从其绑定的设备上设置的MAC地址获得
	// 基于同样的理由，驱动程序没有提供set_mac_addr函数
	memset(dev->dev_addr, 0, ETH_ALEN);

	ether_setup(dev);

	// 在网桥设备上发出的ioctl命令使用br_dev_ioctl函数处理
	dev->do_ioctl = br_dev_ioctl;
	dev->get_stats = br_dev_get_stats;
	// 驱动程序会把hard_start_xmit函数指针初始化为设备用于传输数据的函数，网桥驱动程序将该指针
	// 初始化为br_dev_xmit，该函数负责实现"网桥设备抽象"一节所讲的网络设备抽象层
	dev->hard_start_xmit = br_dev_xmit;
	// 当网桥设备因管理手段被启动时，内核会通过dev_open调用br_dev_open来启动网桥
	dev->open = br_dev_open;
	dev->set_multicast_list = br_dev_set_multicast_list;
	// 当网桥设备上的MTU改变时，内核必须确保新MTU值不会大于那些被绑定的设备中最小的
	// MTU值，这一点由br_change_mtu来确保
	dev->change_mtu = br_change_mtu;
	dev->destructor = free_netdev;
	SET_MODULE_OWNER(dev);
 	SET_ETHTOOL_OPS(dev, &br_ethtool_ops);
	dev->stop = br_dev_stop;
	// 网桥设备默认是没有实现队列机制，而是让被绑定的设备负责实现，因此tx_queue_len被初始化为0
	// 管理员可以通过ifconfig或ip link命令配置tx_queue_len
	dev->tx_queue_len = 0;
	dev->set_mac_address = br_set_mac_address;
	// 必要时，还会设定IFF_BRIDGE标记，使得内核可以区别网桥设备和其他类型的设备
	dev->priv_flags = IFF_EBRIDGE;

 	dev->features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
 			NETIF_F_TSO | NETIF_F_NO_CSUM | NETIF_F_GSO_ROBUST;
}
