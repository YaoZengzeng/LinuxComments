#ifndef __LINUX_NEIGHBOUR_H
#define __LINUX_NEIGHBOUR_H

#include <linux/netlink.h>

struct ndmsg
{
	__u8		ndm_family;
	__u8		ndm_pad1;
	__u16		ndm_pad2;
	__s32		ndm_ifindex;
	__u16		ndm_state;
	__u8		ndm_flags;
	__u8		ndm_type;
};

enum
{
	NDA_UNSPEC,
	NDA_DST,
	NDA_LLADDR,
	NDA_CACHEINFO,
	NDA_PROBES,
	__NDA_MAX
};

#define NDA_MAX (__NDA_MAX - 1)

/*
 *	Neighbor Cache Entry Flags
 */

#define NTF_PROXY	0x08	/* == ATF_PUBL */
#define NTF_ROUTER	0x80

/*
 *	Neighbor Cache Entry States.
 */
// 请求报文已发送，但尚未收到应答的状态，在此状态下，还没有解析到硬件地址，因此尚无
// 可使用的硬件地址，如果有报文要输出到此邻居，会先将其缓存起来，当进入此状态时，会
// 启动一个定时器，如果在定时器到期时还未接收到邻居的回应，则会重复发送请求报文，直到
// 解析成功或者尝试发送请求报文的次数达到上限，解析成功进入NUD_REACHABLE状态，否则
// 如果尝试发送请求报文的次数达到上限，便进入NUD_FAILED状态 
#define NUD_INCOMPLETE	0x01
// 可达状态，已经得到并缓存了邻居的硬件地址，进入该状态时，首先设置邻居项相关的output
// 函数指针(该状态下使用neigh_ops结构的connected_output),然后查看是否存在要发送到
// 该邻居的报文，如果有，则将其发送出去，如果在该状态下闲置时间达到指定上限时，便会进入
// NUD_STALE状态
#define NUD_REACHABLE	0x02
// 过期状态，在该状态一旦有报文输出到该邻居，则会进入NUD_DELAY状态并将该报文输出：如果
// 在该状态闲置时间达到指定上限，且此时的引用计数为1，则通过垃圾回收机制将其删除 
#define NUD_STALE	0x04
// 报文已发出，需得到邻居的可达性确认的状态
// 在该状态在延迟的指定时间内未收到确认，便会进入NUD_PROBE状态，否则进入NUD_REACHABLE
// 状态，在该状态下，报文的输出不受限制，使用慢速发送过程 
#define NUD_DELAY	0x08
// 过度状态，类似NUD_INCOMPLETE状态
// 在未接收到邻居的应答或确认时也会定时地重发请求，直到收到邻居的应答，确认或尝试发送请求报文
// 的次数达到上限，如果收到邻居的应答或确认，则进入NUD_REACHABLE状态；如果尝试发送请求报文的
// 次数达到上限，则进入NUD_FAILED状态，在该状态下，报文的输出也不受限制，使用慢速发送过程 
#define NUD_PROBE	0x10
// 由于没有接收到应答而无法访问状态
// 在两种情况下邻居项会进入NUD_FAILED状态，一是在刚创建时有报文要发送，但解析地址不成功
// 二是邻居项处于NUD_PROBE状态是有报文要发送，却没有收到应答或确认 
#define NUD_FAILED	0x20

/* Dummy states */
// 标识邻居无需从三层协议地址映射到二层地址协议的支持 
#define NUD_NOARP	0x40
// 该状态一般通过应用层命令设置，邻居项的硬件地址已静态设置，也无需将三层协议地址映射到二层地址协议的支持
// 也不会被垃圾回收 
#define NUD_PERMANENT	0x80
// 在此状态下，还没有硬件地址可用，因此还不能发送请求报文，此时，一旦有报文要输出到该邻居
// 便会触发对该邻居硬件地址的请求，进入NUD_INCOMPLETE状态，并缓存发送的报文 
#define NUD_NONE	0x00

/* NUD_NOARP & NUD_PERMANENT are pseudostates, they never change
   and make no address resolution or NUD.
   NUD_PERMANENT is also cannot be deleted by garbage collectors.
 */

struct nda_cacheinfo
{
	__u32		ndm_confirmed;
	__u32		ndm_used;
	__u32		ndm_updated;
	__u32		ndm_refcnt;
};

/*****************************************************************
 *		Neighbour tables specific messages.
 *
 * To retrieve the neighbour tables send RTM_GETNEIGHTBL with the
 * NLM_F_DUMP flag set. Every neighbour table configuration is
 * spread over multiple messages to avoid running into message
 * size limits on systems with many interfaces. The first message
 * in the sequence transports all not device specific data such as
 * statistics, configuration, and the default parameter set.
 * This message is followed by 0..n messages carrying device
 * specific parameter sets.
 * Although the ordering should be sufficient, NDTA_NAME can be
 * used to identify sequences. The initial message can be identified
 * by checking for NDTA_CONFIG. The device specific messages do
 * not contain this TLV but have NDTPA_IFINDEX set to the
 * corresponding interface index.
 *
 * To change neighbour table attributes, send RTM_SETNEIGHTBL
 * with NDTA_NAME set. Changeable attribute include NDTA_THRESH[1-3],
 * NDTA_GC_INTERVAL, and all TLVs in NDTA_PARMS unless marked
 * otherwise. Device specific parameter sets can be changed by
 * setting NDTPA_IFINDEX to the interface index of the corresponding
 * device.
 ****/

struct ndt_stats
{
	__u64		ndts_allocs;
	__u64		ndts_destroys;
	__u64		ndts_hash_grows;
	__u64		ndts_res_failed;
	__u64		ndts_lookups;
	__u64		ndts_hits;
	__u64		ndts_rcv_probes_mcast;
	__u64		ndts_rcv_probes_ucast;
	__u64		ndts_periodic_gc_runs;
	__u64		ndts_forced_gc_runs;
};

enum {
	NDTPA_UNSPEC,
	NDTPA_IFINDEX,			/* u32, unchangeable */
	NDTPA_REFCNT,			/* u32, read-only */
	NDTPA_REACHABLE_TIME,		/* u64, read-only, msecs */
	NDTPA_BASE_REACHABLE_TIME,	/* u64, msecs */
	NDTPA_RETRANS_TIME,		/* u64, msecs */
	NDTPA_GC_STALETIME,		/* u64, msecs */
	NDTPA_DELAY_PROBE_TIME,		/* u64, msecs */
	NDTPA_QUEUE_LEN,		/* u32 */
	NDTPA_APP_PROBES,		/* u32 */
	NDTPA_UCAST_PROBES,		/* u32 */
	NDTPA_MCAST_PROBES,		/* u32 */
	NDTPA_ANYCAST_DELAY,		/* u64, msecs */
	NDTPA_PROXY_DELAY,		/* u64, msecs */
	NDTPA_PROXY_QLEN,		/* u32 */
	NDTPA_LOCKTIME,			/* u64, msecs */
	__NDTPA_MAX
};
#define NDTPA_MAX (__NDTPA_MAX - 1)

struct ndtmsg
{
	__u8		ndtm_family;
	__u8		ndtm_pad1;
	__u16		ndtm_pad2;
};

struct ndt_config
{
	__u16		ndtc_key_len;
	__u16		ndtc_entry_size;
	__u32		ndtc_entries;
	__u32		ndtc_last_flush;	/* delta to now in msecs */
	__u32		ndtc_last_rand;		/* delta to now in msecs */
	__u32		ndtc_hash_rnd;
	__u32		ndtc_hash_mask;
	__u32		ndtc_hash_chain_gc;
	__u32		ndtc_proxy_qlen;
};

enum {
	NDTA_UNSPEC,
	NDTA_NAME,			/* char *, unchangeable */
	NDTA_THRESH1,			/* u32 */
	NDTA_THRESH2,			/* u32 */
	NDTA_THRESH3,			/* u32 */
	NDTA_CONFIG,			/* struct ndt_config, read-only */
	NDTA_PARMS,			/* nested TLV NDTPA_* */
	NDTA_STATS,			/* struct ndt_stats, read-only */
	NDTA_GC_INTERVAL,		/* u64, msecs */
	__NDTA_MAX
};
#define NDTA_MAX (__NDTA_MAX - 1)

#endif
