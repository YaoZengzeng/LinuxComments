#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

// fib_alias实例代表一条路由表项，目的地址相同但其他参数配置不同的表项共享fib_node实例
struct fib_alias {
	// 将与共享同一个fib_node实例的所有fib_alias实例链接在一起
	struct list_head	fa_list;
	struct rcu_head rcu;
	//　指针指向一个fib_info实例，该实例存储着如何处理与该路由匹配数据报的信息
	struct fib_info		*fa_info;
	// 路由的服务类型比特位字段，当该值为零时表示还没有配置TOS，所以在路由查找时任何值都可以匹配
	// fa_tos用户对每一条路由表项配置的TOS，区别于fib_rule4结构中的tos
	u8			fa_tos;
	// 路由表项的类型，它间接定义了当路由查找匹配时应采取的动作，该字段可能的取值有：
	// RTN_UNSPEC:定义一个未初始化的值，例如当从路由表中删除一个表项时使用该值
	// RTN_LOCAL:目的地址被配置为一个本地接口的地址
	// RTN_UNICAST:该路由是一条到单播地址的直连或非直连路由。当通过ip route命令添加路由但没有指定其他
	// 路由类型时，路由类型默认被设置为RTN_UNICAST
	u8			fa_type;
	// 路由表项的作用范围
	u8			fa_scope;
	// 一些标志的位图，目前只有一个标志，即FA_S_ACCESSED，表示该表项已经被访问过
	u8			fa_state;
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, __be32 zone, __be32 mask,
				int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(struct fib_config *cfg);
extern int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u32 tb_id, u8 type, u8 scope, __be32 dst,
			 int dst_len, u8 tos, struct fib_info *fi,
			 unsigned int);
extern void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
		      int dst_len, u32 tb_id, struct nl_info *info);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int *dflt);

#endif /* _FIB_LOOKUP_H */
