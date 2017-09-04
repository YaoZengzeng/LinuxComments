/*
 * NET		Generic infrastructure for Network protocols.
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <net/request_sock.h>

/*
 * Maximum number of SYN_RECV sockets in queue per LISTEN socket.
 * One SYN_RECV socket costs about 80bytes on a 32bit machine.
 * It would be better to replace it with a global counter for all sockets
 * but then some measure against one socket starving all other sockets
 * would be needed.
 *
 * It was 128 by default. Experiments with real servers show, that
 * it is absolutely not enough even at 100conn/sec. 256 cures most
 * of problems. This value is adjusted to 128 for very small machines
 * (<=32Mb of memory) and to 1024 on normal or better ones (>=256Mb).
 * Note : Dont forget somaxconn that may limit backlog too.
 */
int sysctl_max_syn_backlog = 256;

// reqsk_queue_alloc()函数用来分配连接请求块散列表，然后将其连接到所在传输控制块的请求块容器中
int reqsk_queue_alloc(struct request_sock_queue *queue,
		      unsigned int nr_table_entries)
{
	size_t lopt_size = sizeof(struct listen_sock);
	struct listen_sock *lopt;

	// 取用户设定的连接队列长度最大值参数nr_table_entries和系统最多可同时存在未完成三次握手syn请求数max_syn_backlog
	// 两者的最小值，他们都用来控制连接队列的长度，只是前者是针对某传输控制块，而后者控制的是全局的
	nr_table_entries = min_t(u32, nr_table_entries, sysctl_max_syn_backlog);
	nr_table_entries = max_t(u32, nr_table_entries, 8);
	// 调用round_pow_of_two()以确保nr_table_entries的值为2的n次方
	nr_table_entries = roundup_pow_of_two(nr_table_entries + 1);
	// 计算用来保存syn请求连接的listen_sock结构的大小
	lopt_size += nr_table_entries * sizeof(struct request_sock *);
	if (lopt_size > PAGE_SIZE)
		// 如果用于保存syn请求连接的listen_sock结构大于一个页面，则调用__vmalloc()
		// 从高位内存中分配虚拟内存，并且清零
		lopt = __vmalloc(lopt_size,
			GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
			PAGE_KERNEL);
	else
		// 如果小于一个页面，则在常规内存中分配内存并清零，kzalloc()封装了kmalloc()及memset()
		lopt = kzalloc(lopt_size, GFP_KERNEL);
	if (lopt == NULL)
		return -ENOMEM;

	// 之前已由roundup_pow_of_two()确保nr_table_entries的值为2的n次方，在此计算该n值为
	// max_qlen_log
	for (lopt->max_qlen_log = 3;
	     (1 << lopt->max_qlen_log) < nr_table_entries;
	     lopt->max_qlen_log++);

	// 初始化listen_sock结构中的一些成员
	get_random_bytes(&lopt->hash_rnd, sizeof(lopt->hash_rnd));
	rwlock_init(&queue->syn_wait_lock);
	queue->rskq_accept_head = NULL;
	lopt->nr_table_entries = nr_table_entries;

	// 最后将散列表连接到所在传输控制块的请求块容器中
	write_lock_bh(&queue->syn_wait_lock);
	queue->listen_opt = lopt;
	write_unlock_bh(&queue->syn_wait_lock);

	return 0;
}

EXPORT_SYMBOL(reqsk_queue_alloc);

void reqsk_queue_destroy(struct request_sock_queue *queue)
{
	/* make all the listen_opt local to us */
	struct listen_sock *lopt = reqsk_queue_yank_listen_sk(queue);
	size_t lopt_size = sizeof(struct listen_sock) +
		lopt->nr_table_entries * sizeof(struct request_sock *);

	if (lopt->qlen != 0) {
		unsigned int i;

		for (i = 0; i < lopt->nr_table_entries; i++) {
			struct request_sock *req;

			while ((req = lopt->syn_table[i]) != NULL) {
				lopt->syn_table[i] = req->dl_next;
				lopt->qlen--;
				reqsk_free(req);
			}
		}
	}

	BUG_TRAP(lopt->qlen == 0);
	if (lopt_size > PAGE_SIZE)
		vfree(lopt);
	else
		kfree(lopt);
}

EXPORT_SYMBOL(reqsk_queue_destroy);
