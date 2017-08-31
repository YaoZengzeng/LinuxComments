/*
 *     SUCS NET3:
 *
 *     Generic stream handling routines. These are generic for most
 *     protocols. Even IP. Tonight 8-).
 *     This is used because TCP, LLC (others too) layer all have mostly
 *     identical sendmsg() and recvmsg() code.
 *     So we (will) share it here.
 *
 *     Authors:        Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *                     (from old tcp.c code)
 *                     Alan Cox <alan@redhat.com> (Borrowed comments 8-))
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/signal.h>
#include <linux/tcp.h>
#include <linux/wait.h>
#include <net/sock.h>

/**
 * sk_stream_write_space - stream socket write_space callback.
 * @sk: socket
 *
 * FIXME: write proper description
 */
void sk_stream_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
			wake_up_interruptible(sk->sk_sleep);
		if (sock->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(sock, 2, POLL_OUT);
	}
}

EXPORT_SYMBOL(sk_stream_write_space);

/**
 * sk_stream_wait_connect - Wait for a socket to get into the connected state
 * @sk: sock to wait on
 * @timeo_p: for how long to wait
 *
 * Must be called with the socket locked.
 */
int sk_stream_wait_connect(struct sock *sk, long *timeo_p)
{
	struct task_struct *tsk = current;
	DEFINE_WAIT(wait);
	int done;

	do {
		int err = sock_error(sk);
		if (err)
			return err;
		if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV))
			return -EPIPE;
		if (!*timeo_p)
			return -EAGAIN;
		if (signal_pending(tsk))
			return sock_intr_errno(*timeo_p);

		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
		sk->sk_write_pending++;
		done = sk_wait_event(sk, timeo_p,
				     !sk->sk_err &&
				     !((1 << sk->sk_state) & 
				       ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)));
		finish_wait(sk->sk_sleep, &wait);
		sk->sk_write_pending--;
	} while (!done);
	return 0;
}

EXPORT_SYMBOL(sk_stream_wait_connect);

/**
 * sk_stream_closing - Return 1 if we still have things to send in our buffers.
 * @sk: socket to verify
 */
static inline int sk_stream_closing(struct sock *sk)
{
	return (1 << sk->sk_state) &
	       (TCPF_FIN_WAIT1 | TCPF_CLOSING | TCPF_LAST_ACK);
}

void sk_stream_wait_close(struct sock *sk, long timeout)
{
	if (timeout) {
		DEFINE_WAIT(wait);

		do {
			prepare_to_wait(sk->sk_sleep, &wait,
					TASK_INTERRUPTIBLE);
			if (sk_wait_event(sk, &timeout, !sk_stream_closing(sk)))
				break;
		} while (!signal_pending(current) && timeout);

		finish_wait(sk->sk_sleep, &wait);
	}
}

EXPORT_SYMBOL(sk_stream_wait_close);

/**
 * sk_stream_wait_memory - Wait for more memory for a socket
 * @sk: socket to wait for memory
 * @timeo_p: for how long
 */
// 在发送数据时，如果分配缓冲区失败，则会调用sk_stream_wait_memory()等待
// 该函数返回0，表示等待成功，返回非0，则为具体出错的错误码
int sk_stream_wait_memory(struct sock *sk, long *timeo_p)
{
	int err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT(wait);

	if (sk_stream_memory_free(sk))
		current_timeo = vm_wait = (net_random() % (HZ / 5)) + 2;

	while (1) {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

		if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
			goto do_error;
		if (!*timeo_p)
			goto do_nonblock;
		if (signal_pending(current))
			goto do_interrupted;
		clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		if (sk_stream_memory_free(sk) && !vm_wait)
			break;

		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk->sk_write_pending++;
		sk_wait_event(sk, &current_timeo, !sk->sk_err && 
						  !(sk->sk_shutdown & SEND_SHUTDOWN) &&
						  sk_stream_memory_free(sk) &&
						  vm_wait);
		sk->sk_write_pending--;

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo_p;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo_p = current_timeo;
	}
out:
	finish_wait(sk->sk_sleep, &wait);
	return err;

do_error:
	err = -EPIPE;
	goto out;
do_nonblock:
	err = -EAGAIN;
	goto out;
do_interrupted:
	err = sock_intr_errno(*timeo_p);
	goto out;
}

EXPORT_SYMBOL(sk_stream_wait_memory);

void sk_stream_rfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	skb_truesize_check(skb);
	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	sk->sk_forward_alloc += skb->truesize;
}

EXPORT_SYMBOL(sk_stream_rfree);

int sk_stream_error(struct sock *sk, int flags, int err)
{
	if (err == -EPIPE)
		err = sock_error(sk) ? : -EPIPE;
	if (err == -EPIPE && !(flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);
	return err;
}

EXPORT_SYMBOL(sk_stream_error);

// 在多数情况下会调用sk_stream_mem_reclaim()来回收缓存，如，在断开连接，释放传输控制块，关闭tcp套接口时
// 释放发送或接收队列中的skb
// sk_stream_mem_reclaim()只在预分配量大于一个页面时，才调用__sk_stream_mem_reclaim()进行真正的缓存回收
void __sk_stream_mem_reclaim(struct sock *sk)
{
	// 调整memory_allocated和sk_forward_alloc
	atomic_sub(sk->sk_forward_alloc / SK_STREAM_MEM_QUANTUM,
		   sk->sk_prot->memory_allocated);
	sk->sk_forward_alloc &= SK_STREAM_MEM_QUANTUM - 1;
	// 如果处于告警状态且已分配内存低于低水平线，则将状态恢复到正常状态
	if (*sk->sk_prot->memory_pressure &&
	    (atomic_read(sk->sk_prot->memory_allocated) <
	     sk->sk_prot->sysctl_mem[0]))
		*sk->sk_prot->memory_pressure = 0;
}

EXPORT_SYMBOL(__sk_stream_mem_reclaim);

// 无论是为发送而分配skb，还是将报文接收到tcp传输层，都需要对新进入传输控制块的缓存进行确认
// 确认时如果套接缓存中的数据长度大于预分配量，则需要进行全面的确认，这个过程由sk_stream_mem_schedule()实现
// size：要确认的缓存长度
// kind：类型，0为发送缓存，1为接收缓存
int sk_stream_mem_schedule(struct sock *sk, int size, int kind)
{
	// 根据待确认的缓存长度，向上取整获得所占用的页面数
	int amt = sk_stream_pages(size);

	// 在确认之前需预先调整预分配量，加上之前计算得到的页面字节数，调整整个tcp传输层已分配内存
	// 加上之前计算得到的页面数
	sk->sk_forward_alloc += amt * SK_STREAM_MEM_QUANTUM;
	atomic_add(amt, sk->sk_prot->memory_allocated);

	/* Under limit. */
	// 如果已分配内存低于低水平线，则将原先的告警状态恢复到正常状态，返回1，表示确认成功
	if (atomic_read(sk->sk_prot->memory_allocated) < sk->sk_prot->sysctl_mem[0]) {
		if (*sk->sk_prot->memory_pressure)
			*sk->sk_prot->memory_pressure = 0;
		return 1;
	}

	/* Over hard limit. */
	// 如果已分配内存高于警戒线但低于硬性限制线，则进入告警状态
	if (atomic_read(sk->sk_prot->memory_allocated) > sk->sk_prot->sysctl_mem[2]) {
		sk->sk_prot->enter_memory_pressure();
		goto suppress_allocation;
	}

	/* Under pressure. */
	// 如果已分配内存高于警戒线但低于硬性限制线，则进入告警状态
	if (atomic_read(sk->sk_prot->memory_allocated) > sk->sk_prot->sysctl_mem[1])
		sk->sk_prot->enter_memory_pressure();

	// 对于已分配的内存高于警戒线但低于硬性限制线情况的处理
	if (kind) {
		// 如果待确认的是接收缓存，且接收队列中段的数据总长度小于接收缓冲区的长度，则确认成功，否则还需要进一步确认
		if (atomic_read(&sk->sk_rmem_alloc) < sk->sk_prot->sysctl_rmem[0])
			return 1;
	} else if (sk->sk_wmem_queued < sk->sk_prot->sysctl_wmem[0])
		// 如果待确认的是发送缓存，且发送队列中段的数据总长度小于发送缓冲区的长度上限，则确认成功，否则还需要进一步确认
		return 1;

	// 如果没有进入告警状态，或者当前套接口发送队列中所有段数据总长度，接收队列中所有段数据总长度
	// 预分配缓存总长度的当前系统中套接口数量的倍数这三者之和还小于硬性限制线，则确认成功
	if (!*sk->sk_prot->memory_pressure ||
	    sk->sk_prot->sysctl_mem[2] > atomic_read(sk->sk_prot->sockets_allocated) *
				sk_stream_pages(sk->sk_wmem_queued +
						atomic_read(&sk->sk_rmem_alloc) +
						sk->sk_forward_alloc))
		return 1;

// 处理已分配的内存高于硬性限制线的情况
suppress_allocation:

	if (!kind) {
		// 若待确认的是发送缓存，则将传输控制块发送缓冲区的预设大小减小为已分配缓冲队列大小的一半
		sk_stream_moderate_sndbuf(sk);

		/* Fail only if socket is _under_ its sndbuf.
		 * In this case we cannot block, so that we have to fail.
		 */
		// 如果已分配缓冲队列大小与待确认长度之和大于sk_sndbuf，则可通过确认
		// 如果待确认的是接收缓存，当已分配的内存高于硬性限制线时，确认必然失败
		if (sk->sk_wmem_queued + size >= sk->sk_sndbuf)
			return 1;
	}

	/* Alas. Undo changes. */
	// 如果确认失败，则恢复sk_forward_alloc和memory_allocated
	sk->sk_forward_alloc -= amt * SK_STREAM_MEM_QUANTUM;
	atomic_sub(amt, sk->sk_prot->memory_allocated);
	return 0;
}

EXPORT_SYMBOL(sk_stream_mem_schedule);

void sk_stream_kill_queues(struct sock *sk)
{
	/* First the read buffer. */
	__skb_queue_purge(&sk->sk_receive_queue);

	/* Next, the error queue. */
	__skb_queue_purge(&sk->sk_error_queue);

	/* Next, the write queue. */
	BUG_TRAP(skb_queue_empty(&sk->sk_write_queue));

	/* Account for returned memory. */
	sk_stream_mem_reclaim(sk);

	BUG_TRAP(!sk->sk_wmem_queued);
	BUG_TRAP(!sk->sk_forward_alloc);

	/* It is _impossible_ for the backlog to contain anything
	 * when we get here.  All user references to this socket
	 * have gone away, only the net layer knows can touch it.
	 */
}

EXPORT_SYMBOL(sk_stream_kill_queues);
