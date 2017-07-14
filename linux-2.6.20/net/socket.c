/*
 * NET		An implementation of the SOCKET network access protocol.
 *
 * Version:	@(#)socket.c	1.1.93	18/02/95
 *
 * Authors:	Orest Zborowski, <obz@Kodak.COM>
 *		Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Fixes:
 *		Anonymous	:	NOTSOCK/BADF cleanup. Error fix in
 *					shutdown()
 *		Alan Cox	:	verify_area() fixes
 *		Alan Cox	:	Removed DDI
 *		Jonathan Kamens	:	SOCK_DGRAM reconnect bug
 *		Alan Cox	:	Moved a load of checks to the very
 *					top level.
 *		Alan Cox	:	Move address structures to/from user
 *					mode above the protocol layers.
 *		Rob Janssen	:	Allow 0 length sends.
 *		Alan Cox	:	Asynchronous I/O support (cribbed from the
 *					tty drivers).
 *		Niibe Yutaka	:	Asynchronous I/O for writes (4.4BSD style)
 *		Jeff Uphoff	:	Made max number of sockets command-line
 *					configurable.
 *		Matti Aarnio	:	Made the number of sockets dynamic,
 *					to be allocated when needed, and mr.
 *					Uphoff's max is used as max to be
 *					allowed to allocate.
 *		Linus		:	Argh. removed all the socket allocation
 *					altogether: it's in the inode now.
 *		Alan Cox	:	Made sock_alloc()/sock_release() public
 *					for NetROM and future kernel nfsd type
 *					stuff.
 *		Alan Cox	:	sendmsg/recvmsg basics.
 *		Tom Dyas	:	Export net symbols.
 *		Marcin Dalecki	:	Fixed problems with CONFIG_NET="n".
 *		Alan Cox	:	Added thread locking to sys_* calls
 *					for sockets. May have errors at the
 *					moment.
 *		Kevin Buhr	:	Fixed the dumb errors in the above.
 *		Andi Kleen	:	Some small cleanups, optimizations,
 *					and fixed a copy_from_user() bug.
 *		Tigran Aivazian	:	sys_send(args) calls sys_sendto(args, NULL, 0)
 *		Tigran Aivazian	:	Made listen(2) backlog sanity checks
 *					protocol-independent
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *
 *	This module is effectively the top level interface to the BSD socket
 *	paradigm.
 *
 *	Based upon Swansea University Computer Society NET3.039
 */

#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/wanrouter.h>
#include <linux/if_bridge.h>
#include <linux/if_frad.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/kmod.h>
#include <linux/audit.h>
#include <linux/wireless.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <net/compat.h>

#include <net/sock.h>
#include <linux/netfilter.h>

static int sock_no_open(struct inode *irrelevant, struct file *dontcare);
static ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t pos);
static ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
			  unsigned long nr_segs, loff_t pos);
static int sock_mmap(struct file *file, struct vm_area_struct *vma);

static int sock_close(struct inode *inode, struct file *file);
static unsigned int sock_poll(struct file *file,
			      struct poll_table_struct *wait);
static long sock_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
static long compat_sock_ioctl(struct file *file,
			      unsigned int cmd, unsigned long arg);
#endif
static int sock_fasync(int fd, struct file *filp, int on);
static ssize_t sock_sendpage(struct file *file, struct page *page,
			     int offset, size_t size, loff_t *ppos, int more);

/*
 *	Socket files have a set of 'special' operations as well as the generic file ones. These don't appear
 *	in the operation structures but are done directly via the socketcall() multiplexor.
 */
// 套接口有一套独立的系统调用，包括建立套接口、连接和IO操作等，由于在建立套接口后返回的文件描述符
// 因此也可以通过标准的文件IO操作进行对套接口的读写。这是由于在创建套接口文件时，使file结构中的
// f_ops指向了socket_file_ops
static struct file_operations socket_file_ops = {
	.owner =	THIS_MODULE,
	.llseek =	no_llseek,
	.aio_read =	sock_aio_read,
	.aio_write =	sock_aio_write,
	.poll =		sock_poll,
	.unlocked_ioctl = sock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_sock_ioctl,
#endif
	.mmap =		sock_mmap,
	.open =		sock_no_open,	/* special open code to disallow open via /proc */
	.release =	sock_close,
	.fasync =	sock_fasync,
	.sendpage =	sock_sendpage,
	.splice_write = generic_splice_sendpage,
};

/*
 *	The protocol list. Each protocol is registered in here.
 */

static DEFINE_SPINLOCK(net_family_lock);
static const struct net_proto_family *net_families[NPROTO] __read_mostly;

/*
 *	Statistics counters of the socket lists
 */

static DEFINE_PER_CPU(int, sockets_in_use) = 0;

/*
 * Support routines.
 * Move socket addresses back and forth across the kernel/user
 * divide and look after the messy bits.
 */

#define MAX_SOCK_ADDR	128		/* 108 for Unix domain -
					   16 for IP, 16 for IPX,
					   24 for IPv6,
					   about 80 for AX.25
					   must be at least one bigger than
					   the AF_UNIX size (see net/unix/af_unix.c
					   :unix_mkname()).
					 */

/**
 *	move_addr_to_kernel	-	copy a socket address into kernel space
 *	@uaddr: Address in user space
 *	@kaddr: Address in kernel space
 *	@ulen: Length in user space
 *
 *	The address is copied into kernel space. If the provided address is
 *	too long an error code of -EINVAL is returned. If the copy gives
 *	invalid addresses -EFAULT is returned. On a success 0 is returned.
 */

int move_addr_to_kernel(void __user *uaddr, int ulen, void *kaddr)
{
	if (ulen < 0 || ulen > MAX_SOCK_ADDR)
		return -EINVAL;
	if (ulen == 0)
		return 0;
	if (copy_from_user(kaddr, uaddr, ulen))
		return -EFAULT;
	return audit_sockaddr(ulen, kaddr);
}

/**
 *	move_addr_to_user	-	copy an address to user space
 *	@kaddr: kernel space address
 *	@klen: length of address in kernel
 *	@uaddr: user space address
 *	@ulen: pointer to user length field
 *
 *	The value pointed to by ulen on entry is the buffer length available.
 *	This is overwritten with the buffer space used. -EINVAL is returned
 *	if an overlong buffer is specified or a negative buffer size. -EFAULT
 *	is returned if either the buffer or the length field are not
 *	accessible.
 *	After copying the data up to the limit the user specifies, the true
 *	length of the data is written over the length limit the user
 *	specified. Zero is returned for a success.
 */

int move_addr_to_user(void *kaddr, int klen, void __user *uaddr,
		      int __user *ulen)
{
	int err;
	int len;

	err = get_user(len, ulen);
	if (err)
		return err;
	if (len > klen)
		len = klen;
	if (len < 0 || len > MAX_SOCK_ADDR)
		return -EINVAL;
	if (len) {
		if (audit_sockaddr(klen, kaddr))
			return -ENOMEM;
		if (copy_to_user(uaddr, kaddr, len))
			return -EFAULT;
	}
	/*
	 *      "fromlen shall refer to the value before truncation.."
	 *                      1003.1g
	 */
	return __put_user(klen, ulen);
}

#define SOCKFS_MAGIC 0x534F434B

static struct kmem_cache *sock_inode_cachep __read_mostly;

// 套接口文件系统有自己的i节点分配和释放函数sock_alloc_inode(),在文件系统模块
// 分配i节点的接口中会根据文件系统调用对应的i节点分配和释放函数
static struct inode *sock_alloc_inode(struct super_block *sb)
{
	struct socket_alloc *ei;

	// 从sock_inode_cache缓存中分配socket_alloc类型大小的内存用来存放i节点和socket结构
	ei = kmem_cache_alloc(sock_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	// 初始化进程等待队列
	init_waitqueue_head(&ei->socket.wait);

	// 初始化套接口中的其他信息
	ei->socket.fasync_list = NULL;
	ei->socket.state = SS_UNCONNECTED;
	ei->socket.flags = 0;
	ei->socket.ops = NULL;
	ei->socket.sk = NULL;
	ei->socket.file = NULL;

	return &ei->vfs_inode;
}

static void sock_destroy_inode(struct inode *inode)
{
	kmem_cache_free(sock_inode_cachep,
			// 通过i节点定位到与之对应的套接口，然后释放
			container_of(inode, struct socket_alloc, vfs_inode));
}

static void init_once(void *foo, struct kmem_cache *cachep, unsigned long flags)
{
	struct socket_alloc *ei = (struct socket_alloc *)foo;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR))
	    == SLAB_CTOR_CONSTRUCTOR)
		inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	sock_inode_cachep = kmem_cache_create("sock_inode_cache",
					      sizeof(struct socket_alloc),
					      0,
					      (SLAB_HWCACHE_ALIGN |
					       SLAB_RECLAIM_ACCOUNT |
					       SLAB_MEM_SPREAD),
					      init_once,
					      NULL);
	if (sock_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

// sockfs_ops定义了套接口文件系统的操作接口，支持的具体接口有
// i节点的分配、释放和获取文件系统的状态信息
static struct super_operations sockfs_ops = {
	.alloc_inode =	sock_alloc_inode,
	.destroy_inode =sock_destroy_inode,
	.statfs =	simple_statfs,
};

static int sockfs_get_sb(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data,
			 struct vfsmount *mnt)
{
	return get_sb_pseudo(fs_type, "socket:", &sockfs_ops, SOCKFS_MAGIC,
			     mnt);
}

static struct vfsmount *sock_mnt __read_mostly;

// 为了能使套接口与文件描述符关联，并支持特殊套接口层的i节点分配和释放
// 系统中增加了sockfs文件系统类型sock_fs_type，通过sockfs文件系统
// 的get_sb接口和超级块操作集合中的alloc_inode和destroy_inode，可以
// 分配和释放与套接口文件相关的i节点
static struct file_system_type sock_fs_type = {
	.name =		"sockfs",
	.get_sb =	sockfs_get_sb,
	.kill_sb =	kill_anon_super,
};

static int sockfs_delete_dentry(struct dentry *dentry)
{
	/*
	 * At creation time, we pretended this dentry was hashed
	 * (by clearing DCACHE_UNHASHED bit in d_flags)
	 * At delete time, we restore the truth : not hashed.
	 * (so that dput() can proceed correctly)
	 */
	dentry->d_flags |= DCACHE_UNHASHED;
	return 0;
}
static struct dentry_operations sockfs_dentry_operations = {
	.d_delete = sockfs_delete_dentry,
};

/*
 *	Obtains the first available file descriptor and sets it up for use.
 *
 *	These functions create file structures and maps them to fd space
 *	of the current process. On success it returns file descriptor
 *	and file struct implicitly stored in sock->file.
 *	Note that another thread may close file descriptor before we return
 *	from this function. We use the fact that now we do not refer
 *	to socket after mapping. If one day we will need it, this
 *	function will increment ref. count on file by 1.
 *
 *	In any case returned fd MAY BE not valid!
 *	This race condition is unavoidable
 *	with shared fd spaces, we cannot solve it inside kernel,
 *	but we take care of internal coherence yet.
 */

static int sock_alloc_fd(struct file **filep)
{
	int fd;

	// 申请文件描述符
	fd = get_unused_fd();
	if (likely(fd >= 0)) {
		// 分配文件结构空间
		struct file *file = get_empty_filp();

		*filep = file;
		if (unlikely(!file)) {
			put_unused_fd(fd);
			return -ENFILE;
		}
	} else
		*filep = NULL;
	return fd;
}

static int sock_attach_fd(struct socket *sock, struct file *file)
{
	struct qstr this;
	char name[32];

	// 给套接口文件命名并分配目录项，并提供对目录项的操作功能
	this.len = sprintf(name, "[%lu]", SOCK_INODE(sock)->i_ino);
	this.name = name;
	this.hash = 0;

	file->f_path.dentry = d_alloc(sock_mnt->mnt_sb->s_root, &this);
	if (unlikely(!file->f_path.dentry))
		return -ENOMEM;

	// 目录项的操作表挂入socket文件系统的目录操作表
	file->f_path.dentry->d_op = &sockfs_dentry_operations;
	/*
	 * We dont want to push this dentry into global dentry hash table.
	 * We pretend dentry is already hashed, by unsetting DCACHE_UNHASHED
	 * This permits a working /proc/$pid/fd/XXX on sockets
	 */
	// 去掉DCACHE_UNHASHED标志（这样不会把目录项插入到全局的目录项散列表中，在/proc
	// /$pid/fd/中才能看到套接口文件）
	file->f_path.dentry->d_flags &= ~DCACHE_UNHASHED;
	// 填充目录项中有关套接口文件i节点的信息，目录项中的文件兄台哪个信息，地址空间等
	d_instantiate(file->f_path.dentry, SOCK_INODE(sock));
	file->f_path.mnt = mntget(sock_mnt);
	file->f_mapping = file->f_path.dentry->d_inode->i_mapping;

	// 实现套接口和文件的绑定
	sock->file = file;
	// file结构中的f_op和inode结构中的i_fop是对文件操作集合表的指针
	file->f_op = SOCK_INODE(sock)->i_fop = &socket_file_ops;
	file->f_mode = FMODE_READ | FMODE_WRITE;
	file->f_flags = O_RDWR;
	file->f_pos = 0;
	file->private_data = sock;

	return 0;
}

// 实际上sock_map_fd()有一部分工作类似于普通文件open系统调用：获取一个空闲描述符
// 创建一个file结构实例，并绑定两者，最后将file结构添加到进程打开的文件指针数组中
// 除此之外还要绑定套接口和file
int sock_map_fd(struct socket *sock)
{
	struct file *newfile;
	// 获取空闲的文件描述符和文件描述符结构实例
	int fd = sock_alloc_fd(&newfile);

	if (likely(fd >= 0)) {
		int err = sock_attach_fd(sock, newfile);

		if (unlikely(err < 0)) {
			// 操作过程中出现错误则释放文件和文件号
			put_filp(newfile);
			put_unused_fd(fd);
			return err;
		}
		// 调用文件系统模块的fd_install()，在当前进程中，根据文件描述符将文件描述符
		// 结构实例增加到已打开的文件列表中去，完成文件与进程的关联
		fd_install(fd, newfile);
	}
	return fd;
}

static struct socket *sock_from_file(struct file *file, int *err)
{
	struct inode *inode;
	struct socket *sock;

	// 根据对文件操作表指针的判断，如果此文件的操作表指针为socket_file_ops的地址
	// 表明此文件为套接口文件，因此直接返回文件描述符中的private_data的值，该值
	// 是在套接口和文件描述进行关联时，在sock_attach_fd()中被设置
	if (file->f_op == &socket_file_ops)
		return file->private_data;	/* set in sock_map_fd */

	// 否则，需要获取套接口文件的i节点进行判断，首先获取i节点，然后判断i节点的类型
	// 如果i节点不是套接口类型，则设置错误码后直接返回
	inode = file->f_path.dentry->d_inode;
	if (!S_ISSOCK(inode->i_mode)) {
		*err = -ENOTSOCK;
		return NULL;
	}

	// 根据得到的i节点，利用偏移的方法获取套接口指针
	sock = SOCKET_I(inode);
	// 这里做了容错的处理，如果发现套接口中的文件描述符指针和通过参数传入的文件描述符指针
	// 不一致，则重新进行套接口文件描述符指针的设置
	if (sock->file != file) {
		printk(KERN_ERR "socki_lookup: socket file changed!\n");
		sock->file = file;
	}
	return sock;
}

/**
 *	sockfd_lookup	- 	Go from a file number to its socket slot
 *	@fd: file handle
 *	@err: pointer to an error code return
 *
 *	The file handle passed in is locked and the socket it is bound
 *	too is returned. If an error occurs the err pointer is overwritten
 *	with a negative errno code and NULL is returned. The function checks
 *	for both invalid handles and passing a handle which is not a socket.
 *
 *	On a success the socket object pointer is returned.
 */

struct socket *sockfd_lookup(int fd, int *err)
{
	struct file *file;
	struct socket *sock;

	file = fget(fd);
	if (!file) {
		*err = -EBADF;
		return NULL;
	}

	sock = sock_from_file(file, err);
	if (!sock)
		fput(file);
	return sock;
}

// 套接口自创建之后起，对它的操作都是通过其对应的文件描述符来进行的，因此每次对套接口
// 操作之前都需要由参数给出的文件描述符得到套接口本身
// fput_needed，当操作成功时，返回是否对该文件进行减少该文件引用计数的操作
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct file *file;
	struct socket *sock;

	*err = -EBADF;
	// 调用文件系统模块函数fget_light()，根据文件描述符获取对应的文件描述结构实例
	// 并获取是否需要减少对文件引用计数的标志
	file = fget_light(fd, fput_needed);
	if (file) {
		// 如果成功获取文件描述，则根据文件描述符获取套接口指针，如果成功获取套接口指针
		// 则返回对应的套接口，否则根据fput_needed确定减少对文件的引用计数
		sock = sock_from_file(file, err);
		if (sock)
			return sock;
		fput_light(file, *fput_needed);
	}
	return NULL;
}

/**
 *	sock_alloc	-	allocate a socket
 *
 *	Allocate a new inode and socket object. The two are bound together
 *	and initialised. The socket is then returned. If we are out of inodes
 *	NULL is returned.
 */
// 分配socket结构和文件节点
static struct socket *sock_alloc(void)
{
	struct inode *inode;
	struct socket *sock;

	// sock_mnt是socket网络文件系统的根节点
	// 最终调用sock_alloc_inode函数
	inode = new_inode(sock_mnt->mnt_sb);
	if (!inode)
		return NULL;

	sock = SOCKET_I(inode);

	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current->fsuid;
	inode->i_gid = current->fsgid;

	get_cpu_var(sockets_in_use)++;
	put_cpu_var(sockets_in_use);
	return sock;
}

/*
 *	In theory you can't get an open on this inode, but /proc provides
 *	a back door. Remember to keep it shut otherwise you'll let the
 *	creepy crawlies in.
 */

static int sock_no_open(struct inode *irrelevant, struct file *dontcare)
{
	return -ENXIO;
}

const struct file_operations bad_sock_fops = {
	.owner = THIS_MODULE,
	.open = sock_no_open,
};

/**
 *	sock_release	-	close a socket
 *	@sock: socket to close
 *
 *	The socket is released from the protocol stack if it has a release
 *	callback, and the inode is then released if the socket is bound to
 *	an inode not a file.
 */
// sock_release()实现关闭套接口的功能
void sock_release(struct socket *sock)
{
	if (sock->ops) {
		struct module *owner = sock->ops->owner;

		// 通过套接口层接口proto_ops结构，调用release()，实现对传输控制块的释放
		// IPv4中所有的套接口的release接口都是inet_release()，它将实现对具体
		// 传输层close的有关调用
		sock->ops->release(sock);
		sock->ops = NULL;
		// 同时对模块的引用计数减1
		module_put(owner);
	}

	// 处理异步通知队列之后，若发现异步通知队列不为空，则表面系统处理有问题
	// 打印信息提示
	if (sock->fasync_list)
		printk(KERN_ERR "sock_release: fasync list not empty!\n");

	// 更新sockets_in_use，sockets_in_use主要用来统计当前CPU打开的套接口
	// 文件的数量
	get_cpu_var(sockets_in_use)--;
	put_cpu_var(sockets_in_use);
	//　释放i节点和套接口，一般不会被调用，除非系统处理有异常，这里是进行容错处理
	if (!sock->file) {
		iput(SOCK_INODE(sock));
		return;
	}
	// 把套接口中的文件描述指针设置为空，到此为止，有关套接口关闭的处理已经完成
	// 接下来就是释放套接口资源、文件描述符和i节点了
	sock->file = NULL;
}

static inline int __sock_sendmsg(struct kiocb *iocb, struct socket *sock,
				 struct msghdr *msg, size_t size)
{
	struct sock_iocb *si = kiocb_to_siocb(iocb);
	int err;

	si->sock = sock;
	si->scm = NULL;
	si->msg = msg;
	si->size = size;

	err = security_socket_sendmsg(sock, msg, size);
	if (err)
		return err;

	return sock->ops->sendmsg(iocb, sock, msg, size);
}

int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;

	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __sock_sendmsg(&iocb, sock, msg, size);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}

int kernel_sendmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size)
{
	mm_segment_t oldfs = get_fs();
	int result;

	set_fs(KERNEL_DS);
	/*
	 * the following is safe, since for compiler definitions of kvec and
	 * iovec are identical, yielding the same in-core layout and alignment
	 */
	msg->msg_iov = (struct iovec *)vec;
	msg->msg_iovlen = num;
	result = sock_sendmsg(sock, msg, size);
	set_fs(oldfs);
	return result;
}

static inline int __sock_recvmsg(struct kiocb *iocb, struct socket *sock,
				 struct msghdr *msg, size_t size, int flags)
{
	int err;
	struct sock_iocb *si = kiocb_to_siocb(iocb);

	si->sock = sock;
	si->scm = NULL;
	si->msg = msg;
	si->size = size;
	si->flags = flags;

	err = security_socket_recvmsg(sock, msg, size, flags);
	if (err)
		return err;

	return sock->ops->recvmsg(iocb, sock, msg, size, flags);
}

int sock_recvmsg(struct socket *sock, struct msghdr *msg,
		 size_t size, int flags)
{
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;

	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __sock_recvmsg(&iocb, sock, msg, size, flags);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}

int kernel_recvmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size, int flags)
{
	mm_segment_t oldfs = get_fs();
	int result;

	set_fs(KERNEL_DS);
	/*
	 * the following is safe, since for compiler definitions of kvec and
	 * iovec are identical, yielding the same in-core layout and alignment
	 */
	msg->msg_iov = (struct iovec *)vec, msg->msg_iovlen = num;
	result = sock_recvmsg(sock, msg, size, flags);
	set_fs(oldfs);
	return result;
}

static void sock_aio_dtor(struct kiocb *iocb)
{
	kfree(iocb->private);
}

static ssize_t sock_sendpage(struct file *file, struct page *page,
			     int offset, size_t size, loff_t *ppos, int more)
{
	struct socket *sock;
	int flags;

	sock = file->private_data;

	flags = !(file->f_flags & O_NONBLOCK) ? 0 : MSG_DONTWAIT;
	if (more)
		flags |= MSG_MORE;

	return sock->ops->sendpage(sock, page, offset, size, flags);
}

static struct sock_iocb *alloc_sock_iocb(struct kiocb *iocb,
					 struct sock_iocb *siocb)
{
	if (!is_sync_kiocb(iocb)) {
		siocb = kmalloc(sizeof(*siocb), GFP_KERNEL);
		if (!siocb)
			return NULL;
		iocb->ki_dtor = sock_aio_dtor;
	}

	siocb->kiocb = iocb;
	iocb->private = siocb;
	return siocb;
}

static ssize_t do_sock_read(struct msghdr *msg, struct kiocb *iocb,
		struct file *file, const struct iovec *iov,
		unsigned long nr_segs)
{
	struct socket *sock = file->private_data;
	size_t size = 0;
	int i;

	for (i = 0; i < nr_segs; i++)
		size += iov[i].iov_len;

	msg->msg_name = NULL;
	msg->msg_namelen = 0;
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_iov = (struct iovec *)iov;
	msg->msg_iovlen = nr_segs;
	msg->msg_flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;

	return __sock_recvmsg(iocb, sock, msg, size, msg->msg_flags);
}

static ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	struct sock_iocb siocb, *x;

	if (pos != 0)
		return -ESPIPE;

	if (iocb->ki_left == 0)	/* Match SYS5 behaviour */
		return 0;


	x = alloc_sock_iocb(iocb, &siocb);
	if (!x)
		return -ENOMEM;
	return do_sock_read(&x->async_msg, iocb, iocb->ki_filp, iov, nr_segs);
}

static ssize_t do_sock_write(struct msghdr *msg, struct kiocb *iocb,
			struct file *file, const struct iovec *iov,
			unsigned long nr_segs)
{
	struct socket *sock = file->private_data;
	size_t size = 0;
	int i;

	for (i = 0; i < nr_segs; i++)
		size += iov[i].iov_len;

	msg->msg_name = NULL;
	msg->msg_namelen = 0;
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_iov = (struct iovec *)iov;
	msg->msg_iovlen = nr_segs;
	msg->msg_flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
	if (sock->type == SOCK_SEQPACKET)
		msg->msg_flags |= MSG_EOR;

	return __sock_sendmsg(iocb, sock, msg, size);
}

static ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
			  unsigned long nr_segs, loff_t pos)
{
	struct sock_iocb siocb, *x;

	if (pos != 0)
		return -ESPIPE;

	if (iocb->ki_left == 0)	/* Match SYS5 behaviour */
		return 0;

	x = alloc_sock_iocb(iocb, &siocb);
	if (!x)
		return -ENOMEM;

	return do_sock_write(&x->async_msg, iocb, iocb->ki_filp, iov, nr_segs);
}

/*
 * Atomic setting of ioctl hooks to avoid race
 * with module unload.
 */

static DEFINE_MUTEX(br_ioctl_mutex);
static int (*br_ioctl_hook) (unsigned int cmd, void __user *arg) = NULL;

void brioctl_set(int (*hook) (unsigned int, void __user *))
{
	mutex_lock(&br_ioctl_mutex);
	br_ioctl_hook = hook;
	mutex_unlock(&br_ioctl_mutex);
}

EXPORT_SYMBOL(brioctl_set);

static DEFINE_MUTEX(vlan_ioctl_mutex);
static int (*vlan_ioctl_hook) (void __user *arg);

void vlan_ioctl_set(int (*hook) (void __user *))
{
	mutex_lock(&vlan_ioctl_mutex);
	vlan_ioctl_hook = hook;
	mutex_unlock(&vlan_ioctl_mutex);
}

EXPORT_SYMBOL(vlan_ioctl_set);

static DEFINE_MUTEX(dlci_ioctl_mutex);
static int (*dlci_ioctl_hook) (unsigned int, void __user *);

void dlci_ioctl_set(int (*hook) (unsigned int, void __user *))
{
	mutex_lock(&dlci_ioctl_mutex);
	dlci_ioctl_hook = hook;
	mutex_unlock(&dlci_ioctl_mutex);
}

EXPORT_SYMBOL(dlci_ioctl_set);

/*
 *	With an ioctl, arg may well be a user mode pointer, but we don't know
 *	what to do with it - that's up to the protocol still.
 */

static long sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct socket *sock;
	void __user *argp = (void __user *)arg;
	int pid, err;

	sock = file->private_data;
	if (cmd >= SIOCDEVPRIVATE && cmd <= (SIOCDEVPRIVATE + 15)) {
		err = dev_ioctl(cmd, argp);
	} else
#ifdef CONFIG_WIRELESS_EXT
	if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {
		err = dev_ioctl(cmd, argp);
	} else
#endif				/* CONFIG_WIRELESS_EXT */
		switch (cmd) {
		case FIOSETOWN:
		case SIOCSPGRP:
			err = -EFAULT;
			if (get_user(pid, (int __user *)argp))
				break;
			err = f_setown(sock->file, pid, 1);
			break;
		case FIOGETOWN:
		case SIOCGPGRP:
			err = put_user(f_getown(sock->file),
				       (int __user *)argp);
			break;
		case SIOCGIFBR:
		case SIOCSIFBR:
		case SIOCBRADDBR:
		case SIOCBRDELBR:
			err = -ENOPKG;
			if (!br_ioctl_hook)
				request_module("bridge");

			mutex_lock(&br_ioctl_mutex);
			if (br_ioctl_hook)
				err = br_ioctl_hook(cmd, argp);
			mutex_unlock(&br_ioctl_mutex);
			break;
		case SIOCGIFVLAN:
		case SIOCSIFVLAN:
			err = -ENOPKG;
			if (!vlan_ioctl_hook)
				request_module("8021q");

			mutex_lock(&vlan_ioctl_mutex);
			if (vlan_ioctl_hook)
				err = vlan_ioctl_hook(argp);
			mutex_unlock(&vlan_ioctl_mutex);
			break;
		case SIOCADDDLCI:
		case SIOCDELDLCI:
			err = -ENOPKG;
			if (!dlci_ioctl_hook)
				request_module("dlci");

			if (dlci_ioctl_hook) {
				mutex_lock(&dlci_ioctl_mutex);
				err = dlci_ioctl_hook(cmd, argp);
				mutex_unlock(&dlci_ioctl_mutex);
			}
			break;
		default:
			err = sock->ops->ioctl(sock, cmd, arg);

			/*
			 * If this ioctl is unknown try to hand it down
			 * to the NIC driver.
			 */
			if (err == -ENOIOCTLCMD)
				err = dev_ioctl(cmd, argp);
			break;
		}
	return err;
}

int sock_create_lite(int family, int type, int protocol, struct socket **res)
{
	int err;
	struct socket *sock = NULL;

	err = security_socket_create(family, type, protocol, 1);
	if (err)
		goto out;

	sock = sock_alloc();
	if (!sock) {
		err = -ENOMEM;
		goto out;
	}

	sock->type = type;
	err = security_socket_post_create(sock, family, type, protocol, 1);
	if (err)
		goto out_release;

out:
	*res = sock;
	return err;
out_release:
	sock_release(sock);
	sock = NULL;
	goto out;
}

/* No kernel lock held - perfect */
static unsigned int sock_poll(struct file *file, poll_table *wait)
{
	struct socket *sock;

	/*
	 *      We can't return errors to poll, so it's either yes or no.
	 */
	sock = file->private_data;
	return sock->ops->poll(file, sock, wait);
}

static int sock_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct socket *sock = file->private_data;

	return sock->ops->mmap(file, sock, vma);
}

// close系统调用用来关闭各类描述符，当然也包括套接口文件
static int sock_close(struct inode *inode, struct file *filp)
{
	/*
	 *      It was possible the inode is NULL we were
	 *      closing an unfinished socket.
	 */

	if (!inode) {
		printk(KERN_DEBUG "sock_close: NULL inode\n");
		return 0;
	}
	// 从与文件描述符filp关联的套接口的异步通知队列中删除与文件描述符filp有关的
	// 异步通知节点
	sock_fasync(-1, filp, 0);
	// 关闭套接口
	sock_release(SOCKET_I(inode));
	return 0;
}

/*
 *	Update the socket async list
 *
 *	Fasync_list locking strategy.
 *
 *	1. fasync_list is modified only under process context socket lock
 *	   i.e. under semaphore.
 *	2. fasync_list is used under read_lock(&sk->sk_callback_lock)
 *	   or under socket lock.
 *	3. fasync_list can be used from softirq context, so that
 *	   modification under socket lock have to be enhanced with
 *	   write_lock_bh(&sk->sk_callback_lock).
 *							--ANK (990710)
 */
// sock_fasync()实现了对套接口的异步通知队列增加和删除的更新操作，因为它在进程上下文中
// 或在软中断中被使用，因此，在访问异步通知列表时需要上锁，对套接口上锁，对传输控制块上
// sk_callback_lock锁 
static int sock_fasync(int fd, struct file *filp, int on)
{
	struct fasync_struct *fa, *fna = NULL, **prev;
	struct socket *sock;
	struct sock *sk;

	// 如果是添加操作，则需要分配异步通知节点
	if (on) {
		fna = kmalloc(sizeof(struct fasync_struct), GFP_KERNEL);
		if (fna == NULL)
			return -ENOMEM;
	}

	// 获取与此文件相关的套接口和传输控制块
	sock = filp->private_data;

	sk = sock->sk;
	if (sk == NULL) {
		kfree(fna);
		return -EINVAL;
	}

	lock_sock(sk);

	prev = &(sock->fasync_list);

	// 在套接口的异步通知列表中查找与filp相等的节点，用于删除或修改节点
	for (fa = *prev; fa != NULL; prev = &fa->fa_next, fa = *prev)
		if (fa->fa_file == filp)
			break;

	// 如果是添加操作，并且在异步通知列表中有与filp相等的节点，则进行修改操作	
	if (on) {
		if (fa != NULL) {
			write_lock_bh(&sk->sk_callback_lock);
			fa->fa_fd = fd;
			write_unlock_bh(&sk->sk_callback_lock);

			kfree(fna);
			goto out;
		}
		// 异步通知节点的值进行设置后，增加到异步通知列表中
		fna->fa_file = filp;
		fna->fa_fd = fd;
		fna->magic = FASYNC_MAGIC;
		fna->fa_next = sock->fasync_list;
		write_lock_bh(&sk->sk_callback_lock);
		sock->fasync_list = fna;
		write_unlock_bh(&sk->sk_callback_lock);
	} else {
		// 如果在删除的状态下，如果在异步通知列表中找到与filp相等的节点，则进行删除操作
		if (fa != NULL) {
			write_lock_bh(&sk->sk_callback_lock);
			*prev = fa->fa_next;
			write_unlock_bh(&sk->sk_callback_lock);
			kfree(fa);
		}
	}

out:
	release_sock(sock->sk);
	return 0;
}

/* This function may be called only under socket lock or callback_lock */

int sock_wake_async(struct socket *sock, int how, int band)
{
	// 校验套接口和套接口上的异步等待通知队列是否有效
	if (!sock || !sock->fasync_list)
		return -1;
	switch (how) {
	// 检测标识应用程序通过recv等调用时，是否在等待数据的接收，如果正在
	// 等待，则不需要通知应用程序了，否则给应用程序发送SIGIO信号
	case 1:

		if (test_bit(SOCK_ASYNC_WAITDATA, &sock->flags))
			break;
		goto call_kill;
	// 如果此前传输控制块的发送队列曾经到上限，则此时传输控制块的发送队列
	// 可能已经低于上限，因此可以给应用程序发送SIGIO信号	
	case 2:
		if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sock->flags))
			break;
		/* fall through */
	// 对于普通数据，给应用程序发送SIGIO信号	
	case 0:
call_kill:
		__kill_fasync(sock->fasync_list, SIGIO, band);
		break;
	// 对于带外数据，给应用程序发送SIGURG信号	
	case 3:
		__kill_fasync(sock->fasync_list, SIGURG, band);
	}
	return 0;
}

static int __sock_create(int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
	 *      Check protocol is in range
	 */
	// 对参数的合法性进行检查
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

	   This uglymoron is moved from INET layer to here to avoid
	   deadlock in module load.
	 */
	// 目前已废弃了IPv4协议族的SOCK_PACKET类型的套接口，而在系统中另外增加了
	// PF_PACKET类型的协议族，因此这里将SOCK_PACKET强制转换为PF_PACKET类型
	if (family == PF_INET && type == SOCK_PACKET) {
		static int warned;
		if (!warned) {
			warned = 1;
			printk(KERN_INFO "%s uses obsolete (PF_INET,SOCK_PACKET)\n",
			       current->comm);
		}
		family = PF_PACKET;
	}

	// 安全模块对创接口的创建做检查
	err = security_socket_create(family, type, protocol, kern);
	if (err)
		return err;

	/*
	 *	Allocate the socket and allow the family to set things up. if
	 *	the protocol is 0, the family is instructed to select an appropriate
	 *	default.
	 */
	// 调用sock_alloc()在sock_inode_cache缓存中分配与套接口关联的i节点和套接口
	// 同时初始化i节点和套接口，分配失败则直接返回错误码，之所以套接口也可以像一般
	// 的文件对它进行读写，是由于在创建套接口的同时还需要创建与它相关联的文件，此
	// i节点就是用来标识此文件的
	sock = sock_alloc();
	if (!sock) {
		if (net_ratelimit())
			printk(KERN_WARNING "socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
				   closest posix thing */
	}

	// 根据type参数设置套接口的类型
	sock->type = type;

#if defined(CONFIG_KMOD)
	/* Attempt to load a protocol module if the find failed.
	 *
	 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user
	 * requested real, full-featured networking support upon configuration.
	 * Otherwise module support will break!
	 */
	// 如果协议族支持内核模块动态加载，但在创建此协议族类型的套接口时，内核模块并未加载
	// 则调用request_module()进行对内核模块的动态加载
	if (net_families[family] == NULL)
		request_module("net-pf-%d", family);
#endif

	rcu_read_lock();
	// 根据参数family获取已注册到net_families中的对应的net_proto_family指针
	pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	// 如果family标识类型的协议族net_proto_family是以内核模块加载，并动态的注册到
	// net_families中，则对此内核模块的引用计数加1，以防在创建过程中，此内核模块被
	// 动态卸载，而造成严重的后果
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	// 在IPv4协议族中调用inet_create()对已创建的套接口继续进行初始化，同时创建传输控制块
	// IPv4协议族定义为inet_family_ops
	err = pf->create(sock, protocol);
	if (err < 0)
		goto out_module_put;

	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */
	// 如果此类型的proto_ops结构实例以内核模块的方式被加载，并且动态注册到内核中
	// 则增加此内核模块的引用计数，以防止在使用此套接口过程中被意外卸载，直到释放
	// 此套接口为止
	if (!try_module_get(sock->ops->owner))
		goto out_module_busy;

	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	// 完成对IPv4协议族的inet_create()调用后，可以对此模块的引用计数减1
	module_put(pf->owner);
	// 安全模块对套接口的创建做检查
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_release;
	// 至此已经成功创建了套接口和传输控制块，现在只缺少与此套接口对应的文件描述符
	// 套接口的创建的全过程已经过了一大半了
	*res = sock;

	return 0;

out_module_busy:
	err = -EAFNOSUPPORT;
out_module_put:
	sock->ops = NULL;
	module_put(pf->owner);
out_sock_release:
	sock_release(sock);
	return err;

out_release:
	rcu_read_unlock();
	goto out_sock_release;
}

int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(family, type, protocol, res, 0);
}

int sock_create_kern(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(family, type, protocol, res, 1);
}

// sys_socket()把套接口的创建和与此套接口关联的文件描述符的分配做了简单的封装
// 从而完成创建套接口的功能
// family:待创建套接口的协议族，如PF_INET,PF_UNIX等
// type：待创建套接口的类型，如SOCK_STREAM，SOCK_DGRAM，SOCK_RAW等
// protocol:传输层协议，如IPPROTO_TCP,IPPROTO_UDP等
asmlinkage long sys_socket(int family, int type, int protocol)
{
	int retval;
	struct socket *sock;

	// 根据参数给定的协议族、套接口类型、以及传输层协议创建并初始化一个套接口
	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		goto out;

	// 给创建的套接口分配一个文件描述符并绑定
	retval = sock_map_fd(sock);
	if (retval < 0)
		goto out_release;

out:
	/* It may be already another descriptor 8) Not kernel problem. */
	return retval;

out_release:
	sock_release(sock);
	return retval;
}

/*
 *	Create a pair of connected sockets.
 */

asmlinkage long sys_socketpair(int family, int type, int protocol,
			       int __user *usockvec)
{
	struct socket *sock1, *sock2;
	int fd1, fd2, err;

	/*
	 * Obtain the first socket and check if the underlying protocol
	 * supports the socketpair call.
	 */

	err = sock_create(family, type, protocol, &sock1);
	if (err < 0)
		goto out;

	err = sock_create(family, type, protocol, &sock2);
	if (err < 0)
		goto out_release_1;

	err = sock1->ops->socketpair(sock1, sock2);
	if (err < 0)
		goto out_release_both;

	fd1 = fd2 = -1;

	err = sock_map_fd(sock1);
	if (err < 0)
		goto out_release_both;
	fd1 = err;

	err = sock_map_fd(sock2);
	if (err < 0)
		goto out_close_1;
	fd2 = err;

	/* fd1 and fd2 may be already another descriptors.
	 * Not kernel problem.
	 */

	err = put_user(fd1, &usockvec[0]);
	if (!err)
		err = put_user(fd2, &usockvec[1]);
	if (!err)
		return 0;

	sys_close(fd2);
	sys_close(fd1);
	return err;

out_close_1:
	sock_release(sock2);
	sys_close(fd1);
	return err;

out_release_both:
	sock_release(sock2);
out_release_1:
	sock_release(sock1);
out:
	return err;
}

/*
 *	Bind a name to a socket. Nothing much to do here since it's
 *	the protocol's responsibility to handle the local address.
 *
 *	We move the socket address to kernel space before we call
 *	the protocol layer (having also checked the address is ok).
 */
// bind系统调用将一个本地的地址及传输层的端口和套接口关联起来，一般来说，作为客户的进程
// 并不关心它的本地地址和端口是什么，在这种情况下，进程在进行通信之前没有必要调用bind()
// 内核会自动为其选择一个本地地址和端口
// fd:进行绑定的套接口文件描述符
// umyaddr:进行绑定的地址
// addrlen:进行绑定地址的长度，由于不同协议族的地址描述结构是不一样的，因此需要标识地址长度
asmlinkage long sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
	struct socket *sock;
	char address[MAX_SOCK_ADDR];
	int err, fput_needed;

	// 根据文件描述符获取套接口指针，并且返回是否需要减少对文件引用计数的标志
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if(sock) {
		// 将用户空间的地址数据复制到内核空间中
		err = move_addr_to_kernel(umyaddr, addrlen, address);
		if (err >= 0) {
			// 安全模块对套接口bind做检查
			err = security_socket_bind(sock,
						   (struct sockaddr *)address,
						   addrlen);
			if (!err)
				// 通过套接口层接口，调用bind()接口，在IPv4协议族中，所有类型的
				//　套接口的bind接口是统一的，即inet_bind(),它将实现对具体传输层
				// 接口bind的有关调用
				err = sock->ops->bind(sock,
						      (struct sockaddr *)
						      address, addrlen);
		}
		// 需要根据fput_needed标志，调用fput_light减少对文件引用计数操作
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 *	Perform a listen. Basically, we allow the protocol to do anything
 *	necessary for a listen, and if that works, we mark the socket as
 *	ready for listening.
 */

int sysctl_somaxconn __read_mostly = SOMAXCONN;

// listen系统调用用于通知进程准备接收套接口上的连接请求，它同时也指定套接口上可以
// 排队等待的连接数的门限值，超过门限值时，套接口将拒绝新的连接请求，TCP将忽略进入
// 的连接请求
asmlinkage long sys_listen(int fd, int backlog)
{
	struct socket *sock;
	int err, fput_needed;

	// 根据文件描述符获取套接口指针，并且返回是否需要减少对文件引用计数的标志
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		// 对参数门限值做校验，门限值不能超过上限
		if ((unsigned)backlog > sysctl_somaxconn)
			backlog = sysctl_somaxconn;

		// 安全模块对套接口listen做检查
		err = security_socket_listen(sock, backlog);
		if (!err)
			// 通过套接口系统调用的跳转表proto_ops结构，调用对应传输协议中的listen
			// 操作，SOCK_DGRAM和SOCK_RAW类型不支持listen，只有SOCK_STREAM类型
			// 支持listen接口，TCP中为inet_listen()
			err = sock->ops->listen(sock, backlog);

		// 需要根据fput_needed标志，调用fput_light减少对文件引用计数操作
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 *	For accept, we attempt to create a new socket, set up the link
 *	with the client, wake up the client, then return the new
 *	connected fd. We collect the address of the connector in kernel
 *	space and move it to user at the very end. This is unclean because
 *	we open the socket then return an error.
 *
 *	1003.1g adds the ability to recvmsg() to query connection pending
 *	status to recvmsg. We need to add that support in a way thats
 *	clean when we restucture accept also.
 */
// 调用listen()之后，便可以调用accept()等待连接请求。accept()返回一个新的文件描述符
// 指向一个连接到客户的新的套接口，而用于侦听的套接口仍然是未连接的，并准备接收下一个连接
asmlinkage long sys_accept(int fd, struct sockaddr __user *upeer_sockaddr,
			   int __user *upeer_addrlen)
{
	struct socket *sock, *newsock;
	struct file *newfile;
	int err, len, newfd, fput_needed;
	char address[MAX_SOCK_ADDR];

	// 根据文件描述符获取套接口指针，并且返回是否需要减少对文件引用计数的标志
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = -ENFILE;
	// 调用sock_alloc()，分配一个新的套接口，准备用于处理来自客户端的连接
	if (!(newsock = sock_alloc()))
		goto out_put;

	// 初始化套接口的类型和系统调用的操作跳转表
	newsock->type = sock->type;
	newsock->ops = sock->ops;

	/*
	 * We don't need try_module_get here, as the listening socket (sock)
	 * has the protocol module (sock->ops->owner) held.
	 */
	// 如果是内核模块，则增加支持newsock套接口的协议的内核模块的引用计数，防止对模块的卸载
	__module_get(newsock->ops->owner);

	// 给套接口newsock分配文件描述符，并且根套接口绑定
	newfd = sock_alloc_fd(&newfile);
	if (unlikely(newfd < 0)) {
		err = newfd;
		sock_release(newsock);
		goto out_put;
	}

	err = sock_attach_fd(newsock, newfile);
	if (err < 0)
		goto out_fd;

	// 安全模块对套接口accept做检查
	err = security_socket_accept(sock, newsock);
	if (err)
		goto out_fd;

	// 通过套接口系统调用的跳转表proto_ops结构，调用对应传输协议中的
	// accept操作，SOCK_DGRAM和SOCK_RAW类型不支持accept接口，只有
	// SOCK_STREAM类型支持accept接口，TCP中实现的函数为inet_csk_accept()
	err = sock->ops->accept(sock, newsock, sock->file->f_flags);
	if (err < 0)
		goto out_fd;

	// 如果需要获取客户方套接字地址，则调用getname()获取对方地址信息(通过套接口的
	// 跳转表proto_ops结构，调用对应传输协议中的getname())，如果成功则将获取的信息
	// 复制到用户空间
	if (upeer_sockaddr) {
		if (newsock->ops->getname(newsock, (struct sockaddr *)address,
					  &len, 2) < 0) {
			err = -ECONNABORTED;
			goto out_fd;
		}
		err = move_addr_to_user(address, len, upeer_sockaddr,
					upeer_addrlen);
		if (err < 0)
			goto out_fd;
	}

	/* File flags are not inherited via accept() unlike another OSes. */
	// 调用文件系统模块的fd_install()，在当前的进程中，根据文件描述符将文件描述符
	// 结构实例增加到已打开的文件列表中去，完成文件与进程的关联
	fd_install(newfd, newfile);
	err = newfd;
	// 安全模块对套接口accept做检查
	security_socket_post_accept(sock, newsock);

out_put:
	// 需要根据fput_needed标志，调用fput_light减少对文件引用计数操作
	fput_light(sock->file, fput_needed);
out:
	return err;
out_fd:
	fput(newfile);
	put_unused_fd(newfd);
	goto out_put;
}

/*
 *	Attempt to connect to a socket with the server address.  The address
 *	is in user space so we verify it is OK and move it to kernel space.
 *
 *	For 1003.1g we need to add clean support for a bind to AF_UNSPEC to
 *	break bindings
 *
 *	NOTE: 1003.1g draft 6.3 is broken with respect to AX.25/NetROM and
 *	other SEQPACKET protocols that take time to connect() as it doesn't
 *	include the -EINPROGRESS status for such sockets.
 */
// 对于面向连接的协议如TCP，connect()建立一条与指定的外部地址的连接，如果在connect
// 调用之前没有绑定地址和端口，则会自动绑定一个地址和端口到套接口
// 对于无连接协议如UDP或ICMP，connect则记录外部地址，以便发送数据报时使用，任何以前
// 的外部地址均被新的地址所代替
asmlinkage long sys_connect(int fd, struct sockaddr __user *uservaddr,
			    int addrlen)
{
	struct socket *sock;
	char address[MAX_SOCK_ADDR];
	int err, fput_needed;

	// 根据文件描述符获取套接口指针，并且返回是否需要减少对文件引用计数的标志
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;
	// 将用户空间的uservaddr的数据复制到内核空间的address中
	err = move_addr_to_kernel(uservaddr, addrlen, address);
	if (err < 0)
		goto out_put;

	// 安全模块对套接口connect做检查
	err =　security_socket_connect(sock, (struct sockaddr *)address, addrlen);
	if (err)
		goto out_put;
	// 通过套接口系统调用的跳转表proto_ops结构，调用对应传输协议中的connect操作
	// TCP中为inet_stream_connect()，而UDP中为inet_dgram_connect()
	err = sock->ops->connect(sock, (struct sockaddr *)address, addrlen,
				 sock->file->f_flags);
out_put:
	// 需要根据fput_needed标志，调用fput_light减少对文件引用计数操作
	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 *	Get the local address ('name') of a socket object. Move the obtained
 *	name to user space.
 */

asmlinkage long sys_getsockname(int fd, struct sockaddr __user *usockaddr,
				int __user *usockaddr_len)
{
	struct socket *sock;
	char address[MAX_SOCK_ADDR];
	int len, err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = security_socket_getsockname(sock);
	if (err)
		goto out_put;

	err = sock->ops->getname(sock, (struct sockaddr *)address, &len, 0);
	if (err)
		goto out_put;
	err = move_addr_to_user(address, len, usockaddr, usockaddr_len);

out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 *	Get the remote address ('name') of a socket object. Move the obtained
 *	name to user space.
 */

asmlinkage long sys_getpeername(int fd, struct sockaddr __user *usockaddr,
				int __user *usockaddr_len)
{
	struct socket *sock;
	char address[MAX_SOCK_ADDR];
	int len, err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_getpeername(sock);
		if (err) {
			fput_light(sock->file, fput_needed);
			return err;
		}

		err =
		    sock->ops->getname(sock, (struct sockaddr *)address, &len,
				       1);
		if (!err)
			err = move_addr_to_user(address, len, usockaddr,
						usockaddr_len);
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 *	Send a datagram to a given address. We move the address into kernel
 *	space and check the user space data area is readable before invoking
 *	the protocol.
 */

asmlinkage long sys_sendto(int fd, void __user *buff, size_t len,
			   unsigned flags, struct sockaddr __user *addr,
			   int addr_len)
{
	struct socket *sock;
	char address[MAX_SOCK_ADDR];
	int err;
	struct msghdr msg;
	struct iovec iov;
	int fput_needed;
	struct file *sock_file;

	sock_file = fget_light(fd, &fput_needed);
	if (!sock_file)
		return -EBADF;

	sock = sock_from_file(sock_file, &err);
	if (!sock)
		goto out_put;
	iov.iov_base = buff;
	iov.iov_len = len;
	msg.msg_name = NULL;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;
	if (addr) {
		err = move_addr_to_kernel(addr, addr_len, address);
		if (err < 0)
			goto out_put;
		msg.msg_name = address;
		msg.msg_namelen = addr_len;
	}
	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	msg.msg_flags = flags;
	err = sock_sendmsg(sock, &msg, len);

out_put:
	fput_light(sock_file, fput_needed);
	return err;
}

/*
 *	Send a datagram down a socket.
 */

asmlinkage long sys_send(int fd, void __user *buff, size_t len, unsigned flags)
{
	return sys_sendto(fd, buff, len, flags, NULL, 0);
}

/*
 *	Receive a frame from the socket and optionally record the address of the
 *	sender. We verify the buffers are writable and if needed move the
 *	sender address from kernel to user space.
 */

asmlinkage long sys_recvfrom(int fd, void __user *ubuf, size_t size,
			     unsigned flags, struct sockaddr __user *addr,
			     int __user *addr_len)
{
	struct socket *sock;
	struct iovec iov;
	struct msghdr msg;
	char address[MAX_SOCK_ADDR];
	int err, err2;
	struct file *sock_file;
	int fput_needed;

	sock_file = fget_light(fd, &fput_needed);
	if (!sock_file)
		return -EBADF;

	sock = sock_from_file(sock_file, &err);
	if (!sock)
		goto out;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = size;
	iov.iov_base = ubuf;
	msg.msg_name = address;
	msg.msg_namelen = MAX_SOCK_ADDR;
	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = sock_recvmsg(sock, &msg, size, flags);

	if (err >= 0 && addr != NULL) {
		err2 = move_addr_to_user(address, msg.msg_namelen, addr, addr_len);
		if (err2 < 0)
			err = err2;
	}
out:
	fput_light(sock_file, fput_needed);
	return err;
}

/*
 *	Receive a datagram from a socket.
 */

asmlinkage long sys_recv(int fd, void __user *ubuf, size_t size,
			 unsigned flags)
{
	return sys_recvfrom(fd, ubuf, size, flags, NULL, NULL);
}

/*
 *	Set a socket option. Because we don't know the option lengths we have
 *	to pass the user mode parameter for the protocols to sort out.
 */

asmlinkage long sys_setsockopt(int fd, int level, int optname,
			       char __user *optval, int optlen)
{
	int err, fput_needed;
	struct socket *sock;

	if (optlen < 0)
		return -EINVAL;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_setsockopt(sock, level, optname);
		if (err)
			goto out_put;

		if (level == SOL_SOCKET)
			err =
			    sock_setsockopt(sock, level, optname, optval,
					    optlen);
		else
			err =
			    sock->ops->setsockopt(sock, level, optname, optval,
						  optlen);
out_put:
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 *	Get a socket option. Because we don't know the option lengths we have
 *	to pass a user mode parameter for the protocols to sort out.
 */

asmlinkage long sys_getsockopt(int fd, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	int err, fput_needed;
	struct socket *sock;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_getsockopt(sock, level, optname);
		if (err)
			goto out_put;

		if (level == SOL_SOCKET)
			err =
			    sock_getsockopt(sock, level, optname, optval,
					    optlen);
		else
			err =
			    sock->ops->getsockopt(sock, level, optname, optval,
						  optlen);
out_put:
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 *	Shutdown a socket.
 */
// shutdown系统调用关闭连接的读通道、写通道或读写通道，对于读通道，shutdown丢弃
// 所有进程还没有读走的数据以及调用shutdown之后到达的数据，对于写通道，shutdown
// 使用协议作相应的处理，对于TCP，所有剩余的数据将被发送，发送完成后发送FIN，这就是
// TCP的半关闭特点
// 为了删除套接口和释放文件描述符，必须调用close(),可以在没有调用shutdown()的情况下
// 直接调用close()，同所有描述符一样，当进程结束时，内核将调用close()，关闭所有还没有
// 被关闭的套接口
asmlinkage long sys_shutdown(int fd, int how)
{
	int err, fput_needed;
	struct socket *sock;

	// 根据文件描述符获取套接口指针，并且返回是否需要减少对文件引用计数的标志
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		// 安全模块对套接口shutdown做检查
		err = security_socket_shutdown(sock, how);
		if (!err)
			// 通过套接口层接口proto_ops结构，调用shutdown()，IPv4中所有套接口
			// 的shutdown接口是统一的，即inet_shutdown，它将实现对具体传输层接口
			// shutdown的有关调用
			err = sock->ops->shutdown(sock, how);
		// 需要根据fput_needed标志，调用fput_light减少对文件引用计数操作
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/* A couple of helpful macros for getting the address of the 32/64 bit
 * fields which are the same type (int / unsigned) on our platforms.
 */
#define COMPAT_MSG(msg, member)	((MSG_CMSG_COMPAT & flags) ? &msg##_compat->member : &msg->member)
#define COMPAT_NAMELEN(msg)	COMPAT_MSG(msg, msg_namelen)
#define COMPAT_FLAGS(msg)	COMPAT_MSG(msg, msg_flags)

/*
 *	BSD sendmsg interface
 */

asmlinkage long sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	struct compat_msghdr __user *msg_compat =
	    (struct compat_msghdr __user *)msg;
	struct socket *sock;
	char address[MAX_SOCK_ADDR];
	struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;
	unsigned char ctl[sizeof(struct cmsghdr) + 20]
	    __attribute__ ((aligned(sizeof(__kernel_size_t))));
	/* 20 is size of ipv6_pktinfo */
	unsigned char *ctl_buf = ctl;
	struct msghdr msg_sys;
	int err, ctl_len, iov_size, total_len;
	int fput_needed;

	err = -EFAULT;
	if (MSG_CMSG_COMPAT & flags) {
		if (get_compat_msghdr(&msg_sys, msg_compat))
			return -EFAULT;
	}
	else if (copy_from_user(&msg_sys, msg, sizeof(struct msghdr)))
		return -EFAULT;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	/* do not move before msg_sys is valid */
	err = -EMSGSIZE;
	if (msg_sys.msg_iovlen > UIO_MAXIOV)
		goto out_put;

	/* Check whether to allocate the iovec area */
	err = -ENOMEM;
	iov_size = msg_sys.msg_iovlen * sizeof(struct iovec);
	if (msg_sys.msg_iovlen > UIO_FASTIOV) {
		iov = sock_kmalloc(sock->sk, iov_size, GFP_KERNEL);
		if (!iov)
			goto out_put;
	}

	/* This will also move the address data into kernel space */
	if (MSG_CMSG_COMPAT & flags) {
		err = verify_compat_iovec(&msg_sys, iov, address, VERIFY_READ);
	} else
		err = verify_iovec(&msg_sys, iov, address, VERIFY_READ);
	if (err < 0)
		goto out_freeiov;
	total_len = err;

	err = -ENOBUFS;

	if (msg_sys.msg_controllen > INT_MAX)
		goto out_freeiov;
	ctl_len = msg_sys.msg_controllen;
	if ((MSG_CMSG_COMPAT & flags) && ctl_len) {
		err =
		    cmsghdr_from_user_compat_to_kern(&msg_sys, sock->sk, ctl,
						     sizeof(ctl));
		if (err)
			goto out_freeiov;
		ctl_buf = msg_sys.msg_control;
		ctl_len = msg_sys.msg_controllen;
	} else if (ctl_len) {
		if (ctl_len > sizeof(ctl)) {
			ctl_buf = sock_kmalloc(sock->sk, ctl_len, GFP_KERNEL);
			if (ctl_buf == NULL)
				goto out_freeiov;
		}
		err = -EFAULT;
		/*
		 * Careful! Before this, msg_sys.msg_control contains a user pointer.
		 * Afterwards, it will be a kernel pointer. Thus the compiler-assisted
		 * checking falls down on this.
		 */
		if (copy_from_user(ctl_buf, (void __user *)msg_sys.msg_control,
				   ctl_len))
			goto out_freectl;
		msg_sys.msg_control = ctl_buf;
	}
	msg_sys.msg_flags = flags;

	if (sock->file->f_flags & O_NONBLOCK)
		msg_sys.msg_flags |= MSG_DONTWAIT;
	err = sock_sendmsg(sock, &msg_sys, total_len);

out_freectl:
	if (ctl_buf != ctl)
		sock_kfree_s(sock->sk, ctl_buf, ctl_len);
out_freeiov:
	if (iov != iovstack)
		sock_kfree_s(sock->sk, iov, iov_size);
out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 *	BSD recvmsg interface
 */

asmlinkage long sys_recvmsg(int fd, struct msghdr __user *msg,
			    unsigned int flags)
{
	struct compat_msghdr __user *msg_compat =
	    (struct compat_msghdr __user *)msg;
	struct socket *sock;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct msghdr msg_sys;
	unsigned long cmsg_ptr;
	int err, iov_size, total_len, len;
	int fput_needed;

	/* kernel mode address */
	char addr[MAX_SOCK_ADDR];

	/* user mode address pointers */
	struct sockaddr __user *uaddr;
	int __user *uaddr_len;

	if (MSG_CMSG_COMPAT & flags) {
		if (get_compat_msghdr(&msg_sys, msg_compat))
			return -EFAULT;
	}
	else if (copy_from_user(&msg_sys, msg, sizeof(struct msghdr)))
		return -EFAULT;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = -EMSGSIZE;
	if (msg_sys.msg_iovlen > UIO_MAXIOV)
		goto out_put;

	/* Check whether to allocate the iovec area */
	err = -ENOMEM;
	iov_size = msg_sys.msg_iovlen * sizeof(struct iovec);
	if (msg_sys.msg_iovlen > UIO_FASTIOV) {
		iov = sock_kmalloc(sock->sk, iov_size, GFP_KERNEL);
		if (!iov)
			goto out_put;
	}

	/*
	 *      Save the user-mode address (verify_iovec will change the
	 *      kernel msghdr to use the kernel address space)
	 */

	uaddr = (void __user *)msg_sys.msg_name;
	uaddr_len = COMPAT_NAMELEN(msg);
	if (MSG_CMSG_COMPAT & flags) {
		err = verify_compat_iovec(&msg_sys, iov, addr, VERIFY_WRITE);
	} else
		err = verify_iovec(&msg_sys, iov, addr, VERIFY_WRITE);
	if (err < 0)
		goto out_freeiov;
	total_len = err;

	cmsg_ptr = (unsigned long)msg_sys.msg_control;
	msg_sys.msg_flags = 0;
	if (MSG_CMSG_COMPAT & flags)
		msg_sys.msg_flags = MSG_CMSG_COMPAT;

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = sock_recvmsg(sock, &msg_sys, total_len, flags);
	if (err < 0)
		goto out_freeiov;
	len = err;

	if (uaddr != NULL) {
		err = move_addr_to_user(addr, msg_sys.msg_namelen, uaddr,
					uaddr_len);
		if (err < 0)
			goto out_freeiov;
	}
	err = __put_user((msg_sys.msg_flags & ~MSG_CMSG_COMPAT),
			 COMPAT_FLAGS(msg));
	if (err)
		goto out_freeiov;
	if (MSG_CMSG_COMPAT & flags)
		err = __put_user((unsigned long)msg_sys.msg_control - cmsg_ptr,
				 &msg_compat->msg_controllen);
	else
		err = __put_user((unsigned long)msg_sys.msg_control - cmsg_ptr,
				 &msg->msg_controllen);
	if (err)
		goto out_freeiov;
	err = len;

out_freeiov:
	if (iov != iovstack)
		sock_kfree_s(sock->sk, iov, iov_size);
out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}

#ifdef __ARCH_WANT_SYS_SOCKETCALL

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[18]={
	AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
	AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
	AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)
};

#undef AL

/*
 *	System call vectors.
 *
 *	Argument checking cleaned up. Saved 20% in size.
 *  This function doesn't need to set the kernel lock because
 *  it is set by the callees.
 */

asmlinkage long sys_socketcall(int call, unsigned long __user *args)
{
	unsigned long a[6];
	unsigned long a0, a1;
	int err;

	if (call < 1 || call > SYS_RECVMSG)
		return -EINVAL;

	/* copy_from_user should be SMP safe. */
	if (copy_from_user(a, args, nargs[call]))
		return -EFAULT;

	err = audit_socketcall(nargs[call] / sizeof(unsigned long), a);
	if (err)
		return err;

	a0 = a[0];
	a1 = a[1];

	switch (call) {
	// 创建一个套接口，套接口创建成功以后返回一个打开的文件描述符，这个打开的文件描述符
	// 与一个套接口关联，而不是与磁盘上的某个文件关联
	case SYS_SOCKET:
		err = sys_socket(a0, a1, a[2]);
		break;
	// 当用socket调用创建一个套接字后，存在一个名字空间（地址族），但它没有被命名
	// bind()将套接口地址（包括本地主机地址和本地端口地址）与所创建的套接字号绑定起来
	case SYS_BIND:
		err = sys_bind(a0, (struct sockaddr __user *)a1, a[2]);
		break;
	// 建立连接，对于无连接的套接口也可以调用connect()，这样就不必为每个数据指定目的地址了
	case SYS_CONNECT:
		err = sys_connect(a0, (struct sockaddr __user *)a1, a[2]);
		break;
	// 用于面向连接服务器，表示开始侦听，可以接收连接，在listen()调用中backlog参数表示
	// 请求连接队列的最大长度，用于限制排队请求的个数
	case SYS_LISTEN:
		err = sys_listen(a0, a1);
		break;
	// 用于面向连接服务器，接受新的连接，当建立新的连接之后，调用accept()会返回新连接的
	// 文件描述符
	case SYS_ACCEPT:
		err =
		    sys_accept(a0, (struct sockaddr __user *)a1,
			       (int __user *)a[2]);
		break;
	case SYS_GETSOCKNAME:
		err =
		    sys_getsockname(a0, (struct sockaddr __user *)a1,
				    (int __user *)a[2]);
		break;
	case SYS_GETPEERNAME:
		err =
		    sys_getpeername(a0, (struct sockaddr __user *)a1,
				    (int __user *)a[2]);
		break;
	case SYS_SOCKETPAIR:
		err = sys_socketpair(a0, a1, a[2], (int __user *)a[3]);
		break;
	case SYS_SEND:
		err = sys_send(a0, (void __user *)a1, a[2], a[3]);
		break;
	case SYS_SENDTO:
		err = sys_sendto(a0, (void __user *)a1, a[2], a[3],
				 (struct sockaddr __user *)a[4], a[5]);
		break;
	case SYS_RECV:
		err = sys_recv(a0, (void __user *)a1, a[2], a[3]);
		break;
	case SYS_RECVFROM:
		err = sys_recvfrom(a0, (void __user *)a1, a[2], a[3],
				   (struct sockaddr __user *)a[4],
				   (int __user *)a[5]);
		break;
	case SYS_SHUTDOWN:
		err = sys_shutdown(a0, a1);
		break;
	case SYS_SETSOCKOPT:
		err = sys_setsockopt(a0, a1, a[2], (char __user *)a[3], a[4]);
		break;
	case SYS_GETSOCKOPT:
		err =
		    sys_getsockopt(a0, a1, a[2], (char __user *)a[3],
				   (int __user *)a[4]);
		break;
	case SYS_SENDMSG:
		err = sys_sendmsg(a0, (struct msghdr __user *)a1, a[2]);
		break;
	case SYS_RECVMSG:
		err = sys_recvmsg(a0, (struct msghdr __user *)a1, a[2]);
		break;
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

#endif				/* __ARCH_WANT_SYS_SOCKETCALL */

/**
 *	sock_register - add a socket protocol handler
 *	@ops: description of protocol
 *
 *	This function is called by a protocol handler that wants to
 *	advertise its address family, and have it linked into the
 *	socket interface. The value ops->family coresponds to the
 *	socket system call protocol family.
 */
int sock_register(const struct net_proto_family *ops)
{
	int err;

	if (ops->family >= NPROTO) {
		printk(KERN_CRIT "protocol %d >= NPROTO(%d)\n", ops->family,
		       NPROTO);
		return -ENOBUFS;
	}

	spin_lock(&net_family_lock);
	if (net_families[ops->family])
		err = -EEXIST;
	else {
		net_families[ops->family] = ops;
		err = 0;
	}
	spin_unlock(&net_family_lock);

	printk(KERN_INFO "NET: Registered protocol family %d\n", ops->family);
	return err;
}

/**
 *	sock_unregister - remove a protocol handler
 *	@family: protocol family to remove
 *
 *	This function is called by a protocol handler that wants to
 *	remove its address family, and have it unlinked from the
 *	new socket creation.
 *
 *	If protocol handler is a module, then it can use module reference
 *	counts to protect against new references. If protocol handler is not
 *	a module then it needs to provide its own protection in
 *	the ops->create routine.
 */
void sock_unregister(int family)
{
	BUG_ON(family < 0 || family >= NPROTO);

	spin_lock(&net_family_lock);
	net_families[family] = NULL;
	spin_unlock(&net_family_lock);

	synchronize_rcu();

	printk(KERN_INFO "NET: Unregistered protocol family %d\n", family);
}

// sock_init()在系统启动时在初始化列表中被调用，通过core_initcall宏加入到内核的初始化列表中
static int __init sock_init(void)
{
	/*
	 *      Initialize sock SLAB cache.
	 */
	// 初始化套接口层的SLAB缓存的初始参数
	sk_init();

	/*
	 *      Initialize skbuff SLAB cache
	 */
	// 创建分配SKB的SLAB缓存skbuff_head_cache和skbuff_fclone_cache
	skb_init();

	/*
	 *      Initialize the protocols module.
	 */

	// 创建套接口层的i节点SLAB缓存，名称为sock_inode_cache
	init_inodecache();
	// 注册套接口文件系统，并把套接口文件系统挂载到文件系统列表上
	register_filesystem(&sock_fs_type);
	sock_mnt = kern_mount(&sock_fs_type);

	/* The real protocol initialization is performed in later initcalls.
	 */

#ifdef CONFIG_NETFILTER
	netfilter_init();
#endif

	return 0;
}

core_initcall(sock_init);	/* early initcall */

#ifdef CONFIG_PROC_FS
void socket_seq_show(struct seq_file *seq)
{
	int cpu;
	int counter = 0;

	for_each_possible_cpu(cpu)
	    counter += per_cpu(sockets_in_use, cpu);

	/* It can be negative, by the way. 8) */
	if (counter < 0)
		counter = 0;

	seq_printf(seq, "sockets: used %d\n", counter);
}
#endif				/* CONFIG_PROC_FS */

#ifdef CONFIG_COMPAT
static long compat_sock_ioctl(struct file *file, unsigned cmd,
			      unsigned long arg)
{
	struct socket *sock = file->private_data;
	int ret = -ENOIOCTLCMD;

	if (sock->ops->compat_ioctl)
		ret = sock->ops->compat_ioctl(sock, cmd, arg);

	return ret;
}
#endif

int kernel_bind(struct socket *sock, struct sockaddr *addr, int addrlen)
{
	return sock->ops->bind(sock, addr, addrlen);
}

int kernel_listen(struct socket *sock, int backlog)
{
	return sock->ops->listen(sock, backlog);
}

int kernel_accept(struct socket *sock, struct socket **newsock, int flags)
{
	struct sock *sk = sock->sk;
	int err;

	err = sock_create_lite(sk->sk_family, sk->sk_type, sk->sk_protocol,
			       newsock);
	if (err < 0)
		goto done;

	err = sock->ops->accept(sock, *newsock, flags);
	if (err < 0) {
		sock_release(*newsock);
		goto done;
	}

	(*newsock)->ops = sock->ops;

done:
	return err;
}

int kernel_connect(struct socket *sock, struct sockaddr *addr, int addrlen,
                   int flags)
{
	return sock->ops->connect(sock, addr, addrlen, flags);
}

int kernel_getsockname(struct socket *sock, struct sockaddr *addr,
			 int *addrlen)
{
	return sock->ops->getname(sock, addr, addrlen, 0);
}

int kernel_getpeername(struct socket *sock, struct sockaddr *addr,
			 int *addrlen)
{
	return sock->ops->getname(sock, addr, addrlen, 1);
}

int kernel_getsockopt(struct socket *sock, int level, int optname,
			char *optval, int *optlen)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	if (level == SOL_SOCKET)
		err = sock_getsockopt(sock, level, optname, optval, optlen);
	else
		err = sock->ops->getsockopt(sock, level, optname, optval,
					    optlen);
	set_fs(oldfs);
	return err;
}

int kernel_setsockopt(struct socket *sock, int level, int optname,
			char *optval, int optlen)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	if (level == SOL_SOCKET)
		err = sock_setsockopt(sock, level, optname, optval, optlen);
	else
		err = sock->ops->setsockopt(sock, level, optname, optval,
					    optlen);
	set_fs(oldfs);
	return err;
}

int kernel_sendpage(struct socket *sock, struct page *page, int offset,
		    size_t size, int flags)
{
	if (sock->ops->sendpage)
		return sock->ops->sendpage(sock, page, offset, size, flags);

	return sock_no_sendpage(sock, page, offset, size, flags);
}

int kernel_sock_ioctl(struct socket *sock, int cmd, unsigned long arg)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	err = sock->ops->ioctl(sock, cmd, arg);
	set_fs(oldfs);

	return err;
}

/* ABI emulation layers need these two */
EXPORT_SYMBOL(move_addr_to_kernel);
EXPORT_SYMBOL(move_addr_to_user);
EXPORT_SYMBOL(sock_create);
EXPORT_SYMBOL(sock_create_kern);
EXPORT_SYMBOL(sock_create_lite);
EXPORT_SYMBOL(sock_map_fd);
EXPORT_SYMBOL(sock_recvmsg);
EXPORT_SYMBOL(sock_register);
EXPORT_SYMBOL(sock_release);
EXPORT_SYMBOL(sock_sendmsg);
EXPORT_SYMBOL(sock_unregister);
EXPORT_SYMBOL(sock_wake_async);
EXPORT_SYMBOL(sockfd_lookup);
EXPORT_SYMBOL(kernel_sendmsg);
EXPORT_SYMBOL(kernel_recvmsg);
EXPORT_SYMBOL(kernel_bind);
EXPORT_SYMBOL(kernel_listen);
EXPORT_SYMBOL(kernel_accept);
EXPORT_SYMBOL(kernel_connect);
EXPORT_SYMBOL(kernel_getsockname);
EXPORT_SYMBOL(kernel_getpeername);
EXPORT_SYMBOL(kernel_getsockopt);
EXPORT_SYMBOL(kernel_setsockopt);
EXPORT_SYMBOL(kernel_sendpage);
EXPORT_SYMBOL(kernel_sock_ioctl);
