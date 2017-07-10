/* af_trace.c */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <net/sock.h>

/*
 * a socket tracing a socket.
 * XXX:
 * - copy state of pyhsical socket to virtual socket.
 * - how to pretend socket stauts/address on virtual.
 * - how to specify bind address
 */


#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define AF_TRACE_VERSION	"0.0.0"


#define AF_TRACE	AF_IPX	/* Override AF_IPX! (maybe) it's never used */
#define PF_TRACE	AF_TRACE


/* socket structure for a socket traceing an underlay socket */
struct trace_sock {
	struct sock sk;

	struct socket *vsock;	/* virtual socket (this socket )*/
	struct socket *psock;	/* physical socket */
};


static inline struct trace_sock *trace_sk(const struct sock *sk)
{
	return (struct trace_sock *)sk;
}

static inline struct socket *trace_psock(struct trace_sock *tsk)
{
	return tsk->psock;
}



static int trace_release(struct socket *sock)
{
	/* release physical and virtual sockets */

	struct sock *sk = sock->sk;
	struct trace_sock *tsk;	

	if (!sk)
		return 0;

	/* XXX: release both sockets correctly */
	tsk = trace_sk(sk);
	//tsk->psock->ops->release(tsk->vsock);
	tsk->psock->ops->release(tsk->psock);
	
	sock->sk = NULL;

	return 0;
}

static int trace_bind(struct socket *sock,
		      struct sockaddr *uaddr, int addr_len)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->bind(psock, uaddr, addr_len);
}

static int trace_connect(struct socket *sock, struct sockaddr *vaddr,
			 int sockaddr_len, int flags)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->connect(psock, vaddr, sockaddr_len, flags);
}


static int trace_socketpair(struct socket *sock1, struct socket *sock2)
{
	struct socket *vsock, *psock, *pair;

	if (sock1->sk->sk_family == AF_TRACE) {
		vsock = sock1;
		pair = sock2;
	} else if (sock2->sk->sk_family == AF_TRACE) {
		vsock = sock2;
		pair = sock1;
	} else {
		pr_crit("%s: both socekts are not AF_TRACE sockets\n",
			__func__);
		return -EINVAL;
	}

	psock = trace_psock(trace_sk(vsock->sk));

	return psock->ops->socketpair(psock, pair);
}

static int trace_accept(struct socket *sock, struct socket *newsock,
			int flags)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->accept(psock, newsock, flags);
}

static int trace_getname(struct socket *sock, struct sockaddr *addr,
			 int *sockaddr_len, int peer)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->getname(psock, addr, sockaddr_len, peer);
}

static unsigned int trace_poll(struct file *file, struct socket *sock,
			       struct poll_table_struct *wait)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->poll(file, psock, wait);
}

static int trace_ioctl(struct socket *sock, unsigned int cmd,
		       unsigned long arg)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->ioctl(psock, cmd, arg);
}

static int trace_listen(struct socket *sock, int len)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->listen(psock, len);
}

static int trace_shutdown(struct socket *sock, int flags)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->shutdown(psock, flags);
}

static int trace_setsockopt(struct socket *sock, int level,
			    int optname, char __user *optval,
			    unsigned int optlen)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->setsockopt(psock, level, optname, optval, optlen);
}

static int trace_getsockopt(struct socket *sock, int level,
			    int optname, char __user *optval,
			    int __user *optlen)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->getsockopt(psock, level, optname, optval, optlen);
}

static int trace_sendmsg(struct socket *sock,
			 struct msghdr *m, size_t total_len)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->sendmsg(psock, m, total_len);
}

static int trace_recvmsg(struct socket *sock,
			 struct msghdr *m, size_t total_len, int flags)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->recvmsg(psock, m, total_len, flags);
}

static ssize_t trace_sendpage(struct socket *sock, struct page *page,
			     int offset, size_t size, int flags)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->sendpage(psock, page, offset, size, flags);
}

static ssize_t trace_splice_read(struct socket *sock, loff_t *ppos,
				 struct pipe_inode_info *pipe,
				 size_t len, unsigned int flags)
{
	struct socket *psock = trace_psock(trace_sk(sock->sk));
	return psock->ops->splice_read(psock, ppos, pipe, len, flags);
}

static int trace_set_peek_off(struct sock *sk, int val)
{
	struct socket *psock = trace_psock(trace_sk(sk));
	return psock->ops->set_peek_off(psock->sk, val);
}

static const struct proto_ops trace_proto_ops = {
	.family		= PF_TRACE,
	.owner		= THIS_MODULE,
	.release	= trace_release,
	.bind		= trace_bind,
	.connect	= trace_connect,
	.socketpair	= trace_socketpair,
	.accept		= trace_accept,
	.getname	= trace_getname,
	.poll		= trace_poll,
	.ioctl		= trace_ioctl,
	.listen		= trace_listen,
	.shutdown	= trace_shutdown,
	.setsockopt	= trace_setsockopt,
	.getsockopt	= trace_getsockopt,
	.sendmsg	= trace_sendmsg,
	.recvmsg	= trace_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= trace_sendpage,
	.splice_read	= trace_splice_read,
	.set_peek_off	= trace_set_peek_off,
};

static struct proto trace_proto = {
	.name		= "TRACE",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct trace_sock),
};


static int trace_create(struct net *net, struct socket *sock,
			int protocol, int kern)
{
	int rc;
	struct sock *sk;
	struct trace_sock *tsk;

	pr_info("%s\n", __func__);

	sock->ops = &trace_proto_ops;

	sk = sk_alloc(net, PF_TRACE, GFP_KERNEL, &trace_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	/* create socket at default netns and store both virtual and
	 * physical sockets
	 */
	tsk = trace_sk(sk);
	tsk->vsock = sock;
	rc = __sock_create(get_net(&init_net),
			   AF_INET, sk->sk_type, sk->sk_protocol,
			   &tsk->psock, kern);

	if (rc < 0) {
		pr_crit("%s: failed to create a socket at default netns\n",
			__func__);
		sk_free(sk);
		return rc;
	}

	return 0;
}

static struct net_proto_family trace_family_ops = {
	.family		= PF_TRACE,
	.create		= trace_create,
	.owner		= THIS_MODULE,
};


static int __init af_trace_init(void)
{
	int rc;

	rc = proto_register(&trace_proto, 1);
	if (rc != 0) {
		pr_err("%s: proto_register failed '%d'\n", __func__, rc);
		goto proto_register_failed;
	}

	rc = sock_register(&trace_family_ops);
	if (rc != 0) {
		pr_err("%s: sock_register failed '%d'\n", __func__, rc);
		goto sock_register_failed;
	}

	pr_info("%s (%s) is loaded\n", KBUILD_MODNAME, AF_TRACE_VERSION);

	return rc;

sock_register_failed:
	proto_unregister(&trace_proto);
proto_register_failed:
	return rc;
}

static void __exit af_trace_exit(void)
{
	sock_unregister(PF_TRACE);
	proto_unregister(&trace_proto);
	pr_info("%s (%s) is unloaded\n", KBUILD_MODNAME, AF_TRACE_VERSION);
}

module_init(af_trace_init);
module_exit(af_trace_exit);

MODULE_VERSION(AF_TRACE_VERSION);
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_TRACE);
