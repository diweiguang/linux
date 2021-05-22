/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <net/ip_fib.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>
#include <linux/security.h>

/* IPv4 datagram length is stored into 16bit field (tot_len) */
#define IP_MAX_MTU	0xFFFFU

#define RTO_ONLINK	0x01

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))
#define RT_CONN_FLAGS_TOS(sk,tos)   (RT_TOS(tos) | sock_flag(sk, SOCK_LOCALROUTE))

struct fib_nh;
struct fib_info;
struct uncached_list;
/*

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	IPv4使用rtable结构来存储缓存内的路由表项。nJ以通过査看/proc/net/rt_cache文件，或 者通过ip route list cache和route -C命令来列出路由缓存的内容
	
dst_entry结构作为一部分嵌入到rtable结构中，而dst_entry结构中的第一个成员next就 是用于链接分布在同一个散列桶内的rtable实例，为了便于访问next,因此将dst和rt_next联 合起来。虽然指针的名称不同，但它们所指向的内存位置是相同的。
59 struct in_device *idev
指向输出网络设备的IPv4协议族中的IP配置块。注意：对送往本地的输入报文的路由， 输出网络设备设置为回环设备。
61 unsigned rt_flags
用于标识路由表项的一些特性和标志，见表20-U
表20-1路由表项的标志
rt.flags	描述
RTCF_NOTIFY	路由表项的所有变化通过netlink通知给感兴趣的用户空间应用程序，该选項还没仃完全实现。利 用诸如ip route等命令来设置该标志
RTCF_REDIRECTED	由接收到的ICMP.RED1REC1消息作出响应而添加 条路由缓存项，参见20.10节
RTCF_DORED1RECT	表示并不是股优路山.ip_forward()依据该标志和其他信,R・决定是杏需要发送ICMP雨定向消息。 例如，如果报文是基于源泌而路由，就不应当生成1CMP ＜定向消息
RTCF_DIRECTSRC	不正确的源地址。ICMP模块不会对来闩此源地址的地址掩码诵求消息作出冋应•每当调用 fib_validate_source()检査到接收报文的源地址通过-个木地作用范围(RT„SCOPE_HOST)的下 跳 是可达时，就设置该标志
RTCF_SNAT RTCF_DNAT RTCFNAT	已废除
RTCF_BROADCAST	路由的目的地址是•个广播地址
RTCF_MULT】CAST	路山的日的地址是•个多播地址
RTCF_LOCAL	路山的目的地址是•个本地地址(即本地接口上配置的某个地址)。对本地广播地址和本地多播地 址也设置该标志，参见 ip_route_input_slow()和 ip routc_input_mc()
RTCF_ REJECT	未被使用。依据IPROUTE2软件包的ip rule命令的语法，在该命令中冇 个关鍵?• reject,但该美 键字还未被接受
RTCF TPROXY	未使用
RICF_DIRECTDST	未使用
RTCF_FAST	已废除
RTCF_MASQ	IPv4已不使用
62 _ul6 rt_type
路由表项的类型，见表20-2。它间接定义了当路由查找匹配时应采取的动作。
	表20-2路由类型
rt.type	描述
RIN _ UNSPEC	定义-个未初始化的值.例如.当从路由表中删除•个衣项时使用该債，这是因为删除操作不需 要指定路由表项的类型

（续）
rt.type	描述
RTN_LOCAL	日的地址被fie置为•个本地接口的地址
RTN _UNICAST	该路山是•条到単播地址的直连或1F直连（通过 个网关）¥备山。当用户通过ip route命令添加捋 由伊没有指定其他路由类型时，路山类型欧认设置为RTN_UNICAST
RTN_MULTICAST	目的地址是-个参播地址
RTN_BROADCAST	日的地址是•个广播地城。匹配的ingress报文以广播方式送往本地，匹配的egress报文以广播方 式发送出去
RTN_ANYCAST	匹配的输入报文以广播方式送往本地，匹配的输出报文以甲播发送出去。IPv4没冇该类型
RTN_BLACKHOLE RTN_UNREACHABLE R1T4_PROH1B1T RTN_THROW	这些值与特定的管理配乾而不是与日的地址类型相关联
RTN_NAT	巳废弃
RTNXRESOLVE	有个外部解析器来处理该路由，目前尚未实现该功能

63  	ul6 rt_multipath_alg
添识多路话缓存算法，元创建路由表项时根据相关路由项的配置来设置。
65	 	be32 rt_dst
66	 	be32 rt_src
目的IP地址和源IP地址。
67	int rt_iif
输入网如设备标识，从输入网络设备的net_device数据结构中得到。对本地生成的流量 （因此不是从任何接口上接收到的），该字段被设置为出设备的ifindex字段。对本地生成的报 文，fl中的iif字段被设置为0。
70  	be32 rt_gateway
当目的主机为直连时，即在同一链路匕 gateway表示目的地址。当需要通过一个网关 到达目的地时，rt^gateway被设置为路由项中的下一跳的网关。
73 struct flowi fl
用于缓存査找的搜索的条件组合，参见20.2.2节。
76	 	be32 rt_spec_dst
首选源地址。
添加到路由缓存内的路由缓存项是单向的。但是在一些情况下，接收到报文可能触发一个 动作，要求本地主机选择一个源IP地址，以便在向发送方回送报文时使用。这个地址，即首
 	
选源IP地址，必须与路由该输入报文的路由缓存项保存在一起。首选源1P地址被保存在  	
rt_spec_dst字段内，下面是使用该地址的两种情况：
1）	当一个主机接收到一个ICMP回显请求消息时（常用的ping命令），如果主机没有明 确配置为不作出回应，则该主机返回一个1CMP回显应答消息。对该输入ICMP回显请求消息 选择路由，路由项的rt_spec_dst被用作路由ICMP回显请求消息而进行路由査找的源地址。参 见 14.6.2 节的 icmp replyO和 11.11.2 节的 ip_send_reply（）o
2）	记录路由IP选项和时间戳IP选项要求途经主机的IP地址记录到选项中。
77	struct inet_peer *peer
指向与目的地址相关的对端信息块。 
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
*/
struct rtable {
	struct dst_entry	dst;

	int			rt_genid;
	unsigned int		rt_flags;
	__u16			rt_type;
	__u8			rt_is_input;
	__u8			rt_uses_gateway;

	int			rt_iif;

	u8			rt_gw_family;
	/* Info on neighbour */
	union {
		__be32		rt_gw4;
		struct in6_addr	rt_gw6;
	};

	/* Miscellaneous cached information */
	u32			rt_mtu_locked:1,
				rt_pmtu:31;

	struct list_head	rt_uncached;
	struct uncached_list	*rt_uncached_list;
};

static inline bool rt_is_input_route(const struct rtable *rt)
{
	return rt->rt_is_input != 0;
}

static inline bool rt_is_output_route(const struct rtable *rt)
{
	return rt->rt_is_input == 0;
}

static inline __be32 rt_nexthop(const struct rtable *rt, __be32 daddr)
{
	if (rt->rt_gw_family == AF_INET)
		return rt->rt_gw4;
	return daddr;
}

struct ip_rt_acct {
	__u32 	o_bytes;
	__u32 	o_packets;
	__u32 	i_bytes;
	__u32 	i_packets;
};

struct rt_cache_stat {
        unsigned int in_slow_tot;
        unsigned int in_slow_mc;
        unsigned int in_no_route;
        unsigned int in_brd;
        unsigned int in_martian_dst;
        unsigned int in_martian_src;
        unsigned int out_slow_tot;
        unsigned int out_slow_mc;
};

extern struct ip_rt_acct __percpu *ip_rt_acct;

struct in_device;

int ip_rt_init(void);
void rt_cache_flush(struct net *net);
void rt_flush_dev(struct net_device *dev);
struct rtable *ip_route_output_key_hash(struct net *net, struct flowi4 *flp,
					const struct sk_buff *skb);
struct rtable *ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *flp,
					    struct fib_result *res,
					    const struct sk_buff *skb);

static inline struct rtable *__ip_route_output_key(struct net *net,
						   struct flowi4 *flp)
{
	return ip_route_output_key_hash(net, flp, NULL);
}

struct rtable *ip_route_output_flow(struct net *, struct flowi4 *flp,
				    const struct sock *sk);
struct rtable *ip_route_output_tunnel(struct sk_buff *skb,
				      struct net_device *dev,
				      struct net *net, __be32 *saddr,
				      const struct ip_tunnel_info *info,
				      u8 protocol, bool use_cache);

struct dst_entry *ipv4_blackhole_route(struct net *net,
				       struct dst_entry *dst_orig);

static inline struct rtable *ip_route_output_key(struct net *net, struct flowi4 *flp)
{
	return ip_route_output_flow(net, flp, NULL);
}

static inline struct rtable *ip_route_output(struct net *net, __be32 daddr,
					     __be32 saddr, u8 tos, int oif)
{
	struct flowi4 fl4 = {
		.flowi4_oif = oif,
		.flowi4_tos = tos,
		.daddr = daddr,
		.saddr = saddr,
	};
	return ip_route_output_key(net, &fl4);
}

static inline struct rtable *ip_route_output_ports(struct net *net, struct flowi4 *fl4,
						   struct sock *sk,
						   __be32 daddr, __be32 saddr,
						   __be16 dport, __be16 sport,
						   __u8 proto, __u8 tos, int oif)
{
	flowi4_init_output(fl4, oif, sk ? sk->sk_mark : 0, tos,
			   RT_SCOPE_UNIVERSE, proto,
			   sk ? inet_sk_flowi_flags(sk) : 0,
			   daddr, saddr, dport, sport, sock_net_uid(net, sk));
	if (sk)
		security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
	return ip_route_output_flow(net, fl4, sk);
}

static inline struct rtable *ip_route_output_gre(struct net *net, struct flowi4 *fl4,
						 __be32 daddr, __be32 saddr,
						 __be32 gre_key, __u8 tos, int oif)
{
	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = oif;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->flowi4_tos = tos;
	fl4->flowi4_proto = IPPROTO_GRE;
	fl4->fl4_gre_key = gre_key;
	return ip_route_output_key(net, fl4);
}
int ip_mc_validate_source(struct sk_buff *skb, __be32 daddr, __be32 saddr,
			  u8 tos, struct net_device *dev,
			  struct in_device *in_dev, u32 *itag);
int ip_route_input_noref(struct sk_buff *skb, __be32 dst, __be32 src,
			 u8 tos, struct net_device *devin);
int ip_route_input_rcu(struct sk_buff *skb, __be32 dst, __be32 src,
		       u8 tos, struct net_device *devin,
		       struct fib_result *res);

int ip_route_use_hint(struct sk_buff *skb, __be32 dst, __be32 src,
		      u8 tos, struct net_device *devin,
		      const struct sk_buff *hint);

static inline int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
				 u8 tos, struct net_device *devin)
{
	int err;

	rcu_read_lock();
	err = ip_route_input_noref(skb, dst, src, tos, devin);
	if (!err) {
		skb_dst_force(skb);
		if (!skb_dst(skb))
			err = -EINVAL;
	}
	rcu_read_unlock();

	return err;
}

void ipv4_update_pmtu(struct sk_buff *skb, struct net *net, u32 mtu, int oif,
		      u8 protocol);
void ipv4_sk_update_pmtu(struct sk_buff *skb, struct sock *sk, u32 mtu);
void ipv4_redirect(struct sk_buff *skb, struct net *net, int oif, u8 protocol);
void ipv4_sk_redirect(struct sk_buff *skb, struct sock *sk);
void ip_rt_send_redirect(struct sk_buff *skb);

unsigned int inet_addr_type(struct net *net, __be32 addr);
unsigned int inet_addr_type_table(struct net *net, __be32 addr, u32 tb_id);
unsigned int inet_dev_addr_type(struct net *net, const struct net_device *dev,
				__be32 addr);
unsigned int inet_addr_type_dev_table(struct net *net,
				      const struct net_device *dev,
				      __be32 addr);
void ip_rt_multicast_event(struct in_device *);
int ip_rt_ioctl(struct net *, unsigned int cmd, struct rtentry *rt);
void ip_rt_get_source(u8 *src, struct sk_buff *skb, struct rtable *rt);
struct rtable *rt_dst_alloc(struct net_device *dev,
			     unsigned int flags, u16 type,
			     bool nopolicy, bool noxfrm);
struct rtable *rt_dst_clone(struct net_device *dev, struct rtable *rt);

struct in_ifaddr;
void fib_add_ifaddr(struct in_ifaddr *);
void fib_del_ifaddr(struct in_ifaddr *, struct in_ifaddr *);
void fib_modify_prefix_metric(struct in_ifaddr *ifa, u32 new_metric);

void rt_add_uncached_list(struct rtable *rt);
void rt_del_uncached_list(struct rtable *rt);

int fib_dump_info_fnhe(struct sk_buff *skb, struct netlink_callback *cb,
		       u32 table_id, struct fib_info *fi,
		       int *fa_index, int fa_start, unsigned int flags);

static inline void ip_rt_put(struct rtable *rt)
{
	/* dst_release() accepts a NULL parameter.
	 * We rely on dst being first structure in struct rtable
	 */
	BUILD_BUG_ON(offsetof(struct rtable, dst) != 0);
	dst_release(&rt->dst);
}

#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern const __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

/* ip_route_connect() and ip_route_newports() work in tandem whilst
 * binding a socket for a new outgoing connection.
 *
 * In order to use IPSEC properly, we must, in the end, have a
 * route that was looked up using all available keys including source
 * and destination ports.
 *
 * However, if a source port needs to be allocated (the user specified
 * a wildcard source port) we need to obtain addressing information
 * in order to perform that allocation.
 *
 * So ip_route_connect() looks up a route using wildcarded source and
 * destination ports in the key, simply so that we can get a pair of
 * addresses to use for port allocation.
 *
 * Later, once the ports are allocated, ip_route_newports() will make
 * another route lookup if needed to make sure we catch any IPSEC
 * rules keyed on the port information.
 *
 * The callers allocate the flow key on their stack, and must pass in
 * the same flowi4 object to both the ip_route_connect() and the
 * ip_route_newports() calls.
 */

static inline void ip_route_connect_init(struct flowi4 *fl4, __be32 dst, __be32 src,
					 u32 tos, int oif, u8 protocol,
					 __be16 sport, __be16 dport,
					 struct sock *sk)
{
	__u8 flow_flags = 0;

	if (inet_sk(sk)->transparent)
		flow_flags |= FLOWI_FLAG_ANYSRC;

	flowi4_init_output(fl4, oif, sk->sk_mark, tos, RT_SCOPE_UNIVERSE,
			   protocol, flow_flags, dst, src, dport, sport,
			   sk->sk_uid);
}

static inline struct rtable *ip_route_connect(struct flowi4 *fl4,
					      __be32 dst, __be32 src, u32 tos,
					      int oif, u8 protocol,
					      __be16 sport, __be16 dport,
					      struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct rtable *rt;

	ip_route_connect_init(fl4, dst, src, tos, oif, protocol,
			      sport, dport, sk);

	if (!dst || !src) {
		rt = __ip_route_output_key(net, fl4);
		if (IS_ERR(rt))
			return rt;
		ip_rt_put(rt);
		flowi4_update_output(fl4, oif, tos, fl4->daddr, fl4->saddr);
	}
	security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
	return ip_route_output_flow(net, fl4, sk);
}

static inline struct rtable *ip_route_newports(struct flowi4 *fl4, struct rtable *rt,
					       __be16 orig_sport, __be16 orig_dport,
					       __be16 sport, __be16 dport,
					       struct sock *sk)
{
	if (sport != orig_sport || dport != orig_dport) {
		fl4->fl4_dport = dport;
		fl4->fl4_sport = sport;
		ip_rt_put(rt);
		flowi4_update_output(fl4, sk->sk_bound_dev_if,
				     RT_CONN_FLAGS(sk), fl4->daddr,
				     fl4->saddr);
		security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
		return ip_route_output_flow(sock_net(sk), fl4, sk);
	}
	return rt;
}

static inline int inet_iif(const struct sk_buff *skb)
{
	struct rtable *rt = skb_rtable(skb);

	if (rt && rt->rt_iif)
		return rt->rt_iif;

	return skb->skb_iif;
}

static inline int ip4_dst_hoplimit(const struct dst_entry *dst)
{
	int hoplimit = dst_metric_raw(dst, RTAX_HOPLIMIT);
	struct net *net = dev_net(dst->dev);

	if (hoplimit == 0)
		hoplimit = net->ipv4.sysctl_ip_default_ttl;
	return hoplimit;
}

static inline struct neighbour *ip_neigh_gw4(struct net_device *dev,
					     __be32 daddr)
{
	struct neighbour *neigh;

	neigh = __ipv4_neigh_lookup_noref(dev, daddr);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &daddr, dev, false);

	return neigh;
}

static inline struct neighbour *ip_neigh_for_gw(struct rtable *rt,
						struct sk_buff *skb,
						bool *is_v6gw)
{
	struct net_device *dev = rt->dst.dev;
	struct neighbour *neigh;

	if (likely(rt->rt_gw_family == AF_INET)) {
		neigh = ip_neigh_gw4(dev, rt->rt_gw4);
	} else if (rt->rt_gw_family == AF_INET6) {
		neigh = ip_neigh_gw6(dev, &rt->rt_gw6);
		*is_v6gw = true;
	} else {
		neigh = ip_neigh_gw4(dev, ip_hdr(skb)->daddr);
	}
	return neigh;
}

#endif	/* _ROUTE_H */
