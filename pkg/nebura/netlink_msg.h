#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#define TCA_BUF_MAX	(64*1024)
#define TC_H_ROOT	(0xFFFFFFFFU)
#define TIME_UNITS_PER_SEC	1000000

struct netlink_msg{
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[4096];
};

struct rtnl_handle{
    int fd;
};

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char			buf[1024];
};

struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment;
	__u8	flags;
	__u16	reserved;

	struct in6_addr segments[0];
};

struct seg6_iptunnel_encap {
	int mode;
	struct ipv6_sr_hdr srh[];
};

struct tc_netem_qopt {
	__u32	latency;	/* added delay (us) */
	__u32   limit;		/* fifo limit (packets) */
	__u32	loss;		/* random packet loss (0=none ~0=100%) */
	__u32	gap;		/* re-ordering gap (0 for none) */
	__u32   duplicate;	/* random packet dup  (0=none ~0=100%) */
	__u32	jitter;		/* random jitter in latency (us) */
};

struct tc_netem {
	struct nlmsghdr	n;
	struct tcmsg	t;
	char   buf[TCA_BUF_MAX];
};
