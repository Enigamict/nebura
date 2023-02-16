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