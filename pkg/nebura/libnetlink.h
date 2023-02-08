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
#include	<poll.h>
#include <sys/ioctl.h>
#include <sys/select.h>


#include "netlink_msg.h"

#define MAX_RECV_BUF_LEN 32768

#define NLMSG_TAIL(nmsg) \
  ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define RTA_TAIL(rta) \
	((struct rtattr *) (((void *) (rta)) + \
					RTA_ALIGN((rta)->rta_len)))
  
enum lwtunnel_encap_types {
	LWTUNNEL_ENCAP_NONE,
	LWTUNNEL_ENCAP_MPLS,
	LWTUNNEL_ENCAP_IP,
	LWTUNNEL_ENCAP_ILA,
	LWTUNNEL_ENCAP_IP6,
	LWTUNNEL_ENCAP_SEG6,
	LWTUNNEL_ENCAP_BPF,
	LWTUNNEL_ENCAP_SEG6_LOCAL,
	LWTUNNEL_ENCAP_RPL,
	LWTUNNEL_ENCAP_IOAM6,
	LWTUNNEL_ENCAP_XFRM,
	__LWTUNNEL_ENCAP_MAX,
};

enum {
	SEG6_LOCAL_UNSPEC,
	SEG6_LOCAL_ACTION,
	SEG6_LOCAL_SRH,
	SEG6_LOCAL_TABLE,
	SEG6_LOCAL_NH4,
	SEG6_LOCAL_NH6,
	SEG6_LOCAL_IIF,
	SEG6_LOCAL_OIF,
	SEG6_LOCAL_BPF,
	SEG6_LOCAL_VRFTABLE,
	SEG6_LOCAL_COUNTERS,
	SEG6_LOCAL_FLAVORS,
	__SEG6_LOCAL_MAX,
};

enum {
	SEG6_LOCAL_ACTION_UNSPEC	= 0,
	/* node segment */
	SEG6_LOCAL_ACTION_END		= 1,
	/* adjacency segment (IPv6 cross-connect) */
	SEG6_LOCAL_ACTION_END_X		= 2,
	/* lookup of next seg NH in table */
	SEG6_LOCAL_ACTION_END_T		= 3,
	/* decap and L2 cross-connect */
	SEG6_LOCAL_ACTION_END_DX2	= 4,
	/* decap and IPv6 cross-connect */
	SEG6_LOCAL_ACTION_END_DX6	= 5,
	/* decap and IPv4 cross-connect */
	SEG6_LOCAL_ACTION_END_DX4	= 6,
	/* decap and lookup of DA in v6 table */
	SEG6_LOCAL_ACTION_END_DT6	= 7,
	/* decap and lookup of DA in v4 table */
	SEG6_LOCAL_ACTION_END_DT4	= 8,
	/* binding segment with insertion */
	SEG6_LOCAL_ACTION_END_B6	= 9,
	/* binding segment with encapsulation */
	SEG6_LOCAL_ACTION_END_B6_ENCAP	= 10,
	/* binding segment with MPLS encap */
	SEG6_LOCAL_ACTION_END_BM	= 11,
	/* lookup last seg in table */
	SEG6_LOCAL_ACTION_END_S		= 12,
	/* forward to SR-unaware VNF with static proxy */
	SEG6_LOCAL_ACTION_END_AS	= 13,
	/* forward to SR-unaware VNF with masquerading */
	SEG6_LOCAL_ACTION_END_AM	= 14,
	/* custom BPF action */
	SEG6_LOCAL_ACTION_END_BPF	= 15,
	/* decap and lookup of DA in v4 or v6 table */
	SEG6_LOCAL_ACTION_END_DT46	= 16,

	__SEG6_LOCAL_ACTION_MAX,
};

void hexdump(const void *buffer, size_t bufferlen);

static inline __u8 rta_getattr_u8(const struct rtattr *rta) { return *(__u8 *)RTA_DATA(rta); }
static inline __u16 rta_getattr_u16(const struct rtattr *rta) { return *(__u16 *)RTA_DATA(rta); }
static inline __u32 rta_getattr_u32(const struct rtattr *rta) { return *(__u32 *)RTA_DATA(rta); }
static inline __u64 rta_getattr_u64(const struct rtattr *rta) { return *(__u64 *)RTA_DATA(rta); }
static inline __s8 rta_getattr_s8(const struct rtattr *rta) { return *(__s8 *)RTA_DATA(rta); }
static inline __u16 rta_getattr_s16(const struct rtattr *rta) { return *(__s16 *)RTA_DATA(rta); }
static inline __s32 rta_getattr_s32(const struct rtattr *rta) { return *(__s32 *)RTA_DATA(rta); }
static inline __s64 rta_getattr_s64(const struct rtattr *rta) { return *(__s64 *)RTA_DATA(rta); }
static inline const char *rta_getattr_str(const struct rtattr *rta) { return (const char *)RTA_DATA(rta); }
int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen);


int addattr(struct nlmsghdr *n, int maxlen, int type);
int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data);
int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data);
int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data);
int addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data);
int addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str);

int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len);

int nl_talk_iov(int fd, struct iovec *iov);

int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
      const void *data, int alen);

int rta_addattr8(struct rtattr *rta, int maxlen, int type, __u8 data);

int rta_addattr16(struct rtattr *rta, int maxlen, int type, __u16 data);

int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data);

int rta_addattr64(struct rtattr *rta, int maxlen, int type, __u64 data);

struct rtattr * rta_nest(struct rtattr *rta, int maxlen, int type);

int rta_nest_end(struct rtattr *rta, struct rtattr *nest);


void monitor_show(struct nlmsghdr *hdr);
int rtnl_open();

int rtnl_listen(int fd);