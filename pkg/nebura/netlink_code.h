#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/types.h>

#include "libnetlink.h"
#include "netlink_msg.h"

int ipv4_route_add(char *src_addr, char *dst_addr, int index);
int ipv6_route_add(char *src_addr, int index);
struct ipv6_sr_hdr *parse_srh();
int seg6_end_aciton(struct in6_addr dst_addr);
int seg6_route_add(struct in_addr dst_addr);
int get_time(unsigned int *time, const char *str);
int tc_core_init(void);
int tc_netem_add(int index, char *latestr);