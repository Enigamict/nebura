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

int ipv4_route_add(char *src_addr, char *dst_addr, int index, int len);
int ipv6_route_add(char *src_addr, char *dst_addr, int index, int len);
struct ipv6_sr_hdr *parse_srh(char *segs);
int seg6_end_aciton(char *en, char *nh);
int seg6_route_add(char *encap_addr, char *segs);
int get_time(unsigned int *time, const char *str);
int tc_core_init(void);
int tc_netem_add(int index, char *latestr);