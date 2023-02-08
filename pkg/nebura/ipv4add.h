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
void hexdump1(FILE* fp, const void *buffer, size_t bufferlen);