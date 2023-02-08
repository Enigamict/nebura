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