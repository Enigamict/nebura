#include "libnetlink.h"


void hexdump(const void *buffer, size_t bufferlen)
{
  const unsigned char *data = (const unsigned char *)(buffer); 
  for (size_t i = 0; i < bufferlen; i++) {
    if (i % 4 == 0) {
      printf("  ");
    }
    if (i % 16 == 0) {
      printf("  \n");
    }
    printf("%02X", data[i]);
  }
}

int addattr_l(struct nlmsghdr *n, int maxlen,
    int type, const void *data, int alen)
{
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
    fprintf(stderr,
      "addattr_l ERROR: message exceeded bound of %d\n",
      maxlen);
    return -1;
  }

  rta = NLMSG_TAIL(n);
  rta->rta_type = type;
  rta->rta_len = len;
  if (alen)
    memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  return 0;
}

int addattr(struct nlmsghdr *n, int maxlen, int type)
{
    return addattr_l(n, maxlen, type, NULL, 0);
}
int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u8));
}
int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u16));
}
int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}
int addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u64));
}
int addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{
    return addattr_l(n, maxlen, type, str, strlen(str) + 1);
}

int nl_talk_iov(int fd, struct iovec *iov)
{
  struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = 1,
	};

  int send_len = sendmsg(fd, &msg, 0);

  if (send_len < 0)
  {
    perror("Receiving message failed");
  }

  char recv_buf[MAX_RECV_BUF_LEN];

  struct iovec riov = {
      .iov_base = &recv_buf,
      .iov_len = MAX_RECV_BUF_LEN};

  msg.msg_iov = &riov;
  msg.msg_iovlen = 1;

  int recv_len = recvmsg(fd, &msg, 0);
  if (recv_len < 0)
  {
    perror("Receiving message failed");
  }

  struct nlmsghdr *rnh;

  for (rnh = (struct nlmsghdr *)recv_buf; NLMSG_OK(rnh, recv_len); rnh = NLMSG_NEXT(rnh, recv_len))
  {

    if (rnh->nlmsg_type == NLMSG_ERROR)
    {
      struct nlmsgerr *errmsg;
      errmsg = NLMSG_DATA(rnh);
      printf("%d, %s\n", errmsg->error, strerror(-errmsg->error));
      break;
    }
  }

    return 1;
}

int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
                  const void *data, int alen)
{
  printf("%d", maxlen);
  struct rtattr *subrta;
  int len = RTA_LENGTH(alen);

  subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
  subrta->rta_type = type;
  subrta->rta_len = len;
  if (alen)
    memcpy(RTA_DATA(subrta), data, alen);
  rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
  return 0;
}

int rta_addattr8(struct rtattr *rta, int maxlen, int type, __u8 data)
{
    return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u8));
}

int rta_addattr16(struct rtattr *rta, int maxlen, int type, __u16 data)
{
    return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u16));
}

int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data)
{
    return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u32));
}

int rta_addattr64(struct rtattr *rta, int maxlen, int type, __u64 data)
{
    return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u64));
}

struct rtattr *
rta_nest(struct rtattr *rta, int maxlen, int type)
{
    struct rtattr *nest = RTA_TAIL(rta);
    rta_addattr_l(rta, maxlen, type, NULL, 0);
    nest->rta_type |= NLA_F_NESTED;
    return nest;
}

int rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
    nest->rta_len = (void *)RTA_TAIL(rta) - (void *)nest;
    return rta->rta_len;
}


void monitor_show(struct nlmsghdr *hdr) {

  int ADD_ROUTE = 24;
  int DEL_ROUTE = 25;

  if (hdr->nlmsg_type == ADD_ROUTE) {
		printf("monitor: route add\n");
  }

  if (hdr->nlmsg_type == DEL_ROUTE) {
		printf("monitor: route del\n");
  }
}

int rtnl_open()
{

    socklen_t addr_len;
    int fd;
    struct sockaddr_nl nl = {0};

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

    nl.nl_family = AF_NETLINK;
	nl.nl_groups = RTMGRP_LINK | RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR 
                  | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_MROUTE | RTMGRP_IPV4_RULE | RTMGRP_IPV6_ROUTE 
                  | RTMGRP_IPV6_MROUTE | RTMGRP_IPV6_IFINFO | RTMGRP_IPV6_PREFIX | RTMGRP_NEIGH;

	if (bind(fd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
		fprintf(stderr, "bind err closed socket\n");
		close(fd);
	}

	addr_len = sizeof(nl);

	if (getsockname(fd, (struct sockaddr*)&nl, &addr_len) < 0) {
		fprintf(stderr, "no sock err closed socket\n");
		close(fd);
	}
  return fd;

}

int rtnl_listen(int fd)
{
	char buff[4096];
	struct nlmsghdr	*hdr;
	int len;

	while (1) {

		len = recv(fd, buff, sizeof(buff), 0);
		if (len < 0) {
			break;
		}
		for (hdr = (struct nlmsghdr*)buff; NLMSG_OK(hdr,len); hdr=NLMSG_NEXT(hdr,len)) {
			monitor_show(hdr);
		}  
	}

  return 0;
}

int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len)
{
    if (NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len) > maxlen)
    {
        fprintf(stderr,
                "addraw_l ERROR: message exceeded bound of %d\n",
                maxlen);
        return -1;
    }

    memcpy(NLMSG_TAIL(n), data, len);
    memset((void *)NLMSG_TAIL(n) + len, 0, NLMSG_ALIGN(len) - len);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len);
    return 0;
}