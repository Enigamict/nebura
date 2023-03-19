#include "netlink_code.h"

void hexdump1(FILE* fp, const void *buffer, size_t bufferlen)
{
  const uint8_t *data = (const uint8_t*)(buffer); size_t row = 0;
  while (bufferlen > 0) {
    fprintf(fp, "%04zx:   ", row);
    size_t n;
    if (bufferlen < 16) n = bufferlen;
    else                n = 16;

    for (size_t i = 0; i < n; i++) { if (i == 8) fprintf(fp, " "); fprintf(fp, " %02x", data[i]); }
    for (size_t i = n; i < 16; i++) { fprintf(fp, "   "); } fprintf(fp, "   ");
    for (size_t i = 0; i < n; i++) {
      if (i == 8) fprintf(fp, "  ");
      uint8_t c = data[i];
      if (!(0x20 <= c && c <= 0x7e)) c = '.';
      fprintf(fp, "%c", c);
    }
    fprintf(fp, "\n"); bufferlen -= n; data += n; row  += n;
  }
}

int ipv4_route_add(char *src_addr, char *dst_addr, int index, int len, bool route) {

  struct netlink_msg req;

  struct in_addr add_v4prefix;
  struct in_addr via_v4prefix;

  inet_pton(AF_INET, src_addr, &add_v4prefix);
  inet_pton(AF_INET, dst_addr, &via_v4prefix);

  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (fd < 0) {
    return 0;
  }

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_REPLACE;
  req.n.nlmsg_type  = route ? RTM_NEWROUTE : RTM_DELROUTE;
  req.r.rtm_family = AF_INET;
  req.r.rtm_dst_len = len;
  req.r.rtm_src_len = 0;
  req.r.rtm_tos = 0;
  req.r.rtm_table = RT_TABLE_MAIN; // 0xFE
  req.r.rtm_protocol = RTPROT_BGP; //0x04
  req.r.rtm_scope = RT_SCOPE_UNIVERSE; // 0x00
  req.r.rtm_type = RTN_UNICAST; // 0x01
  req.r.rtm_flags = 0;
 
  addattr_l(&req.n, sizeof(req), RTA_DST, &add_v4prefix, sizeof(struct in_addr));
  addattr_l(&req.n, sizeof(req),
		  RTA_GATEWAY, &via_v4prefix,
		  sizeof(struct in_addr));

  uint32_t oif_idx = index;
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);

  uint32_t table = 254;
  addattr32(&req.n, sizeof(req), RTA_TABLE, table);
  // iproute2は250から見る
  // 08 00 01 00 - rta_len rta_type


  struct iovec iov = {&req, req.n.nlmsg_len };
  hexdump1(stdout, &req, 100);

  nl_talk_iov(fd, &iov);
  return 1; 

}

int ipv6_route_add(char *src_addr, char *dst_addr, int index, int len, bool route) {
struct netlink_msg req;

  struct in6_addr add_v6prefix;
  struct in6_addr via_v6prefix;
  inet_pton(AF_INET6, dst_addr, &add_v6prefix);
  inet_pton(AF_INET6, src_addr, &via_v6prefix);

  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (fd < 0) {
    return 0;
  }

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_REPLACE;
  req.n.nlmsg_type  = route ? RTM_NEWROUTE : RTM_DELROUTE;
  req.r.rtm_family = AF_INET6;
  req.r.rtm_dst_len = len;
  req.r.rtm_src_len = 0;
  req.r.rtm_tos = 0;
  req.r.rtm_table = RT_TABLE_MAIN; // 0xFE
  req.r.rtm_protocol = RTPROT_BGP; //0x04
  req.r.rtm_scope = RT_SCOPE_UNIVERSE; // 0x00
  req.r.rtm_type = RTN_UNICAST; // 0x01
  req.r.rtm_flags = 0;
 
  addattr_l(&req.n, sizeof(req), RTA_DST, &add_v6prefix, sizeof(struct in6_addr));
  req.r.rtm_dst_len = len;
  addattr_l(&req.n, sizeof(req),
		  RTA_GATEWAY, &via_v6prefix,
		  sizeof(struct in6_addr));


  struct iovec iov = {&req, req.n.nlmsg_len };
  hexdump1(stdout, &req, 100);

  nl_talk_iov(fd, &iov);
  return 1; 
}

struct ipv6_sr_hdr *parse_srh(char *segs)
{
	struct ipv6_sr_hdr *srh;
	int srhlen;

	srhlen = 8 + 16*1;

	srh = malloc(srhlen);
	memset(srh, 0, srhlen);

	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = 0;
	srh->first_segment = 0;
  inet_pton(AF_INET6, segs, &srh->segments[0]);

  return srh;
}

int seg6_end_aciton(char *en, char *nh) {

  struct netlink_msg req;
  struct in6_addr encap_prefix;
  struct in_addr via_prefix;

  inet_pton(AF_INET6, en, &encap_prefix);
  inet_pton(AF_INET, nh, &via_prefix);

  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (fd < 0) {
    return 0;
  }

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_REPLACE;
  req.n.nlmsg_type  = RTM_NEWROUTE;
  req.r.rtm_family = AF_INET6;
  req.r.rtm_dst_len = 128;
  req.r.rtm_src_len = 0;
  req.r.rtm_tos = 0;
  req.r.rtm_table = RT_TABLE_MAIN;
  req.r.rtm_protocol = 0x00;
  req.r.rtm_scope = 0xFD;
  req.r.rtm_type = RTN_UNICAST;
  req.r.rtm_flags = 0;

  addattr_l(&req.n, sizeof(req), RTA_DST, &encap_prefix, sizeof(struct in6_addr)); // dst
  uint32_t oif_idx = 39;
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP; // 0x8016
  rta->rta_len = RTA_LENGTH(0); 
  struct rtattr *nest;
  nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  rta_addattr32(rta, sizeof(buf), SEG6_LOCAL_ACTION, SEG6_LOCAL_ACTION_END_DX4);

  rta_addattr_l(rta, sizeof(buf), SEG6_LOCAL_NH4,
					    &via_prefix, sizeof(struct in_addr));

  rta_nest_end(rta, nest);
  addraw_l(&req.n, 1024 , RTA_DATA(rta), RTA_PAYLOAD(rta)); // hexdumpで見てあっていてもaddraw_lでrtattrとreqを結びつける

  addattr16(&req.n, sizeof(req), RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6_LOCAL);
  hexdump1(stdout ,&req, 100);

  struct iovec iov = {&req, req.n.nlmsg_len };

  nl_talk_iov(fd, &iov);
  return 1; 
}
int seg6_route_add(char *encap_addr, char *segs) {

  struct netlink_msg req;
  struct ipv6_sr_hdr *sr;
  struct seg6_iptunnel_encap *tuninfo;

  struct in_addr encap_prefix;

  inet_pton(AF_INET, encap_addr, &encap_prefix);

  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (fd < 0) {
    return 0;
  }

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_REPLACE;
  req.n.nlmsg_type  = RTM_NEWROUTE;
  req.r.rtm_family = AF_INET;
  req.r.rtm_dst_len = 24;
  req.r.rtm_src_len = 0;
  req.r.rtm_tos = 0;
  req.r.rtm_table = RT_TABLE_MAIN;
  req.r.rtm_protocol = 0x03;
  req.r.rtm_scope = 0xFD;
  req.r.rtm_type = RTN_UNICAST;
  req.r.rtm_flags = 0;

  addattr_l(&req.n, sizeof(req), RTA_DST, &encap_prefix, sizeof(struct in_addr)); // dst
  uint32_t oif_idx = 40;
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP; // 0x8016
  rta->rta_len = RTA_LENGTH(0); 
  struct rtattr *nest;
  nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  sr = parse_srh(segs);
  int sr_len;
  sr_len = (sr->hdrlen + 1) << 3;
  tuninfo = malloc(sizeof(*tuninfo) + sr_len);
	memset(tuninfo, 0, sizeof(*tuninfo) + sr_len);
	tuninfo->mode = 1; // SEG6_IPTUN_MODE_ENCAP
	memcpy(tuninfo->srh, sr, sr_len);
  rta_addattr_l(rta, sizeof(buf), 1, tuninfo, sizeof(*tuninfo) + sr_len);

  rta_nest_end(rta, nest);
  addraw_l(&req.n, 1024 , RTA_DATA(rta), RTA_PAYLOAD(rta)); // hexdumpで見てあっていてもaddraw_lでrtattrとreqを結びつける

  addattr16(&req.n, sizeof(req), RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6);
  hexdump1(stdout ,&req, 100);

  struct iovec iov = {&req, req.n.nlmsg_len };

  nl_talk_iov(fd, &iov);
  return 1; 

  //parse(answer, sizeof(buf));

}

int get_time(unsigned int *time, const char *str)
{
	double t;
	char *p;

	t = strtod(str, &p);
	if (p == str)
		return -1;

	if (*p) {
		if (strcasecmp(p, "s") == 0 || strcasecmp(p, "sec") == 0 ||
		    strcasecmp(p, "secs") == 0)
			t *= TIME_UNITS_PER_SEC;
		else if (strcasecmp(p, "ms") == 0 || strcasecmp(p, "msec") == 0 ||
			 strcasecmp(p, "msecs") == 0)
			t *= TIME_UNITS_PER_SEC/1000;
		else if (strcasecmp(p, "us") == 0 || strcasecmp(p, "usec") == 0 ||
			 strcasecmp(p, "usecs") == 0)
			t *= TIME_UNITS_PER_SEC/1000000;
		else
			return -1;
	}

	*time = t;
	return 0;
}

static double tick_in_usec = 1;
static double clock_factor = 1;

static int get_ticks(__u32 *ticks, const char *str)
{
	unsigned int t;

	if (get_time(&t, str))
		return -1;


	*ticks = t * tick_in_usec;
	return 0;
}
int tc_core_init(void) // TCは起動時にカーネルクロックについての初期化を行う。具体的に何を行っているかは不明....
{
	FILE *fp;
	__u32 clock_res;
	__u32 t2us;
	__u32 us2t;

	fp = fopen("/proc/net/psched", "r");
	if (fp == NULL)
		return -1;

	if (fscanf(fp, "%08x%08x%08x", &t2us, &us2t, &clock_res) != 3) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	/* compatibility hack: for old iproute binaries (ignoring
	 * the kernel clock resolution) the kernel advertises a
	 * tick multiplier of 1000 in case of nano-second resolution,
	 * which really is 1. */
	if (clock_res == 1000000000)
		t2us = us2t;

	clock_factor  = (double)clock_res / TIME_UNITS_PER_SEC;
	tick_in_usec = (double)t2us / us2t * clock_factor;
	return 0;
}

int tc_netem_add(int index, char *latestr) {

  char k[16] = {};

  struct tc_netem_qopt opt = { .limit = 1000 };
  struct tc_netem req;

  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  tc_core_init();

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL| NLM_F_CREATE,
  req.n.nlmsg_type = RTM_NEWQDISC,
  req.t.tcm_family = AF_UNSPEC,

  req.t.tcm_ifindex = index;
  req.t.tcm_parent = TC_H_ROOT;
	strncpy(k, "netem", sizeof(k)-1);
	addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);
  get_ticks(&opt.latency, latestr);
  addattr_l(&req.n, 1024, TCA_OPTIONS, &opt, sizeof(opt));
  hexdump1(stdout, &req, 100);
  struct iovec iov = {&req, req.n.nlmsg_len };

  nl_talk_iov(fd, &iov);
	return 0;
}
