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

int ipv4_route_add(char *src_addr, char *dst_addr, int index) {

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
  req.n.nlmsg_type  = RTM_NEWROUTE;
  req.r.rtm_family = AF_INET;
  req.r.rtm_dst_len = 32;
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

int ipv6_route_add(char *src_addr, int index) {
struct netlink_msg req;

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
  req.r.rtm_table = RT_TABLE_MAIN; // 0xFE
  req.r.rtm_protocol = RTPROT_BGP; //0x04
  req.r.rtm_scope = RT_SCOPE_UNIVERSE; // 0x00
  req.r.rtm_type = RTN_UNICAST; // 0x01
  req.r.rtm_flags = 0;
 
  addattr_l(&req.n, sizeof(req), RTA_DST, &src_addr, sizeof(struct in6_addr));

  uint32_t oif_idx = index; 
	addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);

  struct iovec iov = {&req, req.n.nlmsg_len };

  nl_talk_iov(fd, &iov);
  return 1; 
}

struct ipv6_sr_hdr *parse_srh()
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
  inet_pton(AF_INET6, "fc00:2::11", &srh->segments[0]);

  return srh;
}

int seg6_end_aciton(struct in6_addr dst_addr) {

  struct netlink_msg req;

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

  addattr_l(&req.n, sizeof(req), RTA_DST, &dst_addr, sizeof(struct in6_addr)); // dst
  uint32_t oif_idx = 3;
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP; // 0x8016
  rta->rta_len = RTA_LENGTH(0); 
  struct rtattr *nest;
  nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  rta_addattr32(rta, sizeof(buf), SEG6_LOCAL_ACTION, SEG6_LOCAL_ACTION_END_DX4);
  struct in_addr via_prefix;

  inet_pton(AF_INET, "1.1.1.1", &via_prefix);
  rta_addattr_l(rta, sizeof(buf), SEG6_LOCAL_NH4,
					    &via_prefix, sizeof(struct in_addr));

  rta_nest_end(rta, nest);
  addraw_l(&req.n, 1024 , RTA_DATA(rta), RTA_PAYLOAD(rta)); // hexdumpで見てあっていてもaddraw_lでrtattrとreqを結びつける

  addattr16(&req.n, sizeof(req), RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6_LOCAL);
  hexdump1(stdout ,&req, 100);

  struct iovec iov = {&req, req.n.nlmsg_len };

  nl_talk_iov(fd, &iov);

  //parse(answer, sizeof(buf));

}
int seg6_route_add(struct in_addr dst_addr) {

  struct netlink_msg req;
  struct ipv6_sr_hdr *sr;
  struct seg6_iptunnel_encap *tuninfo;

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

  addattr_l(&req.n, sizeof(req), RTA_DST, &dst_addr, sizeof(struct in_addr)); // dst
  uint32_t oif_idx = 3;
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP; // 0x8016
  rta->rta_len = RTA_LENGTH(0); 
  struct rtattr *nest;
  nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  sr = parse_srh();
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

int tc_netem_add() {
  char k[16] = {};

  struct tc_netem_qopt opt = { .limit = 1000 };
  struct tc_netem req;
	struct rtattr *tail;

  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL| NLM_F_CREATE,
  req.n.nlmsg_type = RTM_NEWQDISC,
  req.t.tcm_family = AF_UNSPEC,

  req.t.tcm_ifindex = 34;
  req.t.tcm_parent = TC_H_ROOT;
	strncpy(k, "netem", sizeof(k)-1);
	addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);

	tail = NLMSG_TAIL(&req.n);
  get_time(&opt.latency, "100ms");
  addattr_l(&req.n, 1024, TCA_OPTIONS, &opt, sizeof(opt));
  hexdump1(stdout, &req, 100);
  struct iovec iov = {&req, req.n.nlmsg_len };

  nl_talk_iov(fd, &iov);
}