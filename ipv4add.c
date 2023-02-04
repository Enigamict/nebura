#include "ipv4add.h"

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
  req.r.rtm_protocol = RTPROT_STATIC; //0x04
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
