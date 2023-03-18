#include "bpf_helpers.h"

// XDP program //
SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
  return XDP_DROP;
}

char _license[] SEC("license") = "GPLv2";