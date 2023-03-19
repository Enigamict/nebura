#include "bpf_helpers.h"

// XDP program //

BPF_MAP_DEF(protocols) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
};

BPF_MAP_ADD(protocols);

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
  return XDP_DROP;
}

char _license[] SEC("license") = "GPLv2";