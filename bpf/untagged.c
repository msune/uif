#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("tcx/ingress")
int uif_ingress(struct __sk_buff *skb) {
	if (skb->vlan_present)
		return TC_ACT_UNSPEC;

	int rc = bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 0x0);
	if (rc < 0)
		return TC_ACT_SHOT;

	return TC_ACT_UNSPEC;
}

SEC("tcx/egress")
int uif_egress(struct __sk_buff *skb) {
	if (!skb->vlan_present || skb->vlan_tci != 0)
		return TC_ACT_UNSPEC;

	int rc = bpf_skb_vlan_pop(skb);
	if (rc < 0)
		return TC_ACT_SHOT;

	return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";

