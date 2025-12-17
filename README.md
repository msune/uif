# `uif`: untagged subinterfaces in Linux

`uif` is as small tool to create(emulate) untagged network subinterfaces
`<iface>.ut` in Linux, so interfaces that only receive and send untagged
(no VLAN) traffic. It leverages the power of :bee: [eBPF](https://ebpf.io/).

## Quick start

Clone the repo and build:

```
$ make
```

To create an 'untagged' subinterface over `veth0`:

```
$ sudo output/uif create veth0
```

The subinterface can then be managed using standard Linux tools
(e.g. `ip`), as any other network device.

## Why?

In short:

 * To be able to **only do MAC learning on untagged traffic** on a Linux bridge
   (with `vlan_filtering=0` [^1]) as opposed to what happens when you attach
   the main interface.
 * To make it **compatible with TC/TCX BPF programs**.
 * To allow programs capturing or processing traffic (e.g. `tcpdump` or
   `wireshark`) to handle untagged traffic only transparently, that is without
   pcap filters, etc.
 * To have them modeled as a subinterface, with its own `ifindex` etc, similar
   to how some switches and routers do it.

### More details

In Linux, it's not possible to create a subinterface that sends and receives
only untagged traffic from a network device card (physical or virtual). A main
interface (e.g. `eth0`) sees all traffic, both untagged and tagged. VLAN
subinterfaces, on the other hand, see only traffic tagged with particular
VLAN of that subinterface [^2].

This is generally not an issue at Layer 3, since assigning an IP address to an
interface implicitely applies to untagged traffic (no VLAN), but it is for
Layer 2.

When an interface is attached to a bridge with `vlan_filtering=0` (default),
MAC learning happens using solely the destination MAC address of the received
packet, regardless of the packet's VLAN tag or absence of (unqualified
learning). So attaching `eth0` to a bridge will learn from untagged traffic and
from any other VLAN tagged traffic that `eth0` doesn't have an (outer) VLAN
subinterface for.

The lack of an "untagged subinterface" also prevents attaching (TC/TCX) eBPF
programs to a subinterface that would only process untagged frames.

## How does it work?

`uif` creates a VLAN 0 interface over the target interface with the name
`<iface>.ut`, and it attaches two small eBPF TCX programs on ingress and egress
on `<iface>`.

These programs push a VLAN 0 tag on ingress and pop the VLAN0 tag on egress
respectively, to make sure untagged traffic is muxed/demuxed to `<iface>.ut`
correctly.

Because of the place where TCX eBPF hooks execute, the result is that programs
such as `tcpdump` and `wireshark` work as expected, transparently, seeing all
untagged and tagged traffic in `<iface>`, and only untagged traffic in
`<iface>.ut`.

### Compatibility with VLAN0 priority tagging

As VLAN 0 is (ab)used as a means to mux/demux to/from the main interface,
[VLAN 0 priority tagging](https://www.cisco.com/c/en/us/td/docs/switches/connectedgrid/cg-switch-sw-master/software/configuration/guide/vlan0/b_vlan_0.html)
is not supported.

### Compatibility with other BPF programs

`uif` attaches eBPF programs on ingress and egress of the primary interface
using [TCX](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/).
These programs always return `TC_ACT_UNSPEC`, so it's safe to attach other
programs _after_ it on TCX, or in TC (they will always run after).

[^1]: and in absence of L2 ACLs.
[^2]: or when stacking VLAN interfaces (e.g. 2 interfaces to do 802.1ad), all
      stacked VLANs.
