all: compile

CFLAGS = -O2 -Wall -Werror -g
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG=1
endif

compile:
	clang $(CFLAGS) -target bpf -c untagged.c -o untagged.o

attach:
	sudo tc qdisc add dev veth0 clsact || true
	sudo tc filter add dev veth0 ingress bpf da obj ./untagged.o sec tcx/ingress
	sudo tc filter add dev veth0 egress  bpf da obj ./untagged.o sec tcx/egress
detach:
	$(QUIET)sudo tc filter del dev veth0 ingress || true
	$(QUIET)sudo tc filter del dev veth0 egress || true

clean:
	rm -rf *.o || true
