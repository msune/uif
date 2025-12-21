OUT_DIR ?= output
GO ?= go
GOFLAGS ?=

.PHONY: all build clean check test

all: check
check: setup test test_ns clean

setup:
	sudo ip netns add ext
	sudo ip link add test_br123 type bridge
	sudo ip link set up dev test_br123
	sudo ip link add p1 type veth peer name p1_pair
	sudo ip link add p2 type veth peer name p2_pair
	sudo ip link set netns ext dev p2_pair
	sudo ip link set up dev p1
	sudo ip link set up dev p1_pair
	sudo ../output/uif create p1_pair
	sudo ip link set up dev p1_pair.ut
	sudo ip link set up dev p2
	sudo ip link set master test_br123 dev p1
	sudo ip link set master test_br123 dev p2
	sudo ip netns exec ext ip link set up dev p2_pair
	sudo ip addr add 192.168.99.1/24 dev p1_pair.ut
	sudo ip netns exec ext ip addr add 192.168.99.2/24 dev p2_pair
test:
	ping -c 3 192.168.99.2 || false

test_ns:
	sudo ip netns add ext2
	sudo ip netns exec ext2 ip link add test type veth
	sudo ip netns exec ext2 ip link set up dev test
	sudo ip netns exec ext2 ../output/uif create test

clean:
	sudo ip netns exec ext2 ip link del test || true
	sudo ip netns del ext2 || true
	sudo ip link del p1 || true
	sudo ip link del p2 || true
	sudo ip link del test_br123 || true
	sudo ip netns del ext || true
