OUT_DIR ?= output
GO ?= go
GOFLAGS ?=
GOENV ?= CGO_ENABLED=0

.PHONY: all build clean check

all: build
build:
	mkdir -p $(OUT_DIR)
	$(MAKE) -C bpf
	cp bpf/untagged.o cmd/uif/untagged.o
	$(GOENV) $(GO) build $(GOFLAGS) -o $(OUT_DIR)/uif ./cmd/uif

check: build
	$(MAKE) -C tests
	$(MAKE) -C tests #Run it a second time, to test recreation of ifaces
	$(MAKE) -C tests clean
clean:
	$(MAKE) -C tests clean || true
	$(MAKE) -C bpf clean || true
	rm -rf cmd/uif/untagged.o || true
	rm -rf $(OUT_DIR)/* || true
