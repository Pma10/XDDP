CLANG ?= clang
CC ?= cc
ARCH_INCLUDES ?= /usr/include/$(shell $(CC) -dumpmachine)
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS = -O2 -g -target bpf -mcpu=v2 -I$(ARCH_INCLUDES) -Ixdp -Wall -Werror

.PHONY: all xdp gate test clean
all: xdp gate
build:
	mkdir -p build
xdp: build/xdp_ddos.bpf.o build/xdp_pass.bpf.o build/xddp-loader
build/%.bpf.o: xdp/%.bpf.c xdp/shared.h xdp/parse.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
build/xddp-loader: xdp/loader.c xdp/shared.h | build
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf -lz
gate:
	cargo build --release --manifest-path gate/Cargo.toml --locked
test: xdp
	cargo test --manifest-path gate/Cargo.toml --locked
	python3 -m unittest discover -s tests -p 'test_*.py' -v
	$(CC) $(CFLAGS) -fsanitize=address,undefined -Ixdp tests/parse_test.c -o build/parse-test
	./build/parse-test
clean:
	rm -f build/*.o build/xddp-loader build/parse-test
