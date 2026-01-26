CC := clang
CFLAGS := --target=wasm32-unknown-unknown -O2 -ffreestanding -nostdlib
LDFLAGS := -Wl,--no-entry -Wl,--export=entrypoint -Wl,--strip-all -Wl,--no-export-dynamic
INC := -Isrc

SOURCES := $(wildcard *.c)
WASMS := $(SOURCES:.c=.wasm)

.PHONY: all clean

all: $(WASMS)

%.wasm: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(INC) -o $@ $<

clean:
	rm -f $(WASMS)
