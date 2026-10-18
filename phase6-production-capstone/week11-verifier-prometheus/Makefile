CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

.PHONY: all generate build run clean

all: generate build

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/metrics_exporter .

run: build
	sudo ./bin/metrics_exporter -iface lo

clean:
	rm -rf bin/ bpf_*.go bpf_*.o
