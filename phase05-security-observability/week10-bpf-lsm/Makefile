CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

.PHONY: all generate build run clean

all: generate build

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/lsm_file_guard .

run: build
	sudo ./bin/lsm_file_guard

clean:
	rm -rf bin/ bpf_*.go bpf_*.o lab-files/
