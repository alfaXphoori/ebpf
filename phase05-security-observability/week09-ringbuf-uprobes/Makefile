.PHONY: all generate build test run clean

all: generate build

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/ringbuf_events .

test: generate
	go test -exec sudo -v ./...

run: build
	sudo ./bin/ringbuf_events

clean:
	rm -rf bin/ bpf_*.go bpf_*.o
