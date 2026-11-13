.PHONY: all generate build test run clean

all: generate build

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/lsm_file_guard .

test: generate
	go test -exec sudo -v ./...

run: build
	sudo ./bin/lsm_file_guard

clean:
	rm -rf bin/ bpf_*.go bpf_*.o lab-files/
