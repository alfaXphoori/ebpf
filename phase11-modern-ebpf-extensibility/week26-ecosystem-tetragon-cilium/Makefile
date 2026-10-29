# ==============================================================================
# Makefile: Week 26 - eBPF Ecosystem: Tetragon (hands-on) + Cilium (concepts)
# ==============================================================================
#
# `all` and `test` are cheap and safe (no root, no containers): the repo root
# Makefile calls them for every week. Everything that starts Tetragon is an
# explicit target (up / apply-* / down).
#
#   make up                   # start Tetragon (privileged Docker container)
#   make apply-exec           # policy 01: exec LSM view (+ built-in process_exec/exit)
#   make apply-file           # policy 02: file access monitoring of lab-files/
#   make apply-connect        # policy 03: tcp_connect / tcp_close on port 18026
#   make apply-sigkill        # policy 04: SIGKILL whoever opens lab-files/secret.txt
#   make apply-override       # policy 05: open(lab-files/secret.txt) -> EPERM (BPF LSM)
#   make up-nomulti apply-fmodret  # policy 06: same EPERM via kprobe Override (fmod_ret)
#   make events               # stream compact events (Ctrl+C to stop)
#   make progs                # BPF programs Tetragon loaded
#   make down                 # stop + remove container, verify no BPF program is left
#

RUN := ./run-tetragon.sh

.PHONY: all test lint up down status list events progs prepare clean \
        apply-exec apply-file apply-connect apply-sigkill apply-sigkill-monitor \
        apply-override apply-fmodret up-nomulti remove-all

# Cheap, root-free validation (YAML + safety rules + shell syntax)
all: lint

test: lint

lint:
	@echo "===> Validating TracingPolicy YAML (policies/*.yaml)..."
	@python3 validate-policies.py
	@bash -n $(RUN) && echo "  ok    run-tetragon.sh (bash -n)"

up:
	$(RUN) up

# Policy 06 needs the daemon started without kprobe_multi (fmod_ret Override)
up-nomulti:
	TETRAGON_ARGS="--disable-kprobe-multi" $(RUN) up

down:
	$(RUN) down

status:
	$(RUN) status

list:
	$(RUN) list

events:
	$(RUN) events

progs:
	$(RUN) progs

prepare:
	$(RUN) prepare

apply-exec:
	$(RUN) apply 01-process-exec-lsm.yaml

apply-file:
	$(RUN) apply 02-file-monitor.yaml

apply-connect:
	$(RUN) apply 03-tcp-connect.yaml

# Load the Sigkill policy in monitor mode first (it only counts NMONITOR), then
# switch with: ./run-tetragon.sh mode w26-enforce-secret-sigkill enforce
apply-sigkill-monitor:
	$(RUN) apply 04-enforce-secret-sigkill.yaml monitor

apply-sigkill:
	$(RUN) apply 04-enforce-secret-sigkill.yaml

apply-override:
	$(RUN) apply 05-enforce-secret-override.yaml

apply-fmodret:
	$(RUN) apply 06-enforce-secret-fmodret.yaml

remove-all:
	-$(RUN) remove w26-process-exec-lsm
	-$(RUN) remove w26-file-monitor
	-$(RUN) remove w26-tcp-connect
	-$(RUN) remove w26-enforce-secret-sigkill
	-$(RUN) remove w26-enforce-secret-override
	-$(RUN) remove w26-enforce-secret-fmodret

# Root `make clean` calls this: never touches Docker, only the generated lab files
clean:
	rm -rf lab-files
