package = main
types = -type event_getpwnam -type event_getpwuid -type event_openpty -type event_pam -type event_syscall_trace_enter -type event_accept


all: generate cilium-spider

macos-generate:
	GOPACKAGE=$(package) go run github.com/cilium/ebpf/cmd/bpf2go -cc /opt/local/libexec/llvm-15/bin/clang -cflags= $(types) -target amd64 bpf bpf-c/bpf_main.c

generate:
	GOPACKAGE=$(package) go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags= $(types) -target amd64 bpf bpf-c/bpf_main.c

cilium-spider: bpf_bpfel_x86.go
	@go build

tools: 
	cd bpftools/checksym && go build .

run: cilium-spider
	@echo "Runinig"
	@sudo ./cilium-spider
