package main

import (
	"cilium-spider/util"
	"fmt"

	"github.com/cilium/ebpf/link"
)

var syscallTable map[uint64]string = nil

func AttachSyscallTraceEnter(req *ProbeRequest) []link.Link {
	// Generate system call table, map system call number to system call name.
	table, err := util.ParseSyscallsTBLFile("./syscall_64.tbl")
	if err != nil {
		panic(fmt.Sprintf("parse syscall tbl file: %v", err))
	}
	syscallTable = table

	kps := util.NewKProbeCollection().AttachKProbes([]util.KProbeAttachOptions{
		{
			Symbol:     "syscall_trace_enter",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeSyscallTraceEnter,
		},
	})
	registerPerfMsgHandler(&PerfHandlerRegisterRequest{
		ctx:      req.Ctx,
		m:        req.Objs.EventsSyscallTraceEnter,
		analyzer: *req.Analyzer,
		handler:  syscallTraceEnterHandler,
	})
	return kps
}
