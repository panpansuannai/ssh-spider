package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

var syscallTable map[uint64]string = nil

func (b *bpfEventSyscallTraceEnter) GenerateSlogAttr(name string) slog.Attr {
	return slog.Group("syscall_trace_enter",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", int8Slice2String(b.Base.ErrMsg[:]))),
		slog.Int64("syscall_num", int64(b.SyscallNum)),
		slog.String("syscall_name", name),
	)
}

func syscallTraceEnterHandler(req *PerfMsgHandleRequest) {
	// Handle only success message.
	if req.Msg.MsgTy != MSG_TY_SUCCESS {
		return
	}

	var event bpfEventSyscallTraceEnter
	// Parse the perf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing perf event error", err)
		return
	}
	base := analyzer.BehaviorBase{
		Pid:  event.Base.Pid,
		Comm: int8Slice2String(event.Base.Comm[:]),
		Time: time.Now(),
	}
	syscallName, ok := syscallTable[event.SyscallNum]
	if !ok {
		slog.Debug("", event.GenerateSlogAttr(syscallName))
		req.Analyzer.Act(&analyzer.SyscallBehavior{
			BehaviorBase: base,
			SyscallNum:   event.SyscallNum,
			SyscallName:  syscallName,
		})
	} else {
		slog.Debug("", event.GenerateSlogAttr("unknown"))
		req.Analyzer.Act(&analyzer.SyscallBehavior{
			BehaviorBase: base,
			SyscallNum:   event.SyscallNum,
			SyscallName:  "Unknown",
		})
	}
}

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
		topic:    "perf:syscall_trace_enter",
		analyzer: *req.Analyzer,
		handler:  syscallTraceEnterHandler,
	})
	return kps
}
