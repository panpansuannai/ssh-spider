package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

var syscallTable map[uint64]string = nil

func (b *bpfEventSyscallTraceEnter) GenerateSlogAttr(name string) slog.Attr {
	return slog.Group("syscall_trace_enter",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", util.Int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", util.Int8Slice2String(b.Base.ErrMsg[:]))),
		slog.Int64("syscall_num", int64(b.SyscallNum)),
		slog.String("syscall_name", name),
	)
}

func syscallTraceEnterHandler(a *analyzer.Analyzer, m util.PerfMsg) {
	// Handle only success message.
	if m.MsgTy != util.MSG_TY_SUCCESS {
		return
	}

	var event bpfEventSyscallTraceEnter
	// Parse the perf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(m.Rd.RawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing perf event error", err)
		return
	}
	base := analyzer.BehaviorBase{
		Pid:  event.Base.Pid,
		Comm: util.Int8Slice2String(event.Base.Comm[:]),
		Time: time.Now(),
	}
	syscallName, ok := syscallTable[event.SyscallNum]
	if !ok {
		slog.Debug("", event.GenerateSlogAttr(syscallName))
		a.Act(&analyzer.SyscallBehavior{
			BehaviorBase: base,
			SyscallNum:   event.SyscallNum,
			SyscallName:  syscallName,
		})
	} else {
		slog.Debug("", event.GenerateSlogAttr("unknown"))
		a.Act(&analyzer.SyscallBehavior{
			BehaviorBase: base,
			SyscallNum:   event.SyscallNum,
			SyscallName:  "Unknown",
		})
	}
}

func AttachSyscallTraceEnter(ctx context.Context, objs *bpfObjects, evBus EventBus.Bus, a *analyzer.Analyzer) []link.Link {
	table, err := util.ParseSyscallsTBLFile("./syscall_64.tbl")
	if err != nil {
		panic(fmt.Sprintf("parse syscall tbl file: %v", err))
	}
	syscallTable = table

	kp, err := link.Kprobe("syscall_trace_enter", objs.BeforeSyscallTraceEnter, nil)
	if err != nil {
		slog.Error("loading syscall_trace_enter error", err)
	}

	evBus.Subscribe("perf:syscall_trace_enter", syscallTraceEnterHandler)
	util.PerfHandle(ctx, objs.EventsSyscallTraceEnter, evBus, "perf:syscall_trace_enter", a)
	return []link.Link{kp}
}
