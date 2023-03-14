package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"context"
	"encoding/binary"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

func (b *bpfEventOpenpty) GenerateSlogAttr() slog.Attr {
	return slog.Group("openpty",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", util.Int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", util.Int8Slice2String(b.Base.ErrMsg[:]))),
	)
}

func openptyPerfEventHandler(a *analyzer.Analyzer, m util.PerfMsg) {
	var event bpfEventOpenpty
	// Parse the perf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(m.Rd.RawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing perf event errror", err)
		return
	}
	if a != nil {
		a.Act(&analyzer.OpenptyBehavior{
			BehaviorBase: analyzer.BehaviorBase{
				Pid:  event.Base.Pid,
				Comm: util.Int8Slice2String(event.Base.Comm[:]),
				Time: time.Now(),
			},
		})
	}
	slog.Debug("", event.GenerateSlogAttr())

}

func AttachLibUtil(ctx context.Context, objs *bpfObjects, evBus EventBus.Bus, a *analyzer.Analyzer) []link.Link {
	const utilLibPath = "/usr/lib/x86_64-linux-gnu/libutil.so"
	libUtil := util.NewUprobeCollection(utilLibPath)
	probes := libUtil.AttachUProbes([]util.UprobeAttachOptions{
		{
			Symbol:     "openpty",
			IsRetProbe: true,
			Uprobe:     objs.AfterOpenpty,
		},
	})
	evBus.Subscribe("perf:openpty", openptyPerfEventHandler)
	util.PerfHandle(ctx, objs.EventsOpenpty, evBus, "perf:openpty", a)
	return probes
}
