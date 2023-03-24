package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"encoding/binary"
	"time"

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

func AttachLibUtil(req *ProbeRequest) []link.Link {
	const utilLibPath = "/usr/lib/x86_64-linux-gnu/libutil.so"
	libUtil := util.NewUProbeCollection(utilLibPath)
	probes := libUtil.AttachUProbes([]util.UProbeAttachOptions{
		{
			Symbol:     "openpty",
			IsRetProbe: true,
			Probe:      req.Objs.AfterOpenpty,
		},
	})
	req.EvBus.Subscribe("perf:openpty", openptyPerfEventHandler)
	util.PerfHandle(req.Ctx, req.Objs.EventsOpenpty, req.EvBus, "perf:openpty", req.Analyzer)
	return probes
}
