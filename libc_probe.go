package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

func (b *bpfEventGetpwnam) GenerateSlogAttr() slog.Attr {
	return slog.Group("getpwnam",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", util.Int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", util.Int8Slice2String(b.Base.ErrMsg[:]))),
		slog.Group("Result",
			slog.String("pw_nam", util.Int8Slice2String(b.Result.PwName[:])),
			slog.String("pw_passwd", util.Int8Slice2String(b.Result.PwPasswd[:])),
			slog.Int64("pw_uid", int64(b.Result.PwUid))),
		slog.String("looking", util.Int8Slice2String(b.LookingName[:])),
		slog.Int("ret", int(b.Ret)),
	)
}

func (b *bpfEventGetpwuid) GenerateSlogAttr() slog.Attr {
	return slog.Group("getpwuid",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", util.Int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", util.Int8Slice2String(b.Base.ErrMsg[:]))),
		slog.Group("Result",
			slog.String("pw_nam", util.Int8Slice2String(b.Result.PwName[:])),
			slog.String("pw_passwd", util.Int8Slice2String(b.Result.PwPasswd[:])),
			slog.Int("pw_uid", int(b.Result.PwUid))),
		slog.Int64("looking", int64(b.LookingUid)),
		slog.Int("ret", int(b.Ret)),
	)

}

func getpwnamPerfEventHandler(a *analyzer.Analyzer, m util.PerfMsg) {
	switch m.MsgTy {
	case util.MSG_TY_SUCCESS:
		var event bpfEventGetpwnam
		if err := binary.Read(bytes.NewBuffer(m.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing perf event error", err)
			return
		}
		// log.Printf("[%s:%d](%s) getpwnam(%s)=>(%s,%s,%d)", util.Int8Slice2String(event.Base.Comm[:]), event.Base.Pid, util.Int8Slice2String(event.Base.ErrMsg[:]), util.Int8Slice2String(event.LookingName[:]), util.Int8Slice2String(event.Result.PwName[:]), util.Int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("", event.GenerateSlogAttr())
	case util.MSG_TY_LOST:
	case util.MSG_TY_ERR:
	}
}

func getpwuidPerfEventHandler(a *analyzer.Analyzer, m util.PerfMsg) {
	switch m.MsgTy {
	case util.MSG_TY_SUCCESS:
		var event bpfEventGetpwuid
		if err := binary.Read(bytes.NewBuffer(m.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}
		//log.Printf("[%s:%d](%s) getpwuid(%d)=>(%s,%s,%d)", util.Int8Slice2String(event.Base.Comm[:]), event.Base.Pid, util.Int8Slice2String(event.Base.ErrMsg[:]), event.LookingUid, util.Int8Slice2String(event.Result.PwName[:]), util.Int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("", event.GenerateSlogAttr())
	case util.MSG_TY_LOST:
	case util.MSG_TY_ERR:
	}
}

func AttachLibC(req *ProbeRequest) []link.Link {
	const cLibPath = "/usr/lib/x86_64-linux-gnu/libc.so.6"
	libC := util.NewUProbeCollection(cLibPath)
	probes := libC.AttachUProbes([]util.UProbeAttachOptions{
		{
			Symbol:     "getpwnam",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwnam,
		},
		{
			Symbol:     "getpwnam",
			IsRetProbe: true,
			Probe:      req.Objs.AfterGetpwnam,
		},
		{
			Symbol:     "getpwnam_r",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwnamR,
		},
		{
			Symbol:     "getpwnam_r",
			IsRetProbe: true,
			Probe:      req.Objs.AfterGetpwnamR,
		},
		{
			Symbol:     "getpwuid",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwuid,
		},
		{
			Symbol:     "getpwuid",
			IsRetProbe: true,
			Probe:      req.Objs.AfterGetpwuid,
		},
		{
			Symbol:     "getpwuid_r",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwuidR,
		},
		{
			Symbol:     "getpwuid_r",
			IsRetProbe: true,
			Probe:      req.Objs.AfterGetpwuidR,
		},
	})

	req.EvBus.Subscribe("perf:getpwnam", getpwnamPerfEventHandler)
	req.EvBus.Subscribe("perf:getpwuid", getpwuidPerfEventHandler)
	util.PerfHandle(req.Ctx, req.Objs.EventsGetpwnam, req.EvBus, "perf:getpwnam", req.Analyzer)
	util.PerfHandle(req.Ctx, req.Objs.EventsGetpwuid, req.EvBus, "perf:getpwuid", req.Analyzer)
	return probes
}
