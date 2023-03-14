package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"context"
	"encoding/binary"
	"log"

	"github.com/asaskevich/EventBus"
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

func AttachLibC(ctx context.Context, objs *bpfObjects, evBus EventBus.Bus, a *analyzer.Analyzer) []link.Link {
	const cLibPath = "/usr/lib/x86_64-linux-gnu/libc.so.6"
	libC := util.NewUprobeCollection(cLibPath)
	probes := libC.AttachUProbes([]util.UprobeAttachOptions{
		{
			Symbol:     "getpwnam",
			IsRetProbe: false,
			Uprobe:     objs.BeforeGetpwnam,
		},
		{
			Symbol:     "getpwnam",
			IsRetProbe: true,
			Uprobe:     objs.AfterGetpwnam,
		},
		{
			Symbol:     "getpwnam_r",
			IsRetProbe: false,
			Uprobe:     objs.BeforeGetpwnamR,
		},
		{
			Symbol:     "getpwnam_r",
			IsRetProbe: true,
			Uprobe:     objs.AfterGetpwnamR,
		},
		{
			Symbol:     "getpwuid",
			IsRetProbe: false,
			Uprobe:     objs.BeforeGetpwuid,
		},
		{
			Symbol:     "getpwuid",
			IsRetProbe: true,
			Uprobe:     objs.AfterGetpwuid,
		},
		{
			Symbol:     "getpwuid_r",
			IsRetProbe: false,
			Uprobe:     objs.BeforeGetpwuidR,
		},
		{
			Symbol:     "getpwuid_r",
			IsRetProbe: true,
			Uprobe:     objs.AfterGetpwuidR,
		},
	})

	evBus.Subscribe("perf:getpwnam", getpwnamPerfEventHandler)
	evBus.Subscribe("perf:getpwuid", getpwuidPerfEventHandler)
	util.PerfHandle(ctx, objs.EventsGetpwnam, evBus, "perf:getpwnam", a)
	util.PerfHandle(ctx, objs.EventsGetpwuid, evBus, "perf:getpwuid", a)
	return probes
}
