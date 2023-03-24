package main

import (
	"bytes"
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
			slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", int8Slice2String(b.Base.ErrMsg[:]))),
		slog.Group("Result",
			slog.String("pw_nam", int8Slice2String(b.Result.PwName[:])),
			slog.String("pw_passwd", int8Slice2String(b.Result.PwPasswd[:])),
			slog.Int64("pw_uid", int64(b.Result.PwUid))),
		slog.String("looking", int8Slice2String(b.LookingName[:])),
		slog.Int("ret", int(b.Ret)),
	)
}

func (b *bpfEventGetpwuid) GenerateSlogAttr() slog.Attr {
	return slog.Group("getpwuid",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", int8Slice2String(b.Base.ErrMsg[:]))),
		slog.Group("Result",
			slog.String("pw_nam", int8Slice2String(b.Result.PwName[:])),
			slog.String("pw_passwd", int8Slice2String(b.Result.PwPasswd[:])),
			slog.Int("pw_uid", int(b.Result.PwUid))),
		slog.Int64("looking", int64(b.LookingUid)),
		slog.Int("ret", int(b.Ret)),
	)

}

func getpwnamPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventGetpwnam
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing perf event error", err)
			return
		}
		// log.Printf("[%s:%d](%s) getpwnam(%s)=>(%s,%s,%d)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), int8Slice2String(event.LookingName[:]), int8Slice2String(event.Result.PwName[:]), int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("", event.GenerateSlogAttr())
	case MSG_TY_LOST:
	case MSG_TY_ERR:
	}
}

func getpwuidPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventGetpwuid
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}
		//log.Printf("[%s:%d](%s) getpwuid(%d)=>(%s,%s,%d)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), event.LookingUid, int8Slice2String(event.Result.PwName[:]), int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("", event.GenerateSlogAttr())
	case MSG_TY_LOST:
	case MSG_TY_ERR:
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
	registerPerfMsgHandler(&PerfHandlerRegisterRequest{
		ctx:      req.Ctx,
		m:        req.Objs.EventsGetpwnam,
		analyzer: *req.Analyzer,
		handler:  getpwnamPerfEventHandler,
	})
	registerPerfMsgHandler(&PerfHandlerRegisterRequest{
		ctx:      req.Ctx,
		m:        req.Objs.EventsGetpwuid,
		analyzer: *req.Analyzer,
		handler:  getpwuidPerfEventHandler,
	})

	return probes
}
