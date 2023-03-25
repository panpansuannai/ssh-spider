package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"encoding/binary"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

func (b *bpfEventPam) GenerateSlogAttr() slog.Attr {
	return slog.Group("pam",
		slog.Group("Base",
			slog.Int64("PID", int64(b.Base.Pid)),
			slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
			slog.Int64("CPU", int64(b.Base.Cpu)),
			slog.String("Error", int8Slice2String(b.Base.ErrMsg[:]))),
		slog.String("api_name", int8Slice2String(b.ApiName[:])),
		slog.String("service_name", int8Slice2String(b.ServiceName[:])),
		slog.String("user", int8Slice2String(b.User[:])),
		slog.String("authtok", int8Slice2String(b.Authtok[:])),
		slog.String("ret", analyzer.PamRet(b.PamRet).String()),
	)
}

func (event *bpfEventPam) toBehavior() analyzer.Behavior {
	return &analyzer.PamAuthenticateBehavior{
		BehaviorBase: analyzer.BehaviorBase{
			Pid:  event.Base.Pid,
			Comm: int8Slice2String(event.Base.Comm[:]),
			Time: time.Now(),
		},
		UserName: int8Slice2String(event.User[:]),
		Authtok:  int8Slice2String(event.Authtok[:]),
		Ret:      analyzer.PamRet(event.PamRet),
	}
}

// Handle Perf Event
func pamPerfEventHandler(req *PerfMsgHandleRequest) {
	var event bpfEventPam
	// Parse the perf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return
	}
	if req.Analyzer != nil {
		req.Analyzer.Act(event.toBehavior())
	}
	// log.Printf("[%s:%d](%s) %s({service_name:%s;user:%s;authtok:%s;})=>(%s)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), int8Slice2String(event.ApiName[:]), int8Slice2String(event.ServiceName[:]), int8Slice2String(event.User[:]), int8Slice2String(event.Authtok[:]), PamRet(event.PamRet))
	slog.Debug("", event.GenerateSlogAttr())
}

func AttachLibPam(req *ProbeRequest) []link.Link {
	const pamLibPath = "/lib/x86_64-linux-gnu/libpam.so.0"
	libUtil := util.NewUProbeCollection(pamLibPath)
	probes := libUtil.AttachUProbes([]util.UProbeAttachOptions{
		{
			Symbol:     "pam_authenticate",
			IsRetProbe: false,
			Probe:      req.Objs.BeforePamAuthenticate,
		},
		{
			Symbol:     "pam_authenticate",
			IsRetProbe: true,
			Probe:      req.Objs.AfterPamAuthenticate,
		},
	})
	registerPerfMsgHandler(&PerfHandlerRegisterRequest{
		ctx:      req.Ctx,
		m:        req.Objs.EventsPam,
		analyzer: *req.Analyzer,
		handler:  pamPerfEventHandler,
	})

	return probes
}
