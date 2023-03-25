package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"cilium-spider/util"
	"encoding/binary"
	"fmt"
	"log"
	"time"

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

func (e *bpfEventAccept) toBehavior() analyzer.Behavior {
	return &analyzer.Acceptbehavior{
		BehaviorBase: analyzer.BehaviorBase{
			Pid:  e.Base.Pid,
			Comm: int8Slice2String(e.Base.Comm[:]),
			Time: time.Now(),
		},
		ListenSockFd: e.ListenSockfd,
		ClientSockFd: e.ClientSockfd,
	}
}

func acceptPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventAccept
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}
		if req.Analyzer != nil {
			req.Analyzer.Act(event.toBehavior())
		}
		slog.Debug(fmt.Sprintf("[%s:%d](%s) accept(%d)=>(%d)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), event.ListenSockfd, event.ClientSockfd))
	case MSG_TY_LOST:
	case MSG_TY_ERR:
	}
}

func AttachLibC(req *ProbeRequest) []link.Link {
	const cLibPath = "/usr/lib/x86_64-linux-gnu/libc.so.6"
	libC := util.NewUProbeCollection(cLibPath)
	opts := make([]util.UProbeAttachOptions, 0)
	if req.Config.UseGetpwnam {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "getpwnam",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwnam,
		},
			util.UProbeAttachOptions{
				Symbol:     "getpwnam",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwnam,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwnam_r",
				IsRetProbe: false,
				Probe:      req.Objs.BeforeGetpwnamR,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwnam_r",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwnamR,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsGetpwnam,
			analyzer: *req.Analyzer,
			handler:  getpwnamPerfEventHandler,
		})
	}
	if req.Config.UseGetpwuid {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "getpwuid",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwuid,
		},
			util.UProbeAttachOptions{
				Symbol:     "getpwuid",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwuid,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwuid_r",
				IsRetProbe: false,
				Probe:      req.Objs.BeforeGetpwuidR,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwuid_r",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwuidR,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsGetpwuid,
			analyzer: *req.Analyzer,
			handler:  getpwuidPerfEventHandler,
		})
	}
	if req.Config.UseAccept {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "accept",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeAccept,
		},
			util.UProbeAttachOptions{
				Symbol:     "accept",
				IsRetProbe: true,
				Probe:      req.Objs.AfterAccept,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsAccept,
			analyzer: *req.Analyzer,
			handler:  acceptPerfEventHandler,
		})
	}

	probes := libC.AttachUProbes(opts)
	return probes
}
