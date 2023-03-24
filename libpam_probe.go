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

type PamRet int32

func (r PamRet) String() string {
	switch r {
	case 0:
		return "SUCCESS"
	case 1:
		return "OPEN_ERR"
	case 2:
		return "SYMBOL_ERR"
	case 3:
		return "SERVICE_ERR"
	case 4:
		return "SYSTEM_ERR"
	case 5:
		return "BUF_ERR"
	case 6:
		return "PERM_DENIED"
	case 7:
		return "AUTH_ERR"
	case 8:
		return "CRED_INSUFFICIENT"
	case 9:
		return "AUTHINFO_UNAVAIL"
	case 10:
		return "USER_UNKNOWN"
	case 11:
		return "MAXTRIES"
	case 12:
		return "NEW_AUTHTOK_REQD"
	case 13:
		return "ACCT_EXPIRED"
	case 14:
		return "SESSION_ERR"
	case 15:
		return "CRED_UNAVAIL"
	case 16:
		return "CRED_EXPIRED"
	case 17:
		return "CRED_ERR"
	case 18:
		return "NO_MODULE_DATA"
	case 19:
		return "CONV_ERR"
	case 20:
		return "AUTHTOK_ERR"
	case 21:
		return "AUTHTOK_RECOVER_ERR"
	case 22:
		return "AUTHTOK_LOCK_BUSY"
	case 23:
		return "AUTHTOK_DISABLE_AGING"
	case 24:
		return "TRY_AGAIN"
	case 25:
		return "IGNORE"
	case 26:
		return "ABORT"
	case 27:
		return "AUTHTOK_EXPIRED"
	case 28:
		return "MODULE_UNKNOWN"
	case 29:
		return "BAD_ITEM"
	case 30:
		return "CONV_AGAIN"
	case 31:
		return "INCOMPLETE"
	case 32:
		return "DEFAULT"
	default:
		return "UNKNOWN"
	}
}

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
		slog.String("ret", PamRet(b.PamRet).String()),
	)
}

// Handle Perf Event
func pamPerfEventHandler(req *PerfMsgHandleRequest) {
	var event bpfEventPam
	// Parse the perf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return
	}
	if req.Analyzer != nil && PamRet(event.PamRet).String() == "SUCCESS" {
		req.Analyzer.Act(&analyzer.PamAuthenticateBehavior{
			BehaviorBase: analyzer.BehaviorBase{
				Pid:  event.Base.Pid,
				Comm: int8Slice2String(event.Base.Comm[:]),
				Time: time.Now(),
			},
		})
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
