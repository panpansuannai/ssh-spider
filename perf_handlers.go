package main

import (
	"bytes"
	"cilium-spider/analyzer"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"golang.org/x/exp/slog"
)

func getpwnamPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventGetpwnam
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing perf event error", err)
			return
		}
		// log.Printf("[%s:%d](%s) getpwnam(%s)=>(%s,%s,%d)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), int8Slice2String(event.LookingName[:]), int8Slice2String(event.Result.PwName[:]), int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("getpwnam", event.GenerateSlogAttr())
	case MSG_TY_LOST:
	case MSG_TY_ERR:
	}
}

func getpwnamRPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventGetpwnam
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing perf event error", err)
			return
		}
		// log.Printf("[%s:%d](%s) getpwnam(%s)=>(%s,%s,%d)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), int8Slice2String(event.LookingName[:]), int8Slice2String(event.Result.PwName[:]), int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("getpwnam_r", event.GenerateSlogAttr())
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
		slog.Debug("getpwuid", event.GenerateSlogAttr())
	case MSG_TY_LOST:
	case MSG_TY_ERR:
	}
}

func getpwuidRPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventGetpwuid
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}
		//log.Printf("[%s:%d](%s) getpwuid(%d)=>(%s,%s,%d)", int8Slice2String(event.Base.Comm[:]), event.Base.Pid, int8Slice2String(event.Base.ErrMsg[:]), event.LookingUid, int8Slice2String(event.Result.PwName[:]), int8Slice2String(event.Result.PwPasswd[:]), event.Result.PwUid)
		slog.Debug("getpwuid_r", event.GenerateSlogAttr())
	case MSG_TY_LOST:
	case MSG_TY_ERR:
	}
}

func openptyPerfEventHandler(req *PerfMsgHandleRequest) {
	var event bpfEventOpenpty
	// Parse the perf event entry into a bpfEvent structure.
	if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing perf event errror", err)
		return
	}
	if req.Analyzer != nil {
		req.Analyzer.Act(&analyzer.OpenptyBehavior{
			BehaviorBase: analyzer.BehaviorBase{
				Pid:  event.Base.Pid,
				Comm: int8Slice2String(event.Base.Comm[:]),
				Time: time.Now(),
			},
		})
	}
	slog.Debug("", event.GenerateSlogAttr())

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

func openPerfEventHandler(req *PerfMsgHandleRequest) {
	switch req.Msg.MsgTy {
	case MSG_TY_SUCCESS:
		var event bpfEventOpen
		if err := binary.Read(bytes.NewBuffer(req.Msg.Rd.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			return
		}
		slog.Debug("open", event.GenerateSlogAttr())
	case MSG_TY_LOST:
	case MSG_TY_ERR:
	}
}

func (b *bpfEventGetpwnam) GenerateSlogAttr() slog.Attr {
	return slog.Group("struct",
		slog.String("Event", "getpwnam"),
		slog.Int64("PID", int64(b.Base.Pid)),
		slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
		slog.Int64("CPU", int64(b.Base.Cpu)),
		slog.String("Error", int8Slice2String(b.Base.ErrMsg[:])),
		slog.String("pw_nam", int8Slice2String(b.Result.PwName[:])),
		slog.String("pw_passwd", int8Slice2String(b.Result.PwPasswd[:])),
		slog.Int64("pw_uid", int64(b.Result.PwUid)),
		slog.String("looking", int8Slice2String(b.LookingName[:])),
		slog.Int("exist", int(b.Exist)))
}

func (b *bpfEventGetpwuid) GenerateSlogAttr() slog.Attr {
	return slog.Group("struct",
		slog.String("Event", "getpwuid"),
		slog.Int64("PID", int64(b.Base.Pid)),
		slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
		slog.Int64("CPU", int64(b.Base.Cpu)),
		slog.String("Error", int8Slice2String(b.Base.ErrMsg[:])),
		slog.String("pw_nam", int8Slice2String(b.Result.PwName[:])),
		slog.String("pw_passwd", int8Slice2String(b.Result.PwPasswd[:])),
		slog.Int("pw_uid", int(b.Result.PwUid)),
		slog.Int64("looking", int64(b.LookingUid)),
		slog.Int("exist", int(b.Exist)),
	)

}

func (b *bpfEventOpenpty) GenerateSlogAttr() slog.Attr {
	return slog.Group("struct",
		slog.String("Event", "openpty"),
		slog.Int64("PID", int64(b.Base.Pid)),
		slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
		slog.Int64("CPU", int64(b.Base.Cpu)),
		slog.String("Error", int8Slice2String(b.Base.ErrMsg[:])),
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

func (b *bpfEventSyscallTraceEnter) GenerateSlogAttr(name string) slog.Attr {
	return slog.Group("struct",
		slog.String("Event", "syscall_trace_enter"),
		slog.Int64("PID", int64(b.Base.Pid)),
		slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
		slog.Int64("CPU", int64(b.Base.Cpu)),
		slog.String("Error", int8Slice2String(b.Base.ErrMsg[:])),
		slog.Int64("syscall_num", int64(b.SyscallNum)),
		slog.String("syscall_name", name),
	)
}

func (b *bpfEventPam) GenerateSlogAttr() slog.Attr {
	return slog.Group("struct",
		slog.String("Event", "pam_authenticate"),
		slog.Int64("PID", int64(b.Base.Pid)),
		slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
		slog.Int64("CPU", int64(b.Base.Cpu)),
		slog.String("Error", int8Slice2String(b.Base.ErrMsg[:])),
		slog.String("api_name", int8Slice2String(b.ApiName[:])),
		slog.String("service_name", int8Slice2String(b.ServiceName[:])),
		slog.String("user", int8Slice2String(b.User[:])),
		slog.String("authtok", int8Slice2String(b.Authtok[:])),
		slog.String("ret", analyzer.PamRet(b.PamRet).String()),
	)
}

func (b *bpfEventOpen) GenerateSlogAttr() slog.Attr {
	return slog.Group("struct",
		slog.String("Event", "open"),
		slog.Int64("PID", int64(b.Base.Pid)),
		slog.String("COMM", int8Slice2String(b.Base.Comm[:])),
		slog.Int64("CPU", int64(b.Base.Cpu)),
		slog.String("Error", int8Slice2String(b.Base.ErrMsg[:])),
		slog.String("Path", int8Slice2String(b.Path[:])),
	)
}
