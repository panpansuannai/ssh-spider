package analyzer

import (
	"time"

	"golang.org/x/exp/slog"
)

type Behavior interface {
	_behavior()
	Handle(*Analyzer)
}

type BehaviorBase struct {
	Pid  int32
	Comm string
	Time time.Time
}

func (_ *BehaviorBase) _behavior() {}

type OpenptyBehavior struct {
	BehaviorBase
}

func (v *OpenptyBehavior) Handle(anly *Analyzer) {
	if v.Comm != "sshd" {
		return
	}
	if len(anly.history) == 0 {
		slog.Warn("[found dangerous login]")
	} else if _, ok := anly.history[len(anly.history)-1].(*PamAuthenticateBehavior); !ok {
		slog.Warn("[found dangerous login]")
	} else if pam := anly.history[len(anly.history)-1].(*PamAuthenticateBehavior); v.Time.Sub(pam.Time) > time.Minute {
		slog.Warn("[found dangerous login]")
	} else {
		slog.Info("[normal login]")
	}
	anly.history = append(anly.history, v)
}

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

type PamAuthenticateBehavior struct {
	BehaviorBase
	UserName string
	Authtok  string
	Ret      PamRet
}

func (v *PamAuthenticateBehavior) Handle(anly *Analyzer) {
	if v.Comm != "sshd" || v.Ret.String() != "SUCCESS" {
		return
	}
	anly.history = append(anly.history, v)
}

type SyscallBehavior struct {
	BehaviorBase
	SyscallNum  uint64
	SyscallName string
}

func (_ *SyscallBehavior) Handle(anly *Analyzer) {
}

type Acceptbehavior struct {
	BehaviorBase
	ListenSockFd int32
	ClientSockFd int32
}

func (v *Acceptbehavior) Handle(anly *Analyzer) {
}
