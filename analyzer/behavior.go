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

type PamAuthenticateBehavior struct {
	BehaviorBase
}

func (v *PamAuthenticateBehavior) Handle(anly *Analyzer) {
	if v.Comm != "sshd" {
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
