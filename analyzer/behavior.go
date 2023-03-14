package analyzer

import "time"

type Behavior interface {
	Behavior()
}

type BehaviorBase struct {
	Pid  int32
	Comm string
	Time time.Time
}

func (_ *BehaviorBase) Behavior() {}

type OpenptyBehavior struct {
	BehaviorBase
}

type PamAuthenticateBehavior OpenptyBehavior

type SyscallBehavior struct {
	BehaviorBase
	SyscallNum  uint64
	SyscallName string
}
