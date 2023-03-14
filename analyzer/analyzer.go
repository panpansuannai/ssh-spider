package analyzer

import (
	"time"

	"golang.org/x/exp/slog"
)

type Analyzer struct {
	behaviorChan chan Behavior
	stopper      chan struct{}
	history      []Behavior
}

func (a *Analyzer) Act(b Behavior) {
	a.behaviorChan <- b
}

func (a *Analyzer) analyze() {
	for {
		select {
		case behavior := <-a.behaviorChan:
			a.analyzeBehavior(behavior)
		case <-a.stopper:
			return
		}
	}
}

func (a *Analyzer) analyzeBehavior(behavior Behavior) {
	switch v := behavior.(type) {
	case *OpenptyBehavior:
		if v.Comm != "sshd" {
			return
		}
		if len(a.history) == 0 {
			slog.Warn("[found dangerous login]")
		} else if _, ok := a.history[len(a.history)-1].(*PamAuthenticateBehavior); !ok {
			slog.Warn("[found dangerous login]")
		} else if pam := a.history[len(a.history)-1].(*PamAuthenticateBehavior); v.Time.Sub(pam.Time) > time.Minute {
			slog.Warn("[found dangerous login]")
		} else {
			slog.Info("[normal login]")
		}
		a.history = append(a.history, v)
	case *PamAuthenticateBehavior:
		if v.Comm != "sshd" {
			return
		}
		a.history = append(a.history, v)
	case *SyscallBehavior:

	default:
		slog.Info("[Unknown behavior]")
	}
	// Drop unused history behavior.
	if len(a.history) > 100 {
		a.history = a.history[50:]
	}
}

func (a *Analyzer) Stop() {
	a.stopper <- struct{}{}
}

func NewAnalyzer(chanSize int) *Analyzer {
	a := Analyzer{
		behaviorChan: make(chan Behavior, chanSize),
		stopper:      make(chan struct{}, 0),
		history:      make([]Behavior, 0),
	}
	go func() {
		a.analyze()
	}()
	return &a
}
