package analyzer

import (
	"context"
)

type Analyzer struct {
	ctx          context.Context
	behaviorChan chan Behavior
	history      []Behavior
}

const behaviorHistoryLength = 100

func (a *Analyzer) Act(b Behavior) {
	a.behaviorChan <- b
}

func (a *Analyzer) analyze() {
	for {
		select {
		case behavior := <-a.behaviorChan:
			a.analyzeBehavior(behavior)
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *Analyzer) analyzeBehavior(behavior Behavior) {
	behavior.Handle(a)
	// Drop unused history behavior.
	if len(a.history) >= behaviorHistoryLength-1 {
		a.history = a.history[behaviorHistoryLength/2:]
	}
}

func NewAnalyzer(ctx context.Context, chanSize int) *Analyzer {
	a := Analyzer{
		ctx:          ctx,
		behaviorChan: make(chan Behavior, chanSize),
		history:      make([]Behavior, 0, behaviorHistoryLength),
	}
	go func() {
		a.analyze()
	}()
	return &a
}
