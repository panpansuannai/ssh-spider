package util

import (
	"cilium-spider/analyzer"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/asaskevich/EventBus"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

const (
	MSG_TY_SUCCESS = iota
	MSG_TY_LOST
	MSG_TY_ERR
)

type PerfMsg struct {
	Rd    perf.Record
	MsgTy int
}

func PerfHandle(ctx context.Context, m *ebpf.Map, evBus EventBus.Bus, topic string, a *analyzer.Analyzer) {
	go func() {
		rd, err := perf.NewReader(m, os.Getpagesize())
		if err != nil {
			panic(fmt.Sprintf("creating perf event reader error: %v", err))
		}
		defer rd.Close()
		for {
			select {
			case <-ctx.Done():
				// Exit.
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						break
					}
					evBus.Publish(topic, a, PerfMsg{
						Rd:    perf.Record{},
						MsgTy: MSG_TY_ERR,
					})
					continue
				}

				if record.LostSamples != 0 {
					evBus.Publish(topic, a, PerfMsg{
						Rd:    perf.Record{},
						MsgTy: MSG_TY_LOST,
					})
					continue
				}
				evBus.Publish(topic, a, PerfMsg{
					Rd:    record,
					MsgTy: MSG_TY_SUCCESS,
				})
			}
		}
	}()
}
