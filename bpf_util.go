package main

import (
	"cilium-spider/analyzer"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func int8Slice2String(s []int8) string {
	uintSlice := make([]byte, 0)
	for i := range s {
		if s[i] == 0 {
			break
		}
		uintSlice = append(uintSlice, byte(s[i]))
	}
	return string(uintSlice)
}

const (
	MSG_TY_SUCCESS = iota
	MSG_TY_LOST
	MSG_TY_ERR
)

type PerfMsg struct {
	Rd    perf.Record
	MsgTy int
}

type PerfMsgHandleRequest struct {
	Msg      PerfMsg
	Analyzer *analyzer.Analyzer
}

type PerfMsgHandler func(*PerfMsgHandleRequest)

type PerfHandlerRegisterRequest struct {
	ctx      context.Context
	m        *ebpf.Map
	topic    string
	analyzer analyzer.Analyzer
	handler  PerfMsgHandler
}

func registerPerfMsgHandler(req *PerfHandlerRegisterRequest) {
	go func() {
		rd, err := perf.NewReader(req.m, os.Getpagesize())
		if err != nil {
			panic(fmt.Sprintf("creating perf event reader error: %v", err))
		}
		defer rd.Close()
		for {
			select {
			case <-req.ctx.Done():
				// Exit.
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						break
					}
					go req.handler(&PerfMsgHandleRequest{
						Msg: PerfMsg{
							Rd:    perf.Record{},
							MsgTy: MSG_TY_ERR,
						},
						Analyzer: &req.analyzer,
					})
					continue
				}

				if record.LostSamples != 0 {
					go req.handler(&PerfMsgHandleRequest{
						Msg: PerfMsg{
							Rd:    perf.Record{},
							MsgTy: MSG_TY_LOST,
						},
						Analyzer: &req.analyzer,
					})
					continue
				}
				go req.handler(&PerfMsgHandleRequest{
					Msg: PerfMsg{
						Rd:    record,
						MsgTy: MSG_TY_SUCCESS,
					},
					Analyzer: &req.analyzer,
				})
			}
		}
	}()
}
