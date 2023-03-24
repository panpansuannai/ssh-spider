//go:build amd64

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/asaskevich/EventBus"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/exp/slog"

	"cilium-spider/analyzer"
	"cilium-spider/config"
	"cilium-spider/logger"
)

type ProbeRequest struct {
	Ctx      context.Context
	Objs     *bpfObjects
	EvBus    EventBus.Bus
	Analyzer *analyzer.Analyzer
}

func main() {
	// Initialize config.
	config := config.New()

	// Setup slog library.
	var logLevel = new(slog.LevelVar)
	logLevel.Set(config.LogLevel)
	h := logger.NewJSONLogHandler(
		slog.HandlerOptions{
			AddSource: config.LogSource,
			Level:     logLevel,
		}, config)
	slog.SetDefault(slog.New(h))

	// TODO: Handle log handler's output by recieving from chan.
	go func() {
		for {
			select {
			case msg := <-h.Chan():
				fmt.Println(string(msg))
			}
		}
	}()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("remove mem lock error", err)
		return
	}

	// Load pre-compiled programs and maps into the kernel.
	spec, err := loadBpf()
	if err != nil {
		slog.Error("loading bpf error", err)
		return
	}
	objs := bpfObjects{}
	defer objs.Close()

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		// log.Printf("%v", spec.Programs["after_getpwnam"])
		slog.Error("loading objects error", err)
		return
	}

	// Attach probes.
	probeCloser := AttachProbesFactory(config, &objs)
	defer probeCloser()

	// Wait for a signal and close the perf reader,
	// which will interrupt rd.Read() and make the program exit.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	slog.Info("received signal, exiting program..")
}

func AttachProbesFactory(config *config.Config, objs *bpfObjects) func() {
	behaviorAnalyzer := analyzer.NewAnalyzer(0)
	evBus := EventBus.New()
	perfCtx, perfCanceler := context.WithCancel(context.Background())

	req := &ProbeRequest{
		Ctx:      perfCtx,
		Objs:     objs,
		EvBus:    evBus,
		Analyzer: behaviorAnalyzer,
	}

	probes := make([]link.Link, 0)
	if config.UseSyscall {
		probes = append(probes, AttachSyscallTraceEnter(req)...)
	}

	if config.UseLibC {
		probes = append(probes, AttachLibC(req)...)
	}

	if config.UseLibPam {
		probes = append(probes, AttachLibPam(req)...)
	}

	if config.UseLibUtil {
		probes = append(probes, AttachLibUtil(req)...)
	}

	return func() {
		for _, p := range probes {
			p.Close()
		}
		perfCanceler()
		behaviorAnalyzer.Stop()
	}
}
