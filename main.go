//go:build amd64

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/asaskevich/EventBus"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/exp/slog"

	"cilium-spider/analyzer"
	"cilium-spider/config"
	"cilium-spider/logger"
)

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
		})
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

	behaviorAnalyzer := analyzer.NewAnalyzer(0)
	defer behaviorAnalyzer.Stop()

	evBus := EventBus.New()

	perfCtx, perfCanceler := context.WithCancel(context.Background())
	defer perfCanceler()

	if config.UseSyscall {
		for _, p := range AttachSyscallTraceEnter(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	if config.UseLibC {
		for _, p := range AttachLibC(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	if config.UseLibPam {
		for _, p := range AttachLibPam(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	if config.UseLibUtil {
		for _, p := range AttachLibUtil(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	// Wait for a signal and close the perf reader,
	// which will interrupt rd.Read() and make the program exit.
	<-stopper
	slog.Info("received signal, exiting program..")
}
