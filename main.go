//go:build amd64

package main

import (
	"cilium-spider/analyzer"
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/exp/slog"

	"github.com/asaskevich/EventBus"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Setup slog library.
	var logLevel = new(slog.LevelVar)
	h := slog.HandlerOptions{
		// Cost more time.
		AddSource: true,
		Level:     logLevel,
	}.NewTextHandler(os.Stdout)
	slog.SetDefault(slog.New(h))
	logLevel.Set(slog.LevelDebug)

	pamProbeFlag := flag.Bool("libpam", false, "")
	cProbeFlag := flag.Bool("libc", false, "")
	utilProbeFlag := flag.Bool("libutil", false, "")
	syscallProbeFlag := flag.Bool("syscall", false, "")
	logLevelFlag := flag.Int("loglevel", 0, "")
	flag.Parse()

	switch *logLevelFlag {
	case 0:
		logLevel.Set(slog.LevelDebug)
	case 1:
		logLevel.Set(slog.LevelInfo)
	case 2:
		logLevel.Set(slog.LevelWarn)
	case 3:
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelDebug)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("remove mem lock error", err)
		return
	}

	// Load pre-compiled programs and maps into the kernel.
	spec, err := loadBpf()
	if err != nil {
		slog.Error("loading bpf error", err)
	}
	objs := bpfObjects{}
	defer objs.Close()

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		// log.Printf("%v", spec.Programs["after_getpwnam"])
		slog.Error("loading objects error", err)
	}

	evBus := EventBus.New()
	behaviorAnalyzer := analyzer.NewAnalyzer(0)
	defer behaviorAnalyzer.Stop()

	perfCtx, perfCanceler := context.WithCancel(context.Background())
	defer perfCanceler()

	if *syscallProbeFlag {
		for _, p := range AttachSyscallTraceEnter(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	if *cProbeFlag {
		for _, p := range AttachLibC(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	if *pamProbeFlag {
		for _, p := range AttachLibPam(perfCtx, &objs, evBus, behaviorAnalyzer) {
			defer p.Close()
		}
	}

	if *utilProbeFlag {
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
