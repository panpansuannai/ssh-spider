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

func main() {
	// Initialize config.
	config := config.New()

	ctx, canceler := context.WithCancel(context.Background())

	// Initizlize slog.
	logChan := logger.InitSlog(config)

	// Hanlde log output.
	HandleLogRecord(ctx, logChan)

	// Initialize cilium/bpf.
	objs := InitBPF()
	defer objs.Close()

	// Attach probes.
	probeCloser := AttachProbesFactory(ctx, config, objs)
	defer probeCloser()

	// Wait for a signal and close the perf reader,
	// which will interrupt rd.Read() and make the program exit.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	canceler()
	slog.Info("received signal, exiting program..")
}

func HandleLogRecord(ctx context.Context, logChan <-chan []byte) {
	// TODO: Handle log handler's output by recieving from chan.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-logChan:
				fmt.Println(string(msg))
			}
		}
	}()
}

func InitBPF() *bpfObjects {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(fmt.Sprintf("remove mem lock error: %s", err))
	}

	// Load pre-compiled programs and maps into the kernel.
	spec, err := loadBpf()
	if err != nil {
		panic(fmt.Sprintf("loading bpf error: %s", err))
	}
	objs := bpfObjects{}
	defer objs.Close()

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		// log.Printf("%v", spec.Programs["after_getpwnam"])
		panic(fmt.Sprintf("loading objects error: %s", err))
	}
	return &objs
}

type ProbeRequest struct {
	Ctx      context.Context
	Objs     *bpfObjects
	EvBus    EventBus.Bus
	Analyzer *analyzer.Analyzer
}

func AttachProbesFactory(ctx context.Context, config *config.Config, objs *bpfObjects) func() {
	behaviorAnalyzer := analyzer.NewAnalyzer(ctx, 0)
	evBus := EventBus.New()

	req := &ProbeRequest{
		Ctx:      ctx,
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
	}
}
