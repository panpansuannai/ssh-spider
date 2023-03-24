package util

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type UProbeAttachOptions struct {
	Symbol     string
	IsRetProbe bool
	Probe      *ebpf.Program
	Options    *link.UprobeOptions
}

type KProbeAttachOptions struct {
	Symbol     string
	IsRetProbe bool
	Probe      *ebpf.Program
	Options    *link.KprobeOptions
}

type ProbeCollection struct {
	executable *link.Executable
}

func (u *ProbeCollection) AttachUProbes(m []UProbeAttachOptions) []link.Link {
	uprobes := make([]link.Link, 0, len(m))
	for _, opt := range m {
		if opt.IsRetProbe {
			if i, err := u.executable.Uretprobe(opt.Symbol, opt.Probe, opt.Options); err != nil {
				panic(fmt.Sprintf("creating uretprobe: %s", err))

			} else {
				uprobes = append(uprobes, i)
			}
		} else {
			if i, err := u.executable.Uprobe(opt.Symbol, opt.Probe, opt.Options); err != nil {
				panic(fmt.Sprintf("creating uprobe: %s", err))
			} else {
				uprobes = append(uprobes, i)
			}
		}
	}
	return uprobes
}

func (u *ProbeCollection) AttachKProbes(m []KProbeAttachOptions) []link.Link {
	kprobes := make([]link.Link, 0, len(m))
	for _, opt := range m {
		if opt.IsRetProbe {
			if i, err := link.Kretprobe(opt.Symbol, opt.Probe, opt.Options); err != nil {
				panic(fmt.Sprintf("creating kretprobe: %s", err))

			} else {
				kprobes = append(kprobes, i)
			}
		} else {
			if i, err := link.Kprobe(opt.Symbol, opt.Probe, opt.Options); err != nil {
				panic(fmt.Sprintf("creating kprobe: %s", err))
			} else {
				kprobes = append(kprobes, i)
			}
		}
	}
	return kprobes
}

func NewUProbeCollection(path string) *ProbeCollection {
	e, err := link.OpenExecutable(path)
	if err != nil {
		panic(fmt.Sprintf("opening executable: %s", err))
	}
	return &ProbeCollection{
		executable: e,
	}
}

func NewKProbeCollection() *ProbeCollection {
	return &ProbeCollection{
		executable: nil,
	}
}
