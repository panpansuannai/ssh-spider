package util

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type UprobeAttachOptions struct {
	Symbol     string
	IsRetProbe bool
	Uprobe     *ebpf.Program
	Options    *link.UprobeOptions
}

type UprobeCollection struct {
	executable *link.Executable
}

func (u *UprobeCollection) AttachUProbes(m []UprobeAttachOptions) []link.Link {
	uprobes := make([]link.Link, 0, len(m))
	for _, opt := range m {
		if opt.IsRetProbe {
			if i, err := u.executable.Uretprobe(opt.Symbol, opt.Uprobe, opt.Options); err != nil {
				panic(fmt.Sprintf("creating uretprobe: %s", err))

			} else {
				uprobes = append(uprobes, i)
			}
		} else {
			if i, err := u.executable.Uprobe(opt.Symbol, opt.Uprobe, opt.Options); err != nil {
				panic(fmt.Sprintf("creating uprobe: %s", err))
			} else {
				uprobes = append(uprobes, i)
			}
		}
	}
	return uprobes
}

func NewUprobeCollection(path string) *UprobeCollection {
	e, err := link.OpenExecutable(path)
	if err != nil {
		panic(fmt.Sprintf("opening executable: %s", err))
	}
	return &UprobeCollection{
		executable: e,
	}
}
