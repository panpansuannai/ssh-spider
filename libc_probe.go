package main

import (
	"cilium-spider/util"

	"github.com/cilium/ebpf/link"
)

func AttachLibC(req *ProbeRequest) []link.Link {
	const cLibPath = "/usr/lib/x86_64-linux-gnu/libc.so.6"
	libC := util.NewUProbeCollection(cLibPath)
	opts := make([]util.UProbeAttachOptions, 0)
	if req.Config.UseGetpwnam {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "getpwnam",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwnam,
		},
			util.UProbeAttachOptions{
				Symbol:     "getpwnam",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwnam,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwnam_r",
				IsRetProbe: false,
				Probe:      req.Objs.BeforeGetpwnamR,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwnam_r",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwnamR,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsGetpwnam,
			analyzer: *req.Analyzer,
			handler:  getpwnamPerfEventHandler,
		})
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsGetpwnamR,
			analyzer: *req.Analyzer,
			handler:  getpwnamRPerfEventHandler,
		})
	}
	if req.Config.UseGetpwuid {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "getpwuid",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeGetpwuid,
		},
			util.UProbeAttachOptions{
				Symbol:     "getpwuid",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwuid,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwuid_r",
				IsRetProbe: false,
				Probe:      req.Objs.BeforeGetpwuidR,
			},
			util.UProbeAttachOptions{
				Symbol:     "getpwuid_r",
				IsRetProbe: true,
				Probe:      req.Objs.AfterGetpwuidR,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsGetpwuid,
			analyzer: *req.Analyzer,
			handler:  getpwuidPerfEventHandler,
		})
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsGetpwuidR,
			analyzer: *req.Analyzer,
			handler:  getpwuidRPerfEventHandler,
		})
	}
	if req.Config.UseAccept {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "accept",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeAccept,
		},
			util.UProbeAttachOptions{
				Symbol:     "accept",
				IsRetProbe: true,
				Probe:      req.Objs.AfterAccept,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsAccept,
			analyzer: *req.Analyzer,
			handler:  acceptPerfEventHandler,
		})
	}
	if req.Config.UseOpen {
		opts = append(opts, util.UProbeAttachOptions{
			Symbol:     "open",
			IsRetProbe: false,
			Probe:      req.Objs.BeforeOpen,
		},
			util.UProbeAttachOptions{
				Symbol:     "open",
				IsRetProbe: true,
				Probe:      req.Objs.AfterOpen,
			},
			util.UProbeAttachOptions{
				Symbol:     "openat",
				IsRetProbe: false,
				Probe:      req.Objs.BeforeOpenat,
			},
			util.UProbeAttachOptions{
				Symbol:     "openat",
				IsRetProbe: true,
				Probe:      req.Objs.AfterOpenat,
			},
		)
		registerPerfMsgHandler(&PerfHandlerRegisterRequest{
			ctx:      req.Ctx,
			m:        req.Objs.EventsOpen,
			analyzer: *req.Analyzer,
			handler:  openPerfEventHandler,
		})
	}

	probes := libC.AttachUProbes(opts)
	return probes
}
