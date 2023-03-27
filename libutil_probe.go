package main

import (
	"cilium-spider/util"

	"github.com/cilium/ebpf/link"
)

func AttachLibUtil(req *ProbeRequest) []link.Link {
	const utilLibPath = "/usr/lib/x86_64-linux-gnu/libutil.so"
	libUtil := util.NewUProbeCollection(utilLibPath)
	probes := libUtil.AttachUProbes([]util.UProbeAttachOptions{
		{
			Symbol:     "openpty",
			IsRetProbe: true,
			Probe:      req.Objs.AfterOpenpty,
		},
	})

	registerPerfMsgHandler(&PerfHandlerRegisterRequest{
		ctx:      req.Ctx,
		m:        req.Objs.EventsOpenpty,
		analyzer: *req.Analyzer,
		handler:  openptyPerfEventHandler,
	})
	return probes
}
