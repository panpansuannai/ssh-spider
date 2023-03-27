package main

import (
	"cilium-spider/util"

	"github.com/cilium/ebpf/link"
)

func AttachLibPam(req *ProbeRequest) []link.Link {
	const pamLibPath = "/lib/x86_64-linux-gnu/libpam.so.0"
	libUtil := util.NewUProbeCollection(pamLibPath)
	probes := libUtil.AttachUProbes([]util.UProbeAttachOptions{
		{
			Symbol:     "pam_authenticate",
			IsRetProbe: false,
			Probe:      req.Objs.BeforePamAuthenticate,
		},
		{
			Symbol:     "pam_authenticate",
			IsRetProbe: true,
			Probe:      req.Objs.AfterPamAuthenticate,
		},
	})
	registerPerfMsgHandler(&PerfHandlerRegisterRequest{
		ctx:      req.Ctx,
		m:        req.Objs.EventsPam,
		analyzer: *req.Analyzer,
		handler:  pamPerfEventHandler,
	})

	return probes
}
