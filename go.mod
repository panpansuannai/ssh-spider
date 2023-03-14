module cilium-spider

go 1.18

require (
	github.com/asaskevich/EventBus v0.0.0-20200907212545-49d423059eef
	github.com/cilium/ebpf v0.10.0
	golang.org/x/exp v0.0.0-20230310171629-522b1b587ee0
)

require golang.org/x/sys v0.2.0 // indirect

replace github.com/cilium/ebpf => ./external/ebpf
