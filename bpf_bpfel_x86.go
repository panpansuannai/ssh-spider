// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEventAccept struct {
	Base struct {
		Pid    int32
		Comm   [16]int8
		Cpu    int32
		ErrMsg [32]int8
	}
	ListenSockfd int32
	ClientSockfd int32
}

type bpfEventGetpwnam struct {
	Base struct {
		Pid    int32
		Comm   [16]int8
		Cpu    int32
		ErrMsg [32]int8
	}
	Result struct {
		PwName   [16]int8
		PwPasswd [16]int8
		PwUid    uint32
	}
	LookingName [16]int8
	Exist       int32
}

type bpfEventGetpwuid struct {
	Base struct {
		Pid    int32
		Comm   [16]int8
		Cpu    int32
		ErrMsg [32]int8
	}
	Result struct {
		PwName   [16]int8
		PwPasswd [16]int8
		PwUid    uint32
	}
	LookingUid uint32
	Exist      int32
}

type bpfEventOpenpty struct {
	Base struct {
		Pid    int32
		Comm   [16]int8
		Cpu    int32
		ErrMsg [32]int8
	}
}

type bpfEventPam struct {
	Base struct {
		Pid    int32
		Comm   [16]int8
		Cpu    int32
		ErrMsg [32]int8
	}
	ApiName     [16]int8
	ServiceName [16]int8
	User        [16]int8
	Authtok     [16]int8
	PamRet      int32
}

type bpfEventSyscallTraceEnter struct {
	Base struct {
		Pid    int32
		Comm   [16]int8
		Cpu    int32
		ErrMsg [32]int8
	}
	SyscallNum uint64
}

type bpfPtRegs struct {
	R15     uint64
	R14     uint64
	R13     uint64
	R12     uint64
	Rbp     uint64
	Rbx     uint64
	R11     uint64
	R10     uint64
	R9      uint64
	R8      uint64
	Rax     uint64
	Rcx     uint64
	Rdx     uint64
	Rsi     uint64
	Rdi     uint64
	OrigRax uint64
	Rip     uint64
	Cs      uint64
	Eflags  uint64
	Rsp     uint64
	Ss      uint64
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	AfterAccept             *ebpf.ProgramSpec `ebpf:"after_accept"`
	AfterGetpwnam           *ebpf.ProgramSpec `ebpf:"after_getpwnam"`
	AfterGetpwnamR          *ebpf.ProgramSpec `ebpf:"after_getpwnam_r"`
	AfterGetpwuid           *ebpf.ProgramSpec `ebpf:"after_getpwuid"`
	AfterGetpwuidR          *ebpf.ProgramSpec `ebpf:"after_getpwuid_r"`
	AfterOpenpty            *ebpf.ProgramSpec `ebpf:"after_openpty"`
	AfterPamAuthenticate    *ebpf.ProgramSpec `ebpf:"after_pam_authenticate"`
	BeforeAccept            *ebpf.ProgramSpec `ebpf:"before_accept"`
	BeforeGetpwnam          *ebpf.ProgramSpec `ebpf:"before_getpwnam"`
	BeforeGetpwnamR         *ebpf.ProgramSpec `ebpf:"before_getpwnam_r"`
	BeforeGetpwuid          *ebpf.ProgramSpec `ebpf:"before_getpwuid"`
	BeforeGetpwuidR         *ebpf.ProgramSpec `ebpf:"before_getpwuid_r"`
	BeforePamAuthenticate   *ebpf.ProgramSpec `ebpf:"before_pam_authenticate"`
	BeforeSyscallTraceEnter *ebpf.ProgramSpec `ebpf:"before_syscall_trace_enter"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	EventsAccept            *ebpf.MapSpec `ebpf:"events_accept"`
	EventsGetpwnam          *ebpf.MapSpec `ebpf:"events_getpwnam"`
	EventsGetpwnamR         *ebpf.MapSpec `ebpf:"events_getpwnam_r"`
	EventsGetpwuid          *ebpf.MapSpec `ebpf:"events_getpwuid"`
	EventsGetpwuidR         *ebpf.MapSpec `ebpf:"events_getpwuid_r"`
	EventsOpenpty           *ebpf.MapSpec `ebpf:"events_openpty"`
	EventsPam               *ebpf.MapSpec `ebpf:"events_pam"`
	EventsSyscallTraceEnter *ebpf.MapSpec `ebpf:"events_syscall_trace_enter"`
	HashAccept              *ebpf.MapSpec `ebpf:"hash_accept"`
	HashGetpwnam            *ebpf.MapSpec `ebpf:"hash_getpwnam"`
	HashGetpwnamR           *ebpf.MapSpec `ebpf:"hash_getpwnam_r"`
	HashGetpwuid            *ebpf.MapSpec `ebpf:"hash_getpwuid"`
	HashGetpwuidR           *ebpf.MapSpec `ebpf:"hash_getpwuid_r"`
	HashPamAuthenticate     *ebpf.MapSpec `ebpf:"hash_pam_authenticate"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	EventsAccept            *ebpf.Map `ebpf:"events_accept"`
	EventsGetpwnam          *ebpf.Map `ebpf:"events_getpwnam"`
	EventsGetpwnamR         *ebpf.Map `ebpf:"events_getpwnam_r"`
	EventsGetpwuid          *ebpf.Map `ebpf:"events_getpwuid"`
	EventsGetpwuidR         *ebpf.Map `ebpf:"events_getpwuid_r"`
	EventsOpenpty           *ebpf.Map `ebpf:"events_openpty"`
	EventsPam               *ebpf.Map `ebpf:"events_pam"`
	EventsSyscallTraceEnter *ebpf.Map `ebpf:"events_syscall_trace_enter"`
	HashAccept              *ebpf.Map `ebpf:"hash_accept"`
	HashGetpwnam            *ebpf.Map `ebpf:"hash_getpwnam"`
	HashGetpwnamR           *ebpf.Map `ebpf:"hash_getpwnam_r"`
	HashGetpwuid            *ebpf.Map `ebpf:"hash_getpwuid"`
	HashGetpwuidR           *ebpf.Map `ebpf:"hash_getpwuid_r"`
	HashPamAuthenticate     *ebpf.Map `ebpf:"hash_pam_authenticate"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.EventsAccept,
		m.EventsGetpwnam,
		m.EventsGetpwnamR,
		m.EventsGetpwuid,
		m.EventsGetpwuidR,
		m.EventsOpenpty,
		m.EventsPam,
		m.EventsSyscallTraceEnter,
		m.HashAccept,
		m.HashGetpwnam,
		m.HashGetpwnamR,
		m.HashGetpwuid,
		m.HashGetpwuidR,
		m.HashPamAuthenticate,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	AfterAccept             *ebpf.Program `ebpf:"after_accept"`
	AfterGetpwnam           *ebpf.Program `ebpf:"after_getpwnam"`
	AfterGetpwnamR          *ebpf.Program `ebpf:"after_getpwnam_r"`
	AfterGetpwuid           *ebpf.Program `ebpf:"after_getpwuid"`
	AfterGetpwuidR          *ebpf.Program `ebpf:"after_getpwuid_r"`
	AfterOpenpty            *ebpf.Program `ebpf:"after_openpty"`
	AfterPamAuthenticate    *ebpf.Program `ebpf:"after_pam_authenticate"`
	BeforeAccept            *ebpf.Program `ebpf:"before_accept"`
	BeforeGetpwnam          *ebpf.Program `ebpf:"before_getpwnam"`
	BeforeGetpwnamR         *ebpf.Program `ebpf:"before_getpwnam_r"`
	BeforeGetpwuid          *ebpf.Program `ebpf:"before_getpwuid"`
	BeforeGetpwuidR         *ebpf.Program `ebpf:"before_getpwuid_r"`
	BeforePamAuthenticate   *ebpf.Program `ebpf:"before_pam_authenticate"`
	BeforeSyscallTraceEnter *ebpf.Program `ebpf:"before_syscall_trace_enter"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.AfterAccept,
		p.AfterGetpwnam,
		p.AfterGetpwnamR,
		p.AfterGetpwuid,
		p.AfterGetpwuidR,
		p.AfterOpenpty,
		p.AfterPamAuthenticate,
		p.BeforeAccept,
		p.BeforeGetpwnam,
		p.BeforeGetpwnamR,
		p.BeforeGetpwuid,
		p.BeforeGetpwuidR,
		p.BeforePamAuthenticate,
		p.BeforeSyscallTraceEnter,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel_x86.o
var _BpfBytes []byte
