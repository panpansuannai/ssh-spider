package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	uprobeRefCtrOffsetPMUPath = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset"
	// elixir.bootlin.com/linux/v5.15-rc7/source/kernel/events/core.c#L9799
	uprobeRefCtrOffsetShift = 32

	// ErrNoSymbol indicates that the given symbol was not found
	// in the ELF symbols table.
	ErrNoSymbol = errors.New("not found")
)

type SafeELFFile struct {
	*elf.File
}

// NewSafeELFFile reads an ELF safely.
//
// Any panic during parsing is turned into an error. This is necessary since
// there are a bunch of unfixed bugs in debug/elf.
//
// https://github.com/golang/go/issues?q=is%3Aissue+is%3Aopen+debug%2Felf+in%3Atitle
func NewSafeELFFile(r io.ReaderAt) (safe *SafeELFFile, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

// Executable defines an executable program on the filesystem.
type Executable struct {
	// Path of the executable on the filesystem.
	path string
	// Parsed ELF and dynamic symbols' addresses.
	addresses map[string]uint64
}

// UprobeOptions defines additional parameters that will be used
// when loading Uprobes.
type UprobeOptions struct {
	// Symbol address. Must be provided in case of external symbols (shared libs).
	// If set, overrides the address eventually parsed from the executable.
	Address uint64
	// The offset relative to given symbol. Useful when tracing an arbitrary point
	// inside the frame of given symbol.
	//
	// Note: this field changed from being an absolute offset to being relative
	// to Address.
	Offset uint64
	// Only set the uprobe on the given process ID. Useful when tracing
	// shared library calls or programs that have many running instances.
	PID int
	// Automatically manage SDT reference counts (semaphores).
	//
	// If this field is set, the Kernel will increment/decrement the
	// semaphore located in the process memory at the provided address on
	// probe attach/detach.
	//
	// See also:
	// sourceware.org/systemtap/wiki/UserSpaceProbeImplementation (Semaphore Handling)
	// github.com/torvalds/linux/commit/1cc33161a83d
	// github.com/torvalds/linux/commit/a6ca88b241d5
	RefCtrOffset uint64
	// Arbitrary value that can be fetched from an eBPF program
	// via `bpf_get_attach_cookie()`.
	//
	// Needs kernel 5.15+.
	Cookie uint64
}

// To open a new Executable, use:
//
//	OpenExecutable("/bin/bash")
//
// The returned value can then be used to open Uprobe(s).
func OpenExecutable(path string) (*Executable, error) {
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file '%s': %w", path, err)
	}
	defer f.Close()

	se, err := NewSafeELFFile(f)
	if err != nil {
		return nil, fmt.Errorf("parse ELF file: %w", err)
	}

	if se.Type != elf.ET_EXEC && se.Type != elf.ET_DYN {
		// ELF is not an executable or a shared object.
		return nil, errors.New("the given file is not an executable or a shared object")
	}

	ex := Executable{
		path:      path,
		addresses: make(map[string]uint64),
	}

	if err := ex.load(se); err != nil {
		return nil, err
	}

	return &ex, nil
}

func (ex *Executable) load(f *SafeELFFile) error {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}

	syms = append(syms, dynsyms...)

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := s.Value

		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				// If the symbol value is contained in the segment, calculate
				// the symbol offset.
				//
				// fn symbol offset = fn symbol VA - .text VA + .text offset
				//
				// stackoverflow.com/a/40249502
				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}

		ex.addresses[s.Name] = address
	}

	return nil
}

// address calculates the address of a symbol in the executable.
//
// opts must not be nil.
func (ex *Executable) address(symbol string, opts *UprobeOptions) (uint64, error) {
	if opts.Address > 0 {
		return opts.Address + opts.Offset, nil
	}

	address, ok := ex.addresses[symbol]
	if !ok {
		return 0, fmt.Errorf("symbol %s: %w", symbol, ErrNoSymbol)
	}

	// Symbols with location 0 from section undef are shared library calls and
	// are relocated before the binary is executed. Dynamic linking is not
	// implemented by the library, so mark this as unsupported for now.
	//
	// Since only offset values are stored and not elf.Symbol, if the value is 0,
	// assume it's an external symbol.
	if address == 0 {
		return 0, fmt.Errorf("cannot resolve %s library call '%s'"+
			"(consider providing UprobeOptions.Address)", ex.path, symbol)
	}

	return address + opts.Offset, nil
}

// Uprobe attaches the given eBPF program to a perf event that fires when the
