package config

import (
	"flag"

	"golang.org/x/exp/slog"
)

type Config struct {
	UseLibPam  bool
	UseLibC    bool
	UseLibUtil bool
	UseSyscall bool
	LogSource  bool
	LogLevel   slog.Level
}

func New() *Config {
	c := Config{}
	flag.BoolVar(&c.UseLibPam, "libpam", false, "use libpam probes")
	flag.BoolVar(&c.UseLibC, "libc", false, "use libc probes")
	flag.BoolVar(&c.UseLibUtil, "libutil", false, "use libutil probes")
	flag.BoolVar(&c.UseSyscall, "syscall", false, "use syscall_trace_enter kprobes")
	flag.BoolVar(&c.LogSource, "logsource", true, "add source message to log")
	logLevel := 0
	flag.IntVar(&logLevel, "loglevel", 0, "log level [0|1|2|3]")
	flag.Parse()

	switch logLevel {
	case 0:
		c.LogLevel = slog.LevelDebug
	case 1:
		c.LogLevel = slog.LevelInfo
	case 2:
		c.LogLevel = slog.LevelWarn
	case 3:
		c.LogLevel = slog.LevelError
	default:
		c.LogLevel = slog.LevelDebug
	}
	return &c

}
