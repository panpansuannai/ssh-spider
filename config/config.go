package config

import (
	"errors"
	"flag"
	"strings"

	"golang.org/x/exp/slog"
)

type Config struct {
	UseLibPam bool
	// Libc
	UseGetpwnam bool
	UseGetpwuid bool
	UseAccept   bool

	UseLibUtil    bool
	UseSyscall    bool
	LogSource     bool
	LogLevel      slog.Level
	LogFilterCond map[string]string
}

func New() *Config {
	c := Config{}
	flag.BoolVar(&c.UseLibPam, "libpam", false, "use libpam probes")
	flag.BoolVar(&c.UseGetpwnam, "getpwnam", false, "use getpwnam probe")
	flag.BoolVar(&c.UseGetpwuid, "getpwuid", false, "use getpwuid probe")
	flag.BoolVar(&c.UseAccept, "accept", false, "use accept probe")
	flag.BoolVar(&c.UseLibUtil, "libutil", false, "use libutil probes")
	flag.BoolVar(&c.UseSyscall, "syscall", false, "use syscall_trace_enter kprobes")
	flag.BoolVar(&c.LogSource, "logsource", true, "add source message to log")
	// Logger filter condition.
	flag.Func("filter", "filter log [-filter COMM:sshd]", func(s string) error {
		ind := strings.Index(s, ":")
		if ind == -1 {
			return errors.New("error")
		}
		name := s[:ind]
		val := s[ind+1:]
		if len(name) == 0 || len(val) == 0 {
			return errors.New("error")
		}
		c.LogFilterCond[name] = val
		return nil
	})
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
