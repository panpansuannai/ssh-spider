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
	LogLevel   slog.Level
}

func New() *Config {
	c := Config{}
	flag.BoolVar(&c.UseLibPam, "libpam", false, "")
	flag.BoolVar(&c.UseLibC, "libc", false, "")
	flag.BoolVar(&c.UseLibUtil, "libutil", false, "")
	flag.BoolVar(&c.UseSyscall, "syscall", false, "")
	logLevel := 0
	flag.IntVar(&logLevel, "loglevel", 0, "")
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
