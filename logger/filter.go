package logger

import (
	"cilium-spider/config"

	"golang.org/x/exp/slog"
)

type logFilter struct {
	cond map[string]string
}

func (f logFilter) Filter(record slog.Record) bool {
	ret := true
	record.Attrs(func(attr slog.Attr) {
		if v, ok := f.cond[attr.Key]; ok {
			if v != attr.Value.String() {
				ret = false
				return
			}
		}
	})
	return ret
}

func NewLogFilter(conf *config.Config) logFilter {
	return logFilter{
		cond: conf.LogFilterCond,
	}
}
