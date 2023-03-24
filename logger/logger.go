package logger

import (
	"cilium-spider/config"
	"context"

	"golang.org/x/exp/slog"
)

type JSONLogHandler struct {
	slog.JSONHandler
	writer *chanWriter
	filter logFilter
}

func NewJSONLogHandler(opts slog.HandlerOptions, conf *config.Config) *JSONLogHandler {
	h := JSONLogHandler{
		writer: newChanWriter(16),
		filter: NewLogFilter(conf),
	}
	h.JSONHandler = *opts.NewJSONHandler(h.writer)
	return &h
}

func (h *JSONLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if !h.filter.Filter(record) {
		return nil
	}
	if err := h.JSONHandler.Handle(ctx, record); err != nil {
		return err
	}
	return nil
}

func (h *JSONLogHandler) Chan() chan []byte {
	return h.writer.Chan
}

func InitSlog(config *config.Config) <-chan []byte {
	// Setup slog library.
	var logLevel = new(slog.LevelVar)
	logLevel.Set(config.LogLevel)
	h := NewJSONLogHandler(
		slog.HandlerOptions{
			AddSource: config.LogSource,
			Level:     logLevel,
		}, config)
	slog.SetDefault(slog.New(h))
	return h.Chan()
}
