package logger

import (
	"context"

	"golang.org/x/exp/slog"
)

type JSONLogHandler struct {
	slog.JSONHandler
	writer *chanWriter
}

func NewJSONLogHandler(opts slog.HandlerOptions) *JSONLogHandler {
	h := JSONLogHandler{
		writer: newChanWriter(16),
	}
	h.JSONHandler = *opts.NewJSONHandler(h.writer)
	return &h
}

func (h *JSONLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if err := h.JSONHandler.Handle(ctx, record); err != nil {
		return err
	}
	return nil
}

func (h *JSONLogHandler) Chan() chan []byte {
	return h.writer.Chan
}
