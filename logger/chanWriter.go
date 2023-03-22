package logger

type chanWriter struct {
	Chan chan []byte
}

func newChanWriter(size int) *chanWriter {
	return &chanWriter{
		Chan: make(chan []byte, size),
	}
}

func (c *chanWriter) Write(p []byte) (n int, err error) {
	s := make([]byte, len(p))
	copy(s, p)
	c.Chan <- s
	return len(p), nil
}
