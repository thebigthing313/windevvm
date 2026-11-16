package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync/atomic"

	"windevvm/internal/proxy"
)

// EventLog appends proxy events to a JSON-lines file, rotating it to
// <path>.1 when it grows past MaxBytes. Writes never block the proxy: if the
// writer falls behind, events are dropped and counted.
type EventLog struct {
	Path     string
	MaxBytes int64

	ch      chan proxy.Event
	done    chan struct{}
	dropped atomic.Int64
}

// OpenEventLog starts the background writer.
func OpenEventLog(path string, maxBytes int64) *EventLog {
	l := &EventLog{Path: path, MaxBytes: maxBytes, ch: make(chan proxy.Event, 4096), done: make(chan struct{})}
	go l.run()
	return l
}

// Write queues an event. It never blocks.
func (l *EventLog) Write(e proxy.Event) {
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

// Dropped is how many events were lost because the writer fell behind.
func (l *EventLog) Dropped() int64 { return l.dropped.Load() }

// Close flushes queued events and stops the writer.
func (l *EventLog) Close() {
	close(l.ch)
	<-l.done
}

func (l *EventLog) run() {
	defer close(l.done)
	var f *os.File
	var size int64
	limit := l.MaxBytes
	open := func() {
		var err error
		f, err = os.OpenFile(l.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			f = nil
			return
		}
		if st, err := f.Stat(); err == nil {
			size = st.Size()
		}
	}
	for e := range l.ch {
		if f == nil {
			open()
			if f == nil {
				l.dropped.Add(1)
				continue
			}
		}
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		b = append(b, '\n')
		n, _ := f.Write(b)
		size += int64(n)
		if l.MaxBytes > 0 && size > limit {
			f.Close()
			f = nil
			os.Remove(l.Path + ".1")
			if os.Rename(l.Path, l.Path+".1") != nil {
				// Probably held open by a reader. Keep appending and try
				// again after another MaxBytes, not on every event.
				limit = size + l.MaxBytes
			} else {
				limit = l.MaxBytes
			}
		}
	}
	if f != nil {
		f.Close()
	}
}

// ReadEvents returns the last n events (all if n <= 0) for vm (every VM if
// empty), oldest first, from the log and its rotated predecessor.
func ReadEvents(path, vm string, n int) ([]proxy.Event, error) {
	var out []proxy.Event
	for _, p := range []string{path + ".1", path} {
		evs, _, err := ReadFrom(p, 0, vm)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// ReadFrom reads the events in one log file starting at byte offset off,
// returning them and the offset just past the last complete line. A missing
// file has no events.
func ReadFrom(path string, off int64, vm string) ([]proxy.Event, int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, off, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() < off {
		off = 0 // rotated
	}
	if _, err := f.Seek(off, 0); err != nil {
		return nil, off, err
	}
	var out []proxy.Event
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break // a partial last line is read next time
		}
		off += int64(len(line))
		var e proxy.Event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		if vm == "" || e.VM == vm {
			out = append(out, e)
		}
	}
	return out, off, nil
}
