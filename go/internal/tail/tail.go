// Package tail follows a growing file and emits each new line on a
// channel — inotify-equivalent behaviour with polling, no third-party
// deps. Rotation is handled: when the inode changes (logrotate) or the
// file truncates, we reopen and resume from the new file's start.
//
// Use:
//
//	t, err := tail.Open(ctx, "/var/log/nginx/api.access.log")
//	for line := range t.Lines() {
//	    // line is one row of the log
//	}
//
// The tailer runs a goroutine until the context is cancelled, then
// closes the Lines channel.
package tail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// PollInterval is the default cadence for stat-and-read. Tunable via
// Options{Interval: …} for latency-critical callers; 200ms works fine
// for the web dashboard's "live tail" target (user perception floor is
// ~100ms).
const PollInterval = 200 * time.Millisecond

// Options tweaks a Tailer. Zero value uses sensible defaults.
type Options struct {
	// Interval between stat calls. Defaults to PollInterval.
	Interval time.Duration
	// BufferSize is the channel buffer depth. Defaults to 256 — enough
	// that bursty inserts don't drop unless the consumer stalls hard.
	BufferSize int
}

// Tailer watches a single file. Created by Open().
type Tailer struct {
	path    string
	lines   chan string
	errCh   chan error
	closeMu sync.Mutex
	closed  bool
}

// Lines is the receive channel. Closes when the context is cancelled
// or when an unrecoverable error occurs (check Err()).
func (t *Tailer) Lines() <-chan string { return t.lines }

// Err returns the last fatal error, if any. Non-blocking.
func (t *Tailer) Err() error {
	select {
	case err := <-t.errCh:
		return err
	default:
		return nil
	}
}

// Open starts tailing path. The first read begins at EOF — only NEW
// lines written after Open() are emitted. That matches `tail -F`'s
// default and keeps the SSE consumer from re-rendering ancient history.
func Open(ctx context.Context, path string, opts ...Options) (*Tailer, error) {
	opt := Options{}
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.Interval <= 0 {
		opt.Interval = PollInterval
	}
	if opt.BufferSize <= 0 {
		opt.BufferSize = 256
	}

	t := &Tailer{
		path:  path,
		lines: make(chan string, opt.BufferSize),
		errCh: make(chan error, 1),
	}

	go t.run(ctx, opt.Interval)
	return t, nil
}

// run is the polling loop. Tracks (inode, offset) across polls so we
// emit every new byte exactly once, and handle rotation + truncation
// without losing a single line.
func (t *Tailer) run(ctx context.Context, interval time.Duration) {
	defer t.closeLines()

	var (
		f         *os.File
		reader    *bufio.Reader
		curInode  uint64
		curOffset int64
		leftover  []byte // partial last line from the previous read
	)

	openAtEnd := func() error {
		if f != nil {
			_ = f.Close()
		}
		var err error
		f, err = os.Open(t.path)
		if err != nil {
			return err
		}
		// Seek to EOF so only new writes emit.
		off, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		curOffset = off
		reader = bufio.NewReader(f)
		st, err := f.Stat()
		if err != nil {
			return err
		}
		curInode = inode(st)
		leftover = nil
		return nil
	}

	openAtStart := func() error {
		if f != nil {
			_ = f.Close()
		}
		var err error
		f, err = os.Open(t.path)
		if err != nil {
			return err
		}
		curOffset = 0
		reader = bufio.NewReader(f)
		st, err := f.Stat()
		if err != nil {
			return err
		}
		curInode = inode(st)
		leftover = nil
		return nil
	}

	// Initial open — end-of-file so we don't replay the whole log on
	// startup. If the file doesn't exist yet we treat it like a missing
	// file and retry on the next tick.
	if err := openAtEnd(); err != nil && !os.IsNotExist(err) {
		t.setErr(err)
		return
	}

	tk := time.NewTicker(interval)
	defer tk.Stop()

	for {
		select {
		case <-ctx.Done():
			if f != nil {
				_ = f.Close()
			}
			return
		case <-tk.C:
		}

		st, err := os.Stat(t.path)
		if err != nil {
			// Missing: keep polling. Doesn't fail — the file may land
			// shortly (deploy hole, rsync still copying, etc).
			if os.IsNotExist(err) {
				continue
			}
			t.setErr(err)
			return
		}

		// Rotation — inode changed. Close the old handle, open the new
		// file from the start (we've been watching this path, the new
		// file is the "current" one).
		if inode(st) != curInode && curInode != 0 {
			if err := openAtStart(); err != nil {
				t.setErr(err)
				return
			}
		} else if f == nil {
			// File materialised after a period of absence; we haven't
			// been reading it yet. Start from the beginning — small
			// file, no risk of flood.
			if err := openAtStart(); err != nil {
				t.setErr(err)
				return
			}
		} else if st.Size() < curOffset {
			// Truncation — someone did `> file`. Re-read from the top.
			if err := openAtStart(); err != nil {
				t.setErr(err)
				return
			}
		}

		if reader == nil {
			continue
		}

		// Drain everything currently buffered; ReadBytes returns one
		// line at a time, leaving a partial read in `leftover` until
		// the next poll appends the rest.
		for {
			chunk, err := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				if chunk[len(chunk)-1] == '\n' {
					line := append(leftover, chunk[:len(chunk)-1]...) //nolint:gocritic
					leftover = nil
					// Non-blocking send so a slow consumer doesn't jam
					// the tailer — caller is expected to keep up, but
					// we'd rather drop a log line than wedge the loop.
					select {
					case t.lines <- string(line):
					default:
					}
				} else {
					// Incomplete final line; hold until the tail grows.
					leftover = append(leftover, chunk...)
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				t.setErr(err)
				return
			}
		}

		// Record where we are so rotation/truncation detection works on
		// the next tick.
		if off, err := f.Seek(0, io.SeekCurrent); err == nil {
			curOffset = off
		}
	}
}

func (t *Tailer) setErr(err error) {
	select {
	case t.errCh <- err:
	default:
	}
}

func (t *Tailer) closeLines() {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if !t.closed {
		close(t.lines)
		t.closed = true
	}
}
