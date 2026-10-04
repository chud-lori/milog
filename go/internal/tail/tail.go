// Package tail follows a file by polling, like `tail -F`: when the inode
// changes or the file shrinks it reopens and reads from the start.
//
//	t, err := tail.Open(ctx, "/var/log/nginx/api.access.log")
//	for line := range t.Lines() {
//	    // line is one row of the log
//	}
//
// Lines closes when ctx is cancelled.
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

// PollInterval is the default time between stat-and-read passes.
const PollInterval = 200 * time.Millisecond

// Options tweaks a Tailer; zero values use the defaults.
type Options struct {
	// Interval between stat calls. Defaults to PollInterval.
	Interval time.Duration
	// BufferSize is the channel depth. Defaults to 256.
	BufferSize int
}

// Tailer watches one file.
type Tailer struct {
	path    string
	lines   chan string
	errCh   chan error
	closeMu sync.Mutex
	closed  bool
}

// Lines closes on cancellation or a fatal error (see Err).
func (t *Tailer) Lines() <-chan string { return t.lines }

// Err returns the last fatal error, if any.
func (t *Tailer) Err() error {
	select {
	case err := <-t.errCh:
		return err
	default:
		return nil
	}
}

// Open starts at EOF, so only lines written afterwards are emitted.
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

// run tracks inode and offset so each byte is emitted once across rotation and truncation.
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

	// Start at EOF; a missing file is retried on the next tick.
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
			// Keep polling; the file may appear later.
			if os.IsNotExist(err) {
				continue
			}
			t.setErr(err)
			return
		}

		// Rotated: read the new file from the start.
		if inode(st) != curInode && curInode != 0 {
			if err := openAtStart(); err != nil {
				t.setErr(err)
				return
			}
		} else if f == nil {
			// The file appeared after being absent: read from the start.
			if err := openAtStart(); err != nil {
				t.setErr(err)
				return
			}
		} else if st.Size() < curOffset {
			// Truncated: re-read from the top.
			if err := openAtStart(); err != nil {
				t.setErr(err)
				return
			}
		}

		if reader == nil {
			continue
		}

		// A partial last line waits in `leftover` until the next poll.
		for {
			chunk, err := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				if chunk[len(chunk)-1] == '\n' {
					line := append(leftover, chunk[:len(chunk)-1]...) //nolint:gocritic
					leftover = nil
					// Drop the line rather than block on a slow consumer.
					select {
					case t.lines <- string(line):
					default:
					}
				} else {
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
