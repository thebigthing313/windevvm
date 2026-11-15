package inject

import (
	"bytes"
	"io"
)

// replacer is a streaming find-and-replace over a reader. It holds back only
// a tail that could be the start of a pattern, so streamed responses such as
// server-sent events aren't delayed waiting for more input.
type replacer struct {
	src   io.Reader
	pats  [][]byte
	fn    func(i int) ([]byte, error) // replacement for pattern i, or an error to abort
	chunk []byte
	buf   []byte // input not yet emitted
	out   []byte // output ready to be read
	eof   bool
	err   error
}

func newReplacer(src io.Reader, pats [][]byte, fn func(int) ([]byte, error)) io.Reader {
	if len(pats) == 0 {
		return src
	}
	return &replacer{src: src, pats: pats, fn: fn, chunk: make([]byte, 32<<10)}
}

func (r *replacer) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.eof && len(r.buf) == 0 {
			return 0, io.EOF
		}
		if !r.eof {
			n, err := r.src.Read(r.chunk)
			r.buf = append(r.buf, r.chunk[:n]...)
			if err == io.EOF {
				r.eof = true
			} else if err != nil {
				r.err = err
				return 0, err
			}
		}
		if err := r.process(); err != nil {
			r.err, r.buf = err, nil
			if len(r.out) == 0 {
				return 0, err
			}
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *replacer) process() error {
	for {
		idx, which := -1, -1
		for i, p := range r.pats {
			j := bytes.Index(r.buf, p)
			if j >= 0 && (idx < 0 || j < idx || j == idx && len(p) > len(r.pats[which])) {
				idx, which = j, i
			}
		}
		if idx < 0 {
			break
		}
		if !r.eof && r.longerMayMatch(r.buf[idx:], len(r.pats[which])) {
			// A longer pattern could still match here once more input arrives.
			r.out = append(r.out, r.buf[:idx]...)
			r.buf = append(r.buf[:0], r.buf[idx:]...)
			return nil
		}
		r.out = append(r.out, r.buf[:idx]...)
		rep, err := r.fn(which)
		if err != nil {
			return err
		}
		r.out = append(r.out, rep...)
		r.buf = r.buf[idx+len(r.pats[which]):]
	}
	if r.eof {
		r.out = append(r.out, r.buf...)
		r.buf = r.buf[:0]
		return nil
	}
	keep := r.partialSuffix()
	r.out = append(r.out, r.buf[:len(r.buf)-keep]...)
	r.buf = append(r.buf[:0], r.buf[len(r.buf)-keep:]...)
	return nil
}

// longerMayMatch reports whether some pattern longer than n bytes starts with
// all of rest, so it can't be ruled out until more input arrives.
func (r *replacer) longerMayMatch(rest []byte, n int) bool {
	for _, p := range r.pats {
		if len(p) > n && len(p) > len(rest) && bytes.HasPrefix(p, rest) {
			return true
		}
	}
	return false
}

// partialSuffix returns the length of the longest tail of buf that is a
// proper prefix of some pattern.
func (r *replacer) partialSuffix() int {
	longest := 0
	for _, p := range r.pats {
		longest = max(longest, len(p)-1)
	}
	longest = min(longest, len(r.buf))
	for k := longest; k > 0; k-- {
		tail := r.buf[len(r.buf)-k:]
		for _, p := range r.pats {
			if len(p) > k && bytes.HasPrefix(p, tail) {
				return k
			}
		}
	}
	return 0
}
