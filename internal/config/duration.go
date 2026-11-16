package config

import (
	"fmt"
	"strings"
	"time"
)

// Duration is a time span written like "30m" or "2h". "off" (or "0")
// disables the setting; the zero value means "not set" (inherit).
type Duration time.Duration

// Off is how a disabled Duration is stored.
const Off Duration = -1

// UnmarshalText implements encoding.TextUnmarshaler for TOML.
func (d *Duration) UnmarshalText(b []byte) error {
	s := strings.ToLower(strings.TrimSpace(string(b)))
	if s == "off" || s == "0" || s == "never" {
		*d = Off
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return fmt.Errorf("bad duration %q (use e.g. 30m, 2h or off)", string(b))
	}
	*d = Duration(v)
	return nil
}

// Enabled reports whether the duration is set and not off.
func (d Duration) Enabled() bool { return d > 0 }

func (d Duration) String() string {
	switch {
	case d == Off:
		return "off"
	case d == 0:
		return "unset"
	}
	return time.Duration(d).String()
}
