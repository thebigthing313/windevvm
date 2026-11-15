package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Size is a byte count written like "4GB" or "512MB" (binary units: 1GB = 1024MB).
type Size int64

var units = []struct {
	suffix string
	mult   int64
}{
	{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
	{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10},
	{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10},
	{"B", 1},
}

// ParseSize parses "4GB", "1.5G", "512MB" or a plain byte count.
func ParseSize(s string) (Size, error) {
	t := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if t == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(t, u.suffix) {
			t, mult = strings.TrimSuffix(t, u.suffix), u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("bad size %q (use e.g. 4GB or 512MB)", s)
	}
	return Size(f * float64(mult)), nil
}

func (s *Size) UnmarshalText(b []byte) error {
	v, err := ParseSize(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

func (s Size) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// String formats the size with the largest exact-ish unit.
func (s Size) String() string {
	v := int64(s)
	switch {
	case v >= 1<<40 && v%(1<<30) == 0:
		return trim(float64(v)/(1<<40)) + "TB"
	case v >= 1<<30:
		return trim(float64(v)/(1<<30)) + "GB"
	case v >= 1<<20:
		return trim(float64(v)/(1<<20)) + "MB"
	case v >= 1<<10:
		return trim(float64(v)/(1<<10)) + "KB"
	}
	return strconv.FormatInt(v, 10) + "B"
}

func trim(f float64) string {
	return strings.TrimSuffix(strings.TrimRight(strconv.FormatFloat(f, 'f', 1, 64), "0"), ".")
}
