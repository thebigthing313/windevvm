package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"windevvm/internal/protect"
)

func TestPlaceholder(t *testing.T) {
	a, err := NewPlaceholder("GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewPlaceholder("GITHUB_TOKEN")
	if a == b {
		t.Fatal("placeholders must be unique")
	}
	if !regexp.MustCompile(`^wdvm_ph_GITHUB_TOKEN_[0-9a-f]{32}$`).MatchString(a) {
		t.Fatalf("unexpected placeholder format %q", a)
	}
	if _, err := NewPlaceholder("bad-name"); err == nil {
		t.Fatal("expected an error for an invalid name")
	}
}

func TestAllows(t *testing.T) {
	s := Secret{Name: "X", Hosts: []string{"a.test"}}
	if !s.Allows(InHeader) || s.Allows(InBody) || s.Allows(InURL) {
		t.Error("default must be headers only")
	}
	s.In = []Location{InBody}
	if s.Allows(InHeader) || !s.Allows(InBody) {
		t.Error("explicit locations must replace the default")
	}
}

func TestValidate(t *testing.T) {
	bad := []Secret{
		{Name: "1X", Hosts: []string{"a.test"}},
		{Name: "X"},
		{Name: "X", Hosts: []string{"bad host"}},
		{Name: "X", Hosts: []string{"a.test"}, In: []Location{"cookie"}},
	}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("Validate(%+v): expected an error", s)
		}
	}
}

func TestStore(t *testing.T) {
	dir := t.TempDir()
	st := &Store{Dir: dir, P: protect.Default()}
	in := Secret{Name: "GITHUB_TOKEN", Hosts: []string{"api.github.com"}, Value: []byte("ghp_supersecret")}
	if err := st.Set(in); err != nil {
		t.Fatal(err)
	}

	meta, err := os.ReadFile(filepath.Join(dir, "GITHUB_TOKEN.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(meta), "supersecret") {
		t.Fatal("metadata file contains the value")
	}
	sealed, _ := os.ReadFile(filepath.Join(dir, "GITHUB_TOKEN.sealed"))
	if strings.Contains(string(sealed), "supersecret") {
		t.Fatal("sealed file contains the plaintext value")
	}

	got, err := st.Get("GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value) != "ghp_supersecret" || got.Hosts[0] != "api.github.com" {
		t.Fatalf("Get = %+v", got)
	}

	list, err := st.List()
	if err != nil || len(list) != 1 || list[0].Value != nil {
		t.Fatalf("List = %+v, %v", list, err)
	}

	if err := st.Remove("GITHUB_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("GITHUB_TOKEN"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Remove: %v", err)
	}
}

func TestStoreRejectsEmptyValue(t *testing.T) {
	st := &Store{Dir: t.TempDir(), P: protect.Insecure{}}
	if err := st.Set(Secret{Name: "X", Hosts: []string{"a.test"}}); err == nil {
		t.Fatal("expected an error for an empty value")
	}
}
