package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"windevvm/internal/protect"
)

// ErrNotFound is returned for an unknown secret.
var ErrNotFound = errors.New("secret not found")

// Store keeps secrets on the host: metadata as <name>.json and the value
// sealed by the Protector as <name>.sealed.
type Store struct {
	Dir string
	P   protect.Protector
}

func (s *Store) metaPath(name string) string  { return filepath.Join(s.Dir, name+".json") }
func (s *Store) valuePath(name string) string { return filepath.Join(s.Dir, name+".sealed") }

// Set creates or replaces a secret.
func (s *Store) Set(sec Secret) error {
	if err := sec.Validate(); err != nil {
		return err
	}
	if len(sec.Value) == 0 {
		return fmt.Errorf("secret %s: empty value", sec.Name)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	sealed, err := s.P.Protect(sec.Value)
	if err != nil {
		return err
	}
	meta, err := json.MarshalIndent(sec, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(s.valuePath(sec.Name), sealed); err != nil {
		return err
	}
	return writeAtomic(s.metaPath(sec.Name), meta)
}

// Meta returns a secret's metadata without decrypting its value.
func (s *Store) Meta(name string) (Secret, error) {
	if err := ValidateName(name); err != nil {
		return Secret{}, err
	}
	b, err := os.ReadFile(s.metaPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return Secret{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return Secret{}, err
	}
	var sec Secret
	if err := json.Unmarshal(b, &sec); err != nil {
		return Secret{}, fmt.Errorf("secret %s: %w", name, err)
	}
	return sec, nil
}

// Get returns a secret including its decrypted value.
func (s *Store) Get(name string) (Secret, error) {
	sec, err := s.Meta(name)
	if err != nil {
		return Secret{}, err
	}
	sealed, err := os.ReadFile(s.valuePath(name))
	if err != nil {
		return Secret{}, fmt.Errorf("secret %s: %w", name, err)
	}
	if sec.Value, err = s.P.Unprotect(sealed); err != nil {
		return Secret{}, fmt.Errorf("secret %s: %w", name, err)
	}
	return sec, nil
}

// List returns all secrets' metadata, sorted by name.
func (s *Store) List() ([]Secret, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Secret
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || ValidateName(name) != nil {
			continue
		}
		sec, err := s.Meta(name)
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes a secret.
func (s *Store) Remove(name string) error {
	if _, err := s.Meta(name); err != nil {
		return err
	}
	if err := os.Remove(s.metaPath(name)); err != nil {
		return err
	}
	if err := os.Remove(s.valuePath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
