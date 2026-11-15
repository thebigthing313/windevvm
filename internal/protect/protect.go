// Package protect encrypts small values (secrets, the CA key) at rest.
package protect

// Protector seals and unseals small values. On Windows the default is DPAPI,
// which ties the ciphertext to the current Windows user.
type Protector interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(sealed []byte) ([]byte, error)
}

// Insecure stores values unencrypted. It is meant for tests only.
type Insecure struct{}

func (Insecure) Protect(b []byte) ([]byte, error)   { return append([]byte(nil), b...), nil }
func (Insecure) Unprotect(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
