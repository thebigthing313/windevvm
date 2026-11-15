//go:build !windows

package protect

// Default returns the platform's Protector. windevvm targets Windows; other
// platforms only build for development and get no encryption at rest.
func Default() Protector { return Insecure{} }
