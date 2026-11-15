//go:build windows

package protect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// entropy is mixed into every DPAPI call so that other programs running as
// the same user can't unseal windevvm's values with a plain DPAPI call.
var entropy = []byte("windevvm/protect/v1")

// DPAPI seals values with the Windows Data Protection API in the scope of the
// current user.
type DPAPI struct{}

// Default returns the platform's Protector.
func Default() Protector { return DPAPI{} }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func (DPAPI) Protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(blob(plain), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, fmt.Errorf("dpapi protect: %w", err)
	}
	return takeBlob(&out), nil
}

func (DPAPI) Unprotect(sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptUnprotectData(blob(sealed), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, fmt.Errorf("dpapi unprotect: %w", err)
	}
	return takeBlob(&out), nil
}
