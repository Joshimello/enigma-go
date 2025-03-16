//go:build windows

package enigma

import (
	"syscall"
)

func Create() (*syscall.DLL, error) {
	dll, err := syscall.LoadDLL("library/EnovaMX.dll")
	if err != nil {
		return nil, err
	}
	return dll, nil
}
