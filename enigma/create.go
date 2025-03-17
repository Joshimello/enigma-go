//go:build windows

package enigma

import (
	"syscall"
)

func Create(dllPath string) (*syscall.DLL, error) {
	dll, err := syscall.LoadDLL(dllPath)
	if err != nil {
		return nil, err
	}
	return dll, nil
}
