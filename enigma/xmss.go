//go:build windows

package enigma

import (
	"fmt"
	"syscall"
	"unsafe"
)

func XMSSOpenHandle(dll *syscall.DLL) error {
	proc, err := dll.FindProc("MxpOpenHandle")
	if err != nil {
		return err
	}

	r1, _, _ := proc.Call()
	if r1 != 0 {
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	return nil
}

func XMSSCloseHandle(dll *syscall.DLL) error {
	proc, err := dll.FindProc("MxpCloseHandle")
	if err != nil {
		return err
	}

	r1, _, _ := proc.Call()
	if r1 != 0 {
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	return nil
}

type XMSSParam struct {
	Index      [8]byte
	XMSSID     byte
	IndexBytes byte
}

func XMSSGetParam(dll *syscall.DLL) (*XMSSParam, error) {
	proc, err := dll.FindProc("MxpGetParam")
	if err != nil {
		return nil, err
	}

	var raw struct {
		Index      [8]byte
		XMSSID     byte
		IndexBytes byte
	}

	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&raw)))
	if r1 != 0 {
		return nil, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	out := &XMSSParam{
		Index:      raw.Index,
		XMSSID:     raw.XMSSID,
		IndexBytes: raw.IndexBytes,
	}

	return out, nil
}

func XMSSKeyGen(dll *syscall.DLL, isXMSSMT byte, oid [4]byte, skeyFile string, pkeyFile string) error {
	proc, err := dll.FindProc("XmssKeyGen")
	if err != nil {
		return err
	}

	skPtr, err := syscall.BytePtrFromString(skeyFile)
	if err != nil {
		return err
	}
	pkPtr, err := syscall.BytePtrFromString(pkeyFile)
	if err != nil {
		return err
	}

	r1, _, _ := proc.Call(
		uintptr(isXMSSMT),
		uintptr(unsafe.Pointer(&oid[0])),
		uintptr(unsafe.Pointer(skPtr)),
		uintptr(unsafe.Pointer(pkPtr)),
	)
	if r1 != 0 {
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}
	return nil
}
