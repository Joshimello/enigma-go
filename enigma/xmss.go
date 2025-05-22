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

	err = XMSSOpenHandle(dll)
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
		XMSSCloseHandle(dll) // Close handle even on error
		return nil, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	out := &XMSSParam{
		Index:      raw.Index,
		XMSSID:     raw.XMSSID,
		IndexBytes: raw.IndexBytes,
	}

	err = XMSSCloseHandle(dll)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func XMSSKeyGen(dll *syscall.DLL, isXMSSMT bool, oidStr string, skeyFile string, pkeyFile string) error {
	proc, err := dll.FindProc("XmssKeyGen")
	if err != nil {
		return err
	}

	err = XMSSOpenHandle(dll)
	if err != nil {
		return err
	}

	oidPtr, err := syscall.BytePtrFromString(oidStr)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}
	skPtr, err := syscall.BytePtrFromString(skeyFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}
	pkPtr, err := syscall.BytePtrFromString(pkeyFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}

	fmt.Println(oidPtr)

	var isXMSSMTByte byte
	if isXMSSMT {
		isXMSSMTByte = 1
	}
	
	r1, _, _ := proc.Call(
		uintptr(isXMSSMTByte),
		uintptr(unsafe.Pointer(oidPtr)),
		uintptr(unsafe.Pointer(skPtr)),
		uintptr(unsafe.Pointer(pkPtr)),
	)
	if r1 != 0 {
		fmt.Println("Error in XMSSKeyGen")
		fmt.Println(uint8(r1))
		XMSSCloseHandle(dll) // Close handle even on error
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	err = XMSSCloseHandle(dll)
	if err != nil {
		return err
	}

	return nil
}

func XMSSSign(dll *syscall.DLL, skeyFile, msgFile, sigFile string) error {
	proc, err := dll.FindProc("XmssSign")
	if err != nil {
		return err
	}

	err = XMSSOpenHandle(dll)
	if err != nil {
		return err
	}

	skPtr, err := syscall.BytePtrFromString(skeyFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}
	msgPtr, err := syscall.BytePtrFromString(msgFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}
	sigPtr, err := syscall.BytePtrFromString(sigFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}

	r1, _, _ := proc.Call(
		uintptr(unsafe.Pointer(skPtr)),
		uintptr(unsafe.Pointer(msgPtr)),
		uintptr(unsafe.Pointer(sigPtr)),
	)
	if r1 != 0 {
		XMSSCloseHandle(dll) // Close handle even on error
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}
	
	err = XMSSCloseHandle(dll)
	if err != nil {
		return err
	}
	
	return nil
}

func XMSSVerify(dll *syscall.DLL, pkeyFile, sigFile string) error {
	proc, err := dll.FindProc("XmssVerify")
	if err != nil {
		return err
	}

	err = XMSSOpenHandle(dll)
	if err != nil {
		return err
	}

	pkPtr, err := syscall.BytePtrFromString(pkeyFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}
	sigPtr, err := syscall.BytePtrFromString(sigFile)
	if err != nil {
		XMSSCloseHandle(dll) // Close handle even on error
		return err
	}

	r1, _, _ := proc.Call(
		uintptr(unsafe.Pointer(pkPtr)),
		uintptr(unsafe.Pointer(sigPtr)),
	)
	if r1 != 0 {
		XMSSCloseHandle(dll) // Close handle even on error
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}
	
	err = XMSSCloseHandle(dll)
	if err != nil {
		return err
	}
	
	return nil
}
