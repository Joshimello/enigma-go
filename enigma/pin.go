//go:build windows

package enigma

import (
	"fmt"
	"syscall"
	"unsafe"
)

type RETStatus struct {
	Result                byte
	RetryCountLeftIsValid byte
	RetryCountLeft        byte
	Reserved              byte
}

func LoginStatus(dll *syscall.DLL) (bool, int, bool, error) {
	loginStatusProc, err := dll.FindProc("CheckLoginStatus")
	if err != nil {
		return false, 0, false, err
	}

	r1, _, _ := loginStatusProc.Call()
	if r1 == 0 {
		return false, 0, false, fmt.Errorf("Failed to check login status")
	}

	var status RETStatus
	*(*uint32)(unsafe.Pointer(&status)) = uint32(r1)

	if status.Result != 0 {
		return false, int(status.RetryCountLeft), status.RetryCountLeftIsValid == 1, fmt.Errorf("%s", GetCodeMessage(status.Result))
	}

	if status.RetryCountLeftIsValid != 0 && status.RetryCountLeft == 0 {
		return false, int(status.RetryCountLeft), status.RetryCountLeftIsValid == 1, fmt.Errorf("%s", GetCodeMessage(0x35))
	}

	return true, int(status.RetryCountLeft), status.RetryCountLeftIsValid == 1, nil
}

func Login(dll *syscall.DLL, pin string) (bool, error) {
	loginProc, err := dll.FindProc("mxLoginPIN")
	if err != nil {
		return false, err
	}

	pinBytes := append([]byte(pin), 0)

	r1, _, _ := loginProc.Call(uintptr(unsafe.Pointer(&pinBytes[0])))

	if r1 != 0 {
		return false, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	return true, nil
}
