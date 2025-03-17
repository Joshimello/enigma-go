//go:build windows

package enigma

import (
	"fmt"
	"syscall"
	"unsafe"
)

func Version(dll *syscall.DLL) (bool, string, error) {
	versionProc, err := dll.FindProc("MXAPIVersion")
	if err != nil {
		return false, "", err
	}

	r1, _, _ := versionProc.Call()
	if r1 == 0 {
		return false, "", fmt.Errorf("failed to get version")
	}

	var bytes []byte
	ptr := (*byte)(unsafe.Pointer(r1))
	for *ptr != 0 { // Loop until null terminator
		bytes = append(bytes, *ptr)
		ptr = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1))
	}

	version := string(bytes)
	return true, version, nil
}

func Detect(dll *syscall.DLL) (bool, error) {
	detectDeviceProc, err := dll.FindProc("mxApiDetectDev")
	if err != nil {
		return false, err
	}

	r1, _, _ := detectDeviceProc.Call()
	if r1 != 1 {
		return false, fmt.Errorf("Device not found")
	}

	return true, nil
}

func UID(dll *syscall.DLL) (bool, string, error) {
	uidProc, err := dll.FindProc("GetChipSN")
	if err != nil {
		return false, "", err
	}

	r1, _, _ := uidProc.Call()
	if r1 == 0 {
		return false, "", fmt.Errorf("failed to get UID")
	}

	var bytes [16]byte
	ptr := (*[16]byte)(unsafe.Pointer(r1))
	copy(bytes[:], ptr[:])

	uid := fmt.Sprintf("%x", bytes)
	return true, uid, nil
}
