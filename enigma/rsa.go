//go:build windows

package enigma

import (
	"fmt"
	"syscall"
	"unsafe"
)

func ListKeys(dll *syscall.DLL) (bool, uint8, []string, []string, error) {
	listKeysProc, err := dll.FindProc("list_all_key_ids")
	if err != nil {
		return false, 0, nil, nil, err
	}

	var keyCount uint8
	keyIDs := make([]byte, 16*8)
	customIDs := make([]byte, 16*8)

	r1, _, _ := listKeysProc.Call(
		uintptr(unsafe.Pointer(&keyCount)),
		uintptr(unsafe.Pointer(&keyIDs[0])),
		uintptr(unsafe.Pointer(&customIDs[0])),
	)

	if r1 != 0 {
		return false, 0, nil, nil, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	keyIDList := make([]string, 0)
	customIDList := make([]string, 0)

	for i := range 16 {
		start := i * 8
		end := start + 8

		hasNonZero := false
		for j := start; j < end; j++ {
			if keyIDs[j] != 0 {
				hasNonZero = true
				break
			}
		}

		if hasNonZero {
			keyID := ""
			for j := start; j < end; j++ {
				if keyIDs[j] != 0 {
					keyID += string(rune(keyIDs[j]))
				}
			}
			keyIDList = append(keyIDList, keyID)
		}

		hasNonZero = false
		for j := start; j < end; j++ {
			if customIDs[j] != 0 {
				hasNonZero = true
				break
			}
		}

		if hasNonZero {
			customID := ""
			for j := start; j < end; j++ {
				if customIDs[j] != 0 {
					customID += string(rune(customIDs[j]))
				}
			}
			customIDList = append(customIDList, customID)
		}
	}

	return true, keyCount, keyIDList, customIDList, nil
}
