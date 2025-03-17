//go:build windows

package enigma

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

func TrimLeadingZeroes(data []byte) []byte {
	for i, b := range data {
		if b != 0 {
			return data[i:]
		}
	}
	return data[len(data)-1:]
}

func GenerateKey(dll *syscall.DLL, customID string) (bool, string, string, string, error) {
	generateKeyProc, err := dll.FindProc("generate_rsa_key")
	if err != nil {
		return false, "", "", "", err
	}

	customIDBytes := make([]byte, 8)
	copy(customIDBytes, []byte(customID))

	keyID := make([]byte, 8)
	pubKeyN := make([]byte, 256)
	pubKeyE := make([]byte, 256)

	r1, _, _ := generateKeyProc.Call(
		uintptr(unsafe.Pointer(&customIDBytes[0])),
		uintptr(unsafe.Pointer(&keyID[0])),
		uintptr(unsafe.Pointer(&pubKeyN[0])),
		uintptr(unsafe.Pointer(&pubKeyE[0])),
	)

	if r1 != 0 {
		return false, "", "", "", fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	keyIDStr := string(keyID)
	pubKeyNStr := base64.StdEncoding.EncodeToString(pubKeyN)
	pubKeyEStr := base64.StdEncoding.EncodeToString(TrimLeadingZeroes(pubKeyE))

	return true, keyIDStr, pubKeyNStr, pubKeyEStr, nil
}

func ImportKey(dll *syscall.DLL, customID string, pubKeyN string, pubKeyE string) (bool, string, error) {
	importKeyProc, err := dll.FindProc("store_external_public_key")
	if err != nil {
		return false, "", err
	}

	customIDBytes := make([]byte, 8)
	copy(customIDBytes, []byte(customID))

	pubKeyNBytes, err := base64.StdEncoding.DecodeString(pubKeyN)
	if err != nil {
		return false, "", err
	}

	pubKeyEBytes, err := base64.StdEncoding.DecodeString(pubKeyE)
	if err != nil {
		return false, "", err
	}

	pubKeyNBuffer := make([]byte, 256)
	copy(pubKeyNBuffer, pubKeyNBytes)

	pubKeyEBuffer := make([]byte, 256)
	if len(pubKeyEBytes) < 256 {
		copy(pubKeyEBuffer[256-len(pubKeyEBytes):], pubKeyEBytes)
	} else {
		copy(pubKeyEBuffer, pubKeyEBytes)
	}

	keyID := make([]byte, 8)

	r1, _, _ := importKeyProc.Call(
		uintptr(unsafe.Pointer(&customIDBytes[0])),
		uintptr(unsafe.Pointer(&pubKeyNBuffer[0])),
		uintptr(unsafe.Pointer(&pubKeyEBuffer[0])),
		uintptr(unsafe.Pointer(&keyID[0])),
	)

	if r1 != 0 {
		return false, "", fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	keyIDStr := string(keyID)

	return true, keyIDStr, nil
}

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
