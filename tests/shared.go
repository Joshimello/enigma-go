//go:build windows

package main

import (
	"math/rand"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/joshimello/enigma-go/enigma"
)

func InitTestLibrary(t *testing.T) *syscall.DLL {
	dll, err := enigma.Create("../library/EnovaMX.dll")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	detectRes, err := enigma.Detect(dll)
	if !detectRes || err != nil {
		t.Error(err)
		t.FailNow()
	}

	loginRes, err := enigma.Login(dll, "000000")
	if !loginRes || err != nil {
		t.Error(err)
		t.FailNow()
	}

	return dll
}

func RandomString(length int) string {
	bytes := make([]byte, length)
	const minRune = 0x4E00
	const maxRune = 0x9FFF
	for i := 0; i < length; {
		r := rune(rand.Intn(maxRune-minRune+1) + minRune)
		if utf8.ValidRune(r) {
			count := utf8.RuneLen(r)
			if i+count <= length {
				utf8.EncodeRune(bytes[i:], r)
				i += count
			} else {
				break
			}
		}
	}
	return string(bytes[:length])
}
