//go:build windows

package main

import (
	"fmt"
	"testing"

	"github.com/joshimello/enigma-go/enigma"
)

func TestRSAGenerateKey(t *testing.T) {
	dll := InitTestLibrary(t)

	customID := RandomString(8)
	res, keyID, pubKeyN, pubKeyE, err := enigma.GenerateKey(dll, customID)

	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(keyID)
	fmt.Println(pubKeyN)
	fmt.Println(pubKeyE)
}

func TestRSAImportKey(t *testing.T) {
	dll := InitTestLibrary(t)

	testPubKeyN := "4gFfC45bd8rHyxBNA6WjOcEI+5czvHzZulT3SGbNUX7G4klZEmsakDVi+Eu8r+I2p1/a0EDisZTObauF+hSjO4TAS7gYqmFzZZQy6WWX5ubTJj15uOQ1xLhED6ChsHxoonICvLj/PjTLmQSQKoApwbQmEALgfhyKUS2AdSXM13yVb9Tj0QVog3E7PSCSf/n3ZIHLKTb5hVVmyEDNb1GnRBAD21iVm2n6ae3hdOXFlJZCwDqqeaw8rcyv4laH99bsK/1j47SbRKi/b4Q08nmY0q9BQVMazTcPyeQeLb2SKwr4vK1Ke8rvMK62QDMeGrEbVOGcIWfa0jtVvzjWAb113w=="
	testPubKeyE := "gNZB+w=="

	res, keyID, err := enigma.ImportKey(dll, "test", testPubKeyN, testPubKeyE)

	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(keyID)
}
