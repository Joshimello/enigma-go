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

	res, count, _, _, err := enigma.ListKeys(dll)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(count)

	testPubKeyN := "4gFfC45bd8rHyxBNA6WjOcEI+5czvHzZulT3SGbNUX7G4klZEmsakDVi+Eu8r+I2p1/a0EDisZTObauF+hSjO4TAS7gYqmFzZZQy6WWX5ubTJj15uOQ1xLhED6ChsHxoonICvLj/PjTLmQSQKoApwbQmEALgfhyKUS2AdSXM13yVb9Tj0QVog3E7PSCSf/n3ZIHLKTb5hVVmyEDNb1GnRBAD21iVm2n6ae3hdOXFlJZCwDqqeaw8rcyv4laH99bsK/1j47SbRKi/b4Q08nmY0q9BQVMazTcPyeQeLb2SKwr4vK1Ke8rvMK62QDMeGrEbVOGcIWfa0jtVvzjWAb113w=="
	testPubKeyE := "gNZB+w=="

	res, keyID, err := enigma.ImportKey(dll, "test", testPubKeyN, testPubKeyE)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(keyID)

	res, countAfter, _, _, err := enigma.ListKeys(dll)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(countAfter)

	if countAfter != count+1 {
		t.Error("Key count did not increase")
		t.FailNow()
	}

	delRes, err := enigma.DeleteKey(dll, keyID)
	if !delRes || err != nil {
		t.Error(err)
		t.FailNow()
	}

	res, countAfter, _, _, err = enigma.ListKeys(dll)

	if countAfter != count {
		t.Error("Key count did not decrease")
		t.FailNow()
	}

	fmt.Println(countAfter)
}

func TestRSASetTransKey(t *testing.T) {
	dll := InitTestLibrary(t)

	testPubKeyN := "4gFfC45bd8rHyxBNA6WjOcEI+5czvHzZulT3SGbNUX7G4klZEmsakDVi+Eu8r+I2p1/a0EDisZTObauF+hSjO4TAS7gYqmFzZZQy6WWX5ubTJj15uOQ1xLhED6ChsHxoonICvLj/PjTLmQSQKoApwbQmEALgfhyKUS2AdSXM13yVb9Tj0QVog3E7PSCSf/n3ZIHLKTb5hVVmyEDNb1GnRBAD21iVm2n6ae3hdOXFlJZCwDqqeaw8rcyv4laH99bsK/1j47SbRKi/b4Q08nmY0q9BQVMazTcPyeQeLb2SKwr4vK1Ke8rvMK62QDMeGrEbVOGcIWfa0jtVvzjWAb113w=="
	testPubKeyE := "gNZB+w=="

	res, keyID, err := enigma.SetTransKey(dll, testPubKeyN, testPubKeyE)

	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(keyID)
}

func TestRSAData(t *testing.T) {
	dll := InitTestLibrary(t)

	testString := RandomString(190)
	fmt.Println(testString)

	res, encRes, err := enigma.RSAEncrypt(dll, "enova-00", testString)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}
	fmt.Println(encRes)

	res, decRes, err := enigma.RSADecrypt(dll, "enova-00", encRes)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}
	fmt.Println(decRes)

	if decRes != testString {
		t.Error("Decrypted string does not match original string")
		t.FailNow()
	}
}

func TestRSASign(t *testing.T) {
	dll := InitTestLibrary(t)

	testString := RandomString(256)
	fmt.Println(testString)

	res, signature, err := enigma.Sign(dll, "enova-00", testString)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}
	fmt.Println(signature)

	res, valid, err := enigma.Verify(dll, "enova-00", testString, signature)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	if !valid {
		t.Error("Signature is not valid")
		t.FailNow()
	}

	fmt.Println("Signature is valid")
}

func TestRSAResetKeys(t *testing.T) {
	dll := InitTestLibrary(t)

	res, count, _, _, err := enigma.ListKeys(dll)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(count)

	res, err = enigma.ResetKeys(dll)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	res, countAfter, _, _, err := enigma.ListKeys(dll)
	if !res || err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(countAfter)

	if countAfter != 0 {
		t.Error("Key count did not reset")
		t.FailNow()
	}
}
