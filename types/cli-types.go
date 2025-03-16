//go:build windows

package types

import "syscall"

type EnigmaResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type EnigmaContext struct {
	DLL    *syscall.DLL
	Result *EnigmaResponse
}
