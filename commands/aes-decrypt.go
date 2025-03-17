//go:build windows

package commands

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/joshimello/enigma-go/enigma"
	"github.com/joshimello/enigma-go/types"
	"github.com/urfave/cli/v3"
)

func AESDecrypt() *cli.Command {
	return &cli.Command{
		Name:      "aes-decrypt",
		ArgsUsage: "<base64-encoded-ciphertext>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			base64Ciphertext := cmd.Args().Get(0)
			if base64Ciphertext == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Base64 encoded ciphertext is required as an argument",
					Data:    nil,
				}
				return nil
			}

			ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Invalid base64 encoding: " + err.Error(),
					Data:    nil,
				}
				return nil
			}

			plaintext, err := enigma.AESDecrypt(enigmaContext.DLL, string(ciphertext))
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
					Data:    nil,
				}
				return nil
			}

			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: enigma.GetCodeMessage(0),
				Data:    plaintext,
			}

			return nil
		},
	}
}
