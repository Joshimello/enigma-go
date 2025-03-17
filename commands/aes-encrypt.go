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

func AESEncrypt() *cli.Command {
	return &cli.Command{
		Name:      "aes-encrypt",
		ArgsUsage: "<plaintext>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			plaintext := cmd.Args().Get(0)
			if plaintext == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Plaintext is required as an argument",
					Data:    nil,
				}
				return nil
			}

			ciphertext, err := enigma.AESEncrypt(enigmaContext.DLL, plaintext)
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
					Data:    nil,
				}
				return nil
			}

			base64Encoded := base64.StdEncoding.EncodeToString([]byte(ciphertext))

			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: enigma.GetCodeMessage(0),
				Data:    base64Encoded,
			}

			return nil
		},
	}
}
