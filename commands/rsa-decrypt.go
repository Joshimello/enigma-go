//go:build windows

package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/joshimello/enigma-go/enigma"
	"github.com/joshimello/enigma-go/types"
	"github.com/urfave/cli/v3"
)

func RSADecrypt() *cli.Command {
	return &cli.Command{
		Name:      "rsa-decrypt",
		ArgsUsage: "<key-id> <cipher>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			keyID := cmd.Args().Get(0)
			cipher := cmd.Args().Get(1)

			if keyID == "" || cipher == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Key ID and cipher are required as arguments",
					Data:    nil,
				}
				return nil
			}

			res, decryptedMessage, err := enigma.RSADecrypt(enigmaContext.DLL, keyID, cipher)
			if !res {
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
				Data:    decryptedMessage,
			}

			return nil
		},
	}
}
