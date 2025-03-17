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

func RSAEncrypt() *cli.Command {
	return &cli.Command{
		Name:      "rsa-encrypt",
		ArgsUsage: "<key-id> <message>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			keyID := cmd.Args().Get(0)
			message := cmd.Args().Get(1)

			if keyID == "" || message == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Key ID and message are required as arguments",
					Data:    nil,
				}
				return nil
			}

			res, encryptedMessage, err := enigma.RSAEncrypt(enigmaContext.DLL, keyID, message)
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
				Data:    encryptedMessage,
			}

			return nil
		},
	}
}
