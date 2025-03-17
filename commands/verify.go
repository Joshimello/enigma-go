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

func Verify() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		ArgsUsage: "<key-id> <message> <signature>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			keyID := cmd.Args().Get(0)
			message := cmd.Args().Get(1)
			signature := cmd.Args().Get(2)

			if keyID == "" || message == "" || signature == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Key ID, message, and signature are required as arguments",
					Data:    nil,
				}
				return nil
			}

			res, isValid, err := enigma.Verify(enigmaContext.DLL, keyID, message, signature)
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
				Data:    isValid,
			}

			return nil
		},
	}
}
