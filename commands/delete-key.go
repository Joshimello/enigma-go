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

func DeleteKey() *cli.Command {
	return &cli.Command{
		Name:      "delete-key",
		ArgsUsage: "<key-id>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			keyID := cmd.Args().Get(0)
			if keyID == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Key ID is required as an argument",
					Data:    nil,
				}
				return nil
			}

			res, err := enigma.DeleteKey(enigmaContext.DLL, keyID)
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
				Data:    nil,
			}

			return nil
		},
	}
}
