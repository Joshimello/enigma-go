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

func ChangePin() *cli.Command {
	return &cli.Command{
		Name:      "change-pin",
		ArgsUsage: "<old-pin> <new-pin>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			oldPin := cmd.Args().Get(0)
			newPin := cmd.Args().Get(1)

			if oldPin == "" || newPin == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Old pin and new pin must not be empty",
					Data:    nil,
				}
				return nil
			}

			res, err := enigma.ChangePin(enigmaContext.DLL, oldPin, newPin)

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
