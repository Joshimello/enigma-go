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

func Login() *cli.Command {
	return &cli.Command{
		Name:      "login",
		ArgsUsage: "<pin>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			pin := cmd.Args().Get(0)
			if pin == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "PIN is required as an argument",
					Data:    nil,
				}
				return nil
			}

			res, err := enigma.Login(enigmaContext.DLL, pin)

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
