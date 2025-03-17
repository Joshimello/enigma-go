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

func GenerateKey() *cli.Command {
	return &cli.Command{
		Name:      "generate-key",
		ArgsUsage: "<custom-id>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			customID := cmd.Args().Get(0)
			if customID == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Custom ID is required as an argument",
					Data:    nil,
				}
				return nil
			}

			res, keyID, pubKeyN, pubKeyE, err := enigma.GenerateKey(enigmaContext.DLL, customID)
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
				Data: map[string]string{
					"key_id":     keyID,
					"public_key": pubKeyN,
					"exponent":   pubKeyE,
				},
			}

			return nil
		},
	}
}
