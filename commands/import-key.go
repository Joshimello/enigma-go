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

func ImportKey() *cli.Command {
	return &cli.Command{
		Name:      "import-key",
		ArgsUsage: "<custom-id> <public-key-n> <public-key-e>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			customID := cmd.Args().Get(0)
			pubKeyN := cmd.Args().Get(1)
			pubKeyE := cmd.Args().Get(2)

			if customID == "" || pubKeyN == "" || pubKeyE == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Custom ID, public key N and public key E are required as arguments",
					Data:    nil,
				}
				return nil
			}

			res, keyID, err := enigma.ImportKey(enigmaContext.DLL, customID, pubKeyN, pubKeyE)
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
					"key_id": keyID,
				},
			}

			return nil
		},
	}
}
