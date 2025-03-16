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

func ListKeys() *cli.Command {
	return &cli.Command{
		Name: "list-keys",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			res, keyCount, keyIDList, customIDList, err := enigma.ListKeys(enigmaContext.DLL)

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
				Data: map[string]any{
					"key_count":      keyCount,
					"key_ids":        keyIDList,
					"custom_key_ids": customIDList,
				},
			}

			return nil
		},
	}
}
