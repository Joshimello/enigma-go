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

func LoginStatus() *cli.Command {
	return &cli.Command{
		Name: "login-status",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			res, retryCount, isValid, err := enigma.LoginStatus(enigmaContext.DLL)

			if !res {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
					Data: map[string]any{
						"login_status":      res,
						"retry_count":       retryCount,
						"retry_count_valid": isValid,
					},
				}
				return nil
			}

			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: enigma.GetCodeMessage(0),
				Data: map[string]any{
					"login_status":      res,
					"retry_count":       retryCount,
					"retry_count_valid": isValid,
				},
			}

			return nil
		},
	}
}
