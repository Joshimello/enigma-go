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

func XMSSVerify() *cli.Command {
	return &cli.Command{
		Name:      "xmss-verify",
		ArgsUsage: "<public-key-file> <signature-file> <message-file>",
		Usage:     "Verify a signature using XMSS algorithm",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			pkeyFile := cmd.Args().Get(0)
			sigFile := cmd.Args().Get(1)
			msgFile := cmd.Args().Get(2)

			if pkeyFile == "" || sigFile == "" || msgFile == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Public key file, signature file, and message file paths are required as arguments",
					Data:    nil,
				}
				return nil
			}

			err := enigma.XMSSVerify(enigmaContext.DLL, pkeyFile, sigFile, msgFile)
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
					Data:    nil,
				}
				return nil
			}

			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: "XMSS signature verified successfully",
				Data: map[string]string{
					"verified": "true",
				},
			}

			return nil
		},
	}
}
