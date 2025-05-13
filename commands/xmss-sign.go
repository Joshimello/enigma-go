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

func XMSSSign() *cli.Command {
	return &cli.Command{
		Name:      "xmss-sign",
		ArgsUsage: "<secret-key-file> <message-file> <signature-file>",
		Usage:     "Sign a message file using XMSS algorithm and save the signature to a file",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			skeyFile := cmd.Args().Get(0)
			msgFile := cmd.Args().Get(1)
			sigFile := cmd.Args().Get(2)

			if skeyFile == "" || msgFile == "" || sigFile == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Secret key file, message file, and signature file paths are required as arguments",
					Data:    nil,
				}
				return nil
			}

			err := enigma.XMSSSign(enigmaContext.DLL, skeyFile, msgFile, sigFile)
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
				Message: "XMSS signature created successfully",
				Data: map[string]string{
					"signatureFile": sigFile,
				},
			}

			return nil
		},
	}
}