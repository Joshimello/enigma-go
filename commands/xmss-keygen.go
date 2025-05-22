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

func XMSSKeyGen() *cli.Command {
	return &cli.Command{
		Name:  "xmss-keygen",
		Usage: "Generate XMSS key pair",
		ArgsUsage: "<isXMSSMT> <method> <secretKeyFile> <publicKeyFile>",
		Description: "Generate XMSS key pair using specified parameters.\n" +
			"   isXMSSMT: Use 0/false or 1/true to specify XMSS-MT variant\n" +
			"   method: XMSS method string (e.g., XMSS-SHA2_10_256)\n" +
			"   secretKeyFile: Path to save the secret key\n" +
			"   publicKeyFile: Path to save the public key",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			args := cmd.Args().Slice()
			if len(args) < 4 {
				return fmt.Errorf("missing required arguments: isXMSSMT method secretKeyPath publicKeyPath")
			}

			// Parse isXMSSMT from the first arg
			isXMSSMT := args[0] == "1" || args[0] == "true"
			
			// Get the method, secret key path, and public key path
			method := args[1]
			skeyFile := args[2]
			pkeyFile := args[3]

			err := enigma.XMSSKeyGen(enigmaContext.DLL, isXMSSMT, method, skeyFile, pkeyFile)
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
				Message: "XMSS key pair generated successfully",
				Data: map[string]string{
					"secretKeyFile": skeyFile,
					"publicKeyFile": pkeyFile,
				},
			}

			return nil
		},
	}
}