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
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "mt",
				Usage: "Use XMSS-MT (multi-tree) variant",
			},
			&cli.StringFlag{
				Name:    "oid",
				Aliases: []string{"o"},
				Usage:   "OID value for XMSS parameter set (4 bytes in hex format)",
				Value:   "00000001",
			},
			&cli.StringFlag{
				Name:    "secret-key",
				Aliases: []string{"sk"},
				Usage:   "Secret key file path",
				Value:   "xmss_secret.key",
			},
			&cli.StringFlag{
				Name:    "public-key",
				Aliases: []string{"pk"},
				Usage:   "Public key file path",
				Value:   "xmss_public.key",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			isXMSSMT := byte(0)
			if cmd.Bool("mt") {
				isXMSSMT = 1
			}

			skeyFile := cmd.String("secret-key")
			pkeyFile := cmd.String("public-key")

			err := enigma.XMSSKeyGen(enigmaContext.DLL, isXMSSMT, "XMSS-SHA2_10_256", skeyFile, pkeyFile)
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
