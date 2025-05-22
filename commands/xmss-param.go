//go:build windows

package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/joshimello/enigma-go/enigma"
	"github.com/joshimello/enigma-go/types"
	"github.com/urfave/cli/v3"
)

func XMSSParam() *cli.Command {
	return &cli.Command{
		Name:  "xmss-param",
		Usage: "Get XMSS parameters",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			// Get XMSS parameters
			params, err := enigma.XMSSGetParam(enigmaContext.DLL)
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: fmt.Sprintf("Failed to get XMSS parameters: %v", err),
					Data:    nil,
				}
				return nil
			}

			// Convert binary index to hex string for better readability
			indexHex := hex.EncodeToString(params.Index[:])
			
			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: "XMSS parameters retrieved successfully",
				Data: map[string]interface{}{
					"index":      indexHex,
					"xmssID":     params.XMSSID,
					"indexBytes": params.IndexBytes,
				},
			}

			return nil
		},
	}
}