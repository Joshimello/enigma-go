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

func AESEncryptFile() *cli.Command {
	return &cli.Command{
		Name:      "aes-encrypt-file",
		ArgsUsage: "<source-folder-path> <file-path> <target-folder-path>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			sourceFolderPath := cmd.Args().Get(0)
			filePath := cmd.Args().Get(1)
			targetFolderPath := cmd.Args().Get(2)

			if sourceFolderPath == "" || filePath == "" || targetFolderPath == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Source, file and target folder paths are required arguments",
					Data:    nil,
				}
				return nil
			}

			err := enigma.AESEncryptFile(enigmaContext.DLL, sourceFolderPath, filePath, targetFolderPath)
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
				Message: enigma.GetCodeMessage(0),
				Data:    nil,
			}

			return nil
		},
	}
}
