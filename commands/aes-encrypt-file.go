//go:build windows

package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joshimello/enigma-go/enigma"
	"github.com/joshimello/enigma-go/types"
	"github.com/urfave/cli/v3"
)

func AESEncryptFile() *cli.Command {
	return &cli.Command{
		Name:      "aes-encrypt-file",
		ArgsUsage: "<source-file-path> <target-directory>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			sourceFilePath := cmd.Args().Get(0)
			targetDirectory := cmd.Args().Get(1)

			if sourceFilePath == "" || targetDirectory == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Source file path and target directory are required arguments",
					Data:    nil,
				}
				return nil
			}

			if _, err := os.Stat(sourceFilePath); os.IsNotExist(err) {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Source file does not exist",
					Data:    nil,
				}
				return nil
			}

			if _, err := os.Stat(targetDirectory); os.IsNotExist(err) {
				if err := os.MkdirAll(targetDirectory, 0755); err != nil {
					enigmaContext.Result = &types.EnigmaResponse{
						Status:  "error",
						Message: "Failed to create target directory: " + err.Error(),
						Data:    nil,
					}
					return nil
				}
			}

			sourceDir := filepath.Dir(sourceFilePath)
			fileName := "./" + filepath.Base(sourceFilePath)

			err := enigma.AESEncryptFile(enigmaContext.DLL, sourceDir, fileName, targetDirectory)
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
					Data:    nil,
				}
				return nil
			}

			targetFilePath := filepath.Join(targetDirectory, filepath.Base(sourceFilePath)+".emx")

			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: enigma.GetCodeMessage(0),
				Data: map[string]any{
					"encrypted_file": targetFilePath,
				},
			}

			return nil
		},
	}
}
