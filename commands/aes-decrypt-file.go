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

func AESDecryptFile() *cli.Command {
	return &cli.Command{
		Name:      "aes-decrypt-file",
		ArgsUsage: "<encrypted-file-path> <target-directory>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			encryptedFilePath := cmd.Args().Get(0)
			targetDirectory := cmd.Args().Get(1)

			if encryptedFilePath == "" || targetDirectory == "" {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Encrypted file path and target directory are required arguments",
					Data:    nil,
				}
				return nil
			}

			if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: "Encrypted file does not exist",
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

			sourceDir := filepath.Dir(encryptedFilePath)
			fileName := "./" + filepath.Base(encryptedFilePath)

			err := enigma.AESDecryptFile(enigmaContext.DLL, sourceDir, fileName, targetDirectory)
			if err != nil {
				enigmaContext.Result = &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
					Data:    nil,
				}
				return nil
			}

			originalFileName := filepath.Base(encryptedFilePath)
			if filepath.Ext(originalFileName) == ".emx" {
				originalFileName = originalFileName[:len(originalFileName)-4]
			}

			decryptedFilePath := filepath.Join(targetDirectory, originalFileName)

			enigmaContext.Result = &types.EnigmaResponse{
				Status:  "success",
				Message: enigma.GetCodeMessage(0),
				Data: map[string]any{
					"decrypted_file": decryptedFilePath,
				},
			}

			return nil
		},
	}
}
