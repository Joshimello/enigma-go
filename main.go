//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/joshimello/enigma-go/commands"
	"github.com/joshimello/enigma-go/enigma"
	"github.com/joshimello/enigma-go/types"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {

			dll, err := enigma.Create("library/EnovaMX.dll")
			if err != nil {
				result := &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
				}
				jsonResult, _ := json.Marshal(result)
				fmt.Println(string(jsonResult))
				os.Exit(1)
			}

			res, err := enigma.Detect(dll)
			if err != nil && res == false {
				result := &types.EnigmaResponse{
					Status:  "error",
					Message: err.Error(),
				}
				jsonResult, _ := json.Marshal(result)
				fmt.Println(string(jsonResult))
				os.Exit(1)
			}

			res, _, _, err = enigma.LoginStatus(dll)

			enigmaContext := &types.EnigmaContext{
				DLL:    dll,
				Result: nil,
			}

			return context.WithValue(ctx, "enigma-context", enigmaContext), nil
		},
		Commands: []*cli.Command{
			// status
			commands.Version(),
			commands.DetectDevice(),
			commands.UID(),

			// pin
			commands.LoginStatus(),
			commands.Login(),
			commands.ChangePin(),

			// aes
			commands.AESEncrypt(),
			commands.AESDecrypt(),
			commands.AESEncryptFile(),
			commands.AESDecryptFile(),

			// rsa
			commands.ListKeys(),
		},
		After: func(ctx context.Context, cmd *cli.Command) error {
			enigmaContext, ok := ctx.Value("enigma-context").(*types.EnigmaContext)
			if !ok {
				fmt.Println("Context error")
				os.Exit(1)
			}

			if enigmaContext.Result != nil {
				jsonResult, err := json.Marshal(enigmaContext.Result)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Println(string(jsonResult))
			}

			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		result := &types.EnigmaResponse{
			Status:  "error",
			Message: err.Error(),
		}
		jsonResult, _ := json.Marshal(result)
		fmt.Println(string(jsonResult))
		os.Exit(1)
	}
}
