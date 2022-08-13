package main

import (
	"log"
	"os"

	"github.com/mrinjamul/mrinjamul-auth/utils"
)

func main() {
	prefix := ""
	// check if arguments are passed
	if len(os.Args) > 1 {
		prefix = os.Args[1]
	}
	err := utils.GenerateSecretPEMKey(prefix)
	if err != nil {
		log.Println(err)
	}
}
