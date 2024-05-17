package main

import (
	"github.com/aquasecurity/trivy-aws/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err.Error())
	}
}

func run() error {
	cmd := commands.NewCmd()
	return cmd.Execute()
}
