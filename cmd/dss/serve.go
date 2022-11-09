package dss

import (
	"time"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/mail"
	"github.com/spf13/cobra"
)

func init() {
	cmd.AddCommand(cmdServe)
}

var (
	interval   time.Duration
	port       int
	mailConfig mail.Config

	cmdServe = &cobra.Command{
		Use:   "serve",
		Short: "Serve the scanner via a REST API or dedicated mailbox",
		Run: func(command *cobra.Command, args []string) {
			_ = command.Help()
		},
	}
)
