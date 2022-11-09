package dss

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/domainadvisor"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/model"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/spf13/cobra"
)

func init() {
	cmd.AddCommand(cmdScan)
}

type scanResultWithAdvice struct {
	*scanner.ScanResult
	Advice map[string][]string `json:"advice"`
}

var (
	cache  bool
	format string

	cmdScan = &cobra.Command{
		Use:     "scan [flags] <STDIN>",
		Example: "dss scan <STDIN>\n  dss scan globalcyberalliance.org gcaaide.org google.com\n  dss scan -z < zonefile",
		Short:   "Scan one or multiple domains's DNS records.",
		Long:    "Scan one or multiple domains's DNS records.\nBy default, the command will listen on STDIN, allowing you to type or pipe multiple domains.",
		Run: func(command *cobra.Command, args []string) {
			opts := []scanner.ScannerOption{
				scanner.ConcurrentScans(concurrent),
				scanner.UseCache(cache),
				scanner.UseNameservers(nameservers),
				scanner.WithTimeout(time.Duration(timeout) * time.Second),
			}

			var source scanner.Source

			if len(args) == 0 && zoneFile {
				source = scanner.ZonefileSource(os.Stdin)
			} else if len(args) > 0 && zoneFile {
				log.Fatal().Msg("-z flag provided, but not reading from STDIN")
			} else if len(args) == 0 {
				log.Info().Msg("Accepting input from STDIN. Type a domain and hit enter.")
				source = scanner.TextSource(os.Stdin)
			} else {
				sr := strings.NewReader(strings.Join(args, "\n"))
				source = scanner.TextSource(sr)
			}

			sc, err := scanner.New(opts...)
			if err != nil {
				log.Fatal().Err(err).Msg("An unexpected error occurred.")
			}

			sc.DKIMSelector = dkimSelector
			sc.RecordType = recordType

			for result := range sc.Start(source) {
				advice := domainadvisor.CheckAll(result.SPF, result.DMARC, result.BIMI, result.DKIM)
				printToConsole(model.ScanResultWithAdvice{
					ScanResult: result,
					Advice:     advice,
				})
				printToFile(model.ScanResultWithAdvice{
					ScanResult: result,
					Advice:     advice,
				})
				fmt.Println("")
			}
		},
	}
)
