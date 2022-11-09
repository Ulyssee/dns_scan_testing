package domainadvisor

import (
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func CheckAll(spf string, dmarc string, bimi string, dkim string) (advice map[string][]string) {
	advice = make(map[string][]string)

	advice["dmarc"] = CheckDMARC(dmarc)
	advice["spf"] = CheckSPF(spf)
	advice["bimi"] = CheckBIMI(bimi)
	advice["dkim"] = CheckDKIM(dkim)

	return advice
}

func CheckBIMI(bimi string) (advice []string) {
	if bimi == "" {
		advice = append(advice, "LEVEL 0 : RED / We couldn't detect any active BIMI record for your domain.")
		return advice
	}

	if strings.Contains(bimi, "a= ") {
		advice = append(advice, "Level 2 : GREEN / Your BIMI record is valid.")
	} else {
		advice = append(advice, "LEVEL 0 : RED / Your BIMI record is invalid.")
	}

	return advice
}

func CheckDKIM(dkim string) (advice []string) {
	if dkim == "" {
		advice = append(advice, "Level 0 : RED / We couldn't detect any active DKIM record for your domain.")
	} else {
		advice = append(advice, "Level 2 : GREEN / DKIM is setup for this email server.")
	}
	return advice
}

func CheckDMARC(dmarc string) (advice []string) {
	if len(dmarc) == 0 {
		advice = append(advice, "LEVEL 0 : RED / You do not have DMARC setup!")
		return advice
	}

	if strings.Contains(dmarc, ";") {
		dmarcResult := strings.Split(dmarc, ";")

		counter := 0
		for _, tag := range dmarcResult {
			counter++

			tag = strings.TrimSpace(tag)

			switch counter {
			case 1:
				if !strings.Contains(tag, "v=DMARC1") {
					advice = append(advice, "LEVEL 0 : RED / The beginning of your DMARC record should be v=DMARC1 with specific capitalization.")
				}
			case 2:
				if strings.Contains(tag, "p=") && !strings.Contains(tag, "sp=") {
					ruaExists := false
					tagValue := strings.TrimPrefix(tag, "p=")

					if strings.Contains(dmarc, "rua=") {
						ruaExists = true
					}

					switch tagValue {
					case "quarantine":
						if ruaExists {
							advice = append(advice, "Level 2 : GREEN / You are currently at the second level and receiving reports. Please make sure to review the reports, make the appropriate adjustments, and move to reject soon.")
						} else {
							advice = append(advice, "LEVEL 2 : GREEN / You are currently at the second level. However, you must receive reports in order to determine if DKIM/DMARC/SPF are functioning correctly and move to the highest level (reject). Please add the ‘rua’ tag to your DMARC policy.")
						}
					case "none":
						if ruaExists {
							advice = append(advice, "Level 1 : ORANGE / You are currently at the lowest level and receiving reports, which is a great starting point. Please make sure to review the reports, make the appropriate adjustments, and move to either quarantine or reject soon.")
						} else {
							advice = append(advice, "Level 1 : ORANGE / You are currently at the lowest level, which is a great starting point. However, you must receive reports in order to determine if DKIM/DMARC/SPF are functioning correctly. Please add the ‘rua’ tag to your DMARC policy.")
						}
					case "reject":
						if ruaExists {
							advice = append(advice, "Level 2 : GREEN / You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed.")
						} else {
							advice = append(advice, "Level 2 : GREEN / You are at the highest level! However, we do recommend keeping reports enabled (via the rua tag) in case any issues may arise and you can review reports to see if DMARC is the cause.")
						}
					default:
						advice = append(advice, "Level 0 : RED / Invalid DMARC policy specified, the record must be p=none/p=quarantine/p=reject.")
					}
				} else {
					advice = append(advice, "Level 0 : RED / The second tag in your DMARC record must be p=none/p=quarantine/p=reject.")
				}
			default:
				if strings.Contains(tag, "rua=") {
					trimmedTag := strings.TrimPrefix(tag, "rua=")
					tagArray := strings.Split(trimmedTag, ",")

					var invalidAddress, missingMailto bool
					for _, address := range tagArray {
						if !strings.Contains(address, "mailto:") {
							missingMailto = true
						} else {
							trimmedAddress := strings.TrimPrefix(address, "mailto:")
							if !validateEmail(trimmedAddress) {
								invalidAddress = true
							}
						}
					}

					if missingMailto {
						advice = append(advice, "LEVEL 1 : ORANGE / Each email address under the rua tag should contain a mailto: prefix. Example: rua=mailto:dmarc@growth-agence.com,mailto:dmarc2@growth-agence.com.")
					}

					if invalidAddress {
						advice = append(advice, "LEVEL 1 : ORANGE / Your rua tag contains invalid email addresses.")
					}
				}
			}
		}
	} else {
		advice = append(advice, "LEVEL 0 : RED / Your DMARC record appears to be malformed as no semicolons seem to be present.")
	}

	return advice

}

func CheckSPF(spf string) (advice []string) {
	if spf == "" {
		advice = append(advice, "LEVEL 0 : We couldn't detect any active SPF record for your domain.")
		return advice
	}

	if strings.Contains(spf, "all") {
		advice = append(advice, "LEVEL 2 : GREEN / Your SPF record contains a hard fail (all) which is recommended.")
	} else {
		advice = append(advice, "LEVEL 0 : RED / Your SPF record does not contain a hard fail (all) which is recommended.")
	}
	return advice
}

func validateEmail(email string) bool {
	if len(email) < 3 && len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}
