package record

import (
	"net"
	"regexp"
	"strings"
)

// Record represent information about Whois query and response
type Record struct {
	Source      string
	Target      string
	CountryCode string
	CIDR        string
	Raw         []byte
}

// New generates a new Record
func New(target, source string) Record {
	r := Record{
		Source: source,
		Target: target,
	}
	return r
}

// ParseResponse parsed the response from a whois source and tries to extract the country-code and CIDR.
func (r *Record) ParseResponse(response []byte) {
	r.Raw = response
	country := getCountry(r.Raw, r.Target)
	if len(country) == 2 {
		r.CountryCode = country
	}
	cidr := getCIDR(r.Raw)
	if len(cidr) > 0 {
		r.CIDR = cidr
	}
}

// getCountry tries to extract the country code from a whois response.
func getCountry(response []byte, target string) string {
	var country string
	pattern := `Registrant Country:[[:blank:]]*([A-Z]{2})[[:space:]]`
	if isIPAddress(target) {
		pattern = `(?i:country):[[:blank:]]*([[:alpha:]]{2})[[:space:]]`
	}
	re := regexp.MustCompile(pattern)
	// fmt.Printf(string(response))
	match := re.FindSubmatch(response)
	if len(match) >= 2 {
		country = strings.ToUpper(strings.TrimSpace(string(match[1])))
	}
	return country
}

// getCIDR tries to extract a CIDR address from a whois response
func getCIDR(payload []byte) (CIDR string) {
	patterns := map[string]string{
		"cidr":                 `(?:a\.[[:blank:]]+\[Network Number\]|CIDR:|inet6num:|inetnum:)[[:blank:]]+([^[:space:]]+/[[:digit:]]+)`, // ARIN && JPNIC (also some RIPE
		"range":                `(?:inetnum|inet6num):[[:blank:]]+([^[:space:]]+) - ([^[:space:]]+)`,     // RIPE, AFRINIC and APNIC
//		"curtailed_ipv4_range": `(?:inetnum):[[:blank:]]+([^[:space:]]+)`,                                // LACNIC

	}
	for format, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.Match(payload) {
			allMatches := re.FindAllSubmatch(payload, -1)
			// Start parsing from the end (ideally it's a smaller range)
			for pos := len(allMatches) - 1; pos >= 0; pos-- {
				match := allMatches[pos]
				switch format {
				case "cidr": // Straight match, it should be already in CIDR form
					CIDR = strings.TrimSpace(string(expandCIDR(match[1])))
				case "range":
					CIDR = getCDRFromRange(match)
				default:
					CIDR = ""
				}
				_, _, err := net.ParseCIDR(CIDR)
				if err == nil && len(CIDR) > 0 {
					return
				}
			}
		}
	}
	return ""
}

// isIPAddress try to parse a string to check if it's a valid IP address
// trough https://golang.org/src/net/ip.go?s=15554:15579#L665
func isIPAddress(target string) bool {
	ip := net.ParseIP(target)
	if ip != nil {
		return true
	}
	return false
}

// getCDRFromRange tries to extract a CIDR from a range as reported, for example, by RIPE
func getCDRFromRange(match [][]byte) string {
	var network net.IPNet
	var start string
	var end string
	if len(match) >= 3 {
		start = strings.TrimSpace(string(match[1]))
		end = strings.TrimSpace(string(match[2]))
	}
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)
	if endIP != nil && startIP != nil {
		maxBits := 32
		if strings.Contains(start, ":") || strings.Contains(end, ":") {
			maxBits = 128
		}
		for bits := maxBits; bits >= 0; bits-- {
			mask := net.CIDRMask(bits, maxBits)
			ip := startIP.Mask(mask)
			network = net.IPNet{IP: ip, Mask: mask}
			if network.Contains(endIP) {
				break
			}
		}
	}
	ones, bits := network.Mask.Size()
	if bits > 0 && ones > 0 {
		return network.String()
	}
	return ""
}

// expandCIDR adds zeroes to ipv4CIDR missing it so it can be checked with the net package
// LacNIC would return CIDR like this: 179.5/16 and the net package doesn't handle them.
// Only works with IPv4 as I don't have any IPv6 whois example to work on right now.
func expandCIDR(match []byte) string {
	CIDR := strings.TrimSpace(string(match))
	_, _, err := net.ParseCIDR(CIDR)
	if err != nil {
		// LacNIC inetnum is like this:
		// inetnum:     179.5/16
		// Golang Net library doesn't parse it
		// so I need this ugly hack to convert it to
		// something it parses.
		// Only for IPv4 right now, as I don't have LacNIC IPv6 examples
		// to work on.
		if ! strings.Contains(CIDR, ":") && strings.Contains(CIDR, ".") {
			parts := strings.Split(CIDR, "/")
			if len(parts) == 2 {
				mask := parts[1]
				address := parts[0]
				bytes := strings.Split(address, ".")
				if len(bytes) > 0 && len(bytes) < 4 {
					for z := len(bytes); z < 4; z++ {
						address = address + ".0"
					}
					CIDR = address + "/" + mask
				}
			}
		} else {
			// I don't know how ipv6 CIDR are shown by LacNIC
			CIDR = ""
		}
	}
	return CIDR
}
