package response

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

// Record represent information about Whois query and response
type Response struct {
	Resource    string
	CountryCode string // Last country code
	CIDR        string
	Raw         []byte
	Error       error
	CountryCodes    []string // All country codes
}

// New generates a new Record
func ParseResponse(resource string, response []byte) Response {
	r := Response{
		Resource: resource,
	}
	r.parse(response)
	return r
}

// IsValid is a wrapper for the checks that should classify a response as valid:
// - It should have a resource.
// - It should not have an error attached.
// - It should have either a CIDR or country code.
// - It must have a response body
// A determined developer can, of course, set all these manually as they are public properties, in a way
// that it would pass, but the checks are there mostly to catch mistakes during the flow.
func (r *Response) IsValid() bool {
	switch {
	case r.Error != nil:
		return false
	case len(r.Resource) == 0:
		err := errors.New("missing resource")
		r.Error = err
		return false
	case len(r.CIDR) == 0 && len(r.CountryCode) == 0:
		err := errors.New("no country-code or CIDR")
		r.Error = err
		return false
	case len(r.Raw) == 0:
		err := errors.New("no response")
		r.Error = err
		return false
	}
	return true
}

// parse parses the response from a whois source and tries to extract the country-code and CIDR.
func (r *Response) parse(response []byte) {
	r.Raw = response
	countries, err := GetCountries(r.Raw)
	r.Error = err
	if r.Error == nil {
		r.CountryCodes = countries
		if len(countries) >= 1 {
			r.CountryCode = countries[len(countries)-1]
		}
		cidr, err := GetCIDR(r.Raw)
		r.Error = err
		if len(cidr) > 0 {
			r.CIDR = cidr
		}
	}
}

// getCountries tries to extract the country codes from a whois response.
func GetCountries(response []byte) (countries []string, err error) {
	patterns := [2]string {
		`Registrant Country:[[:blank:]]*([A-Z]{2})[[:space:]]`,
		`(?i:country):[[:blank:]]*([[:alpha:]]{2})[[:space:]]`,
	}
	for _,pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return countries, err
		}
		// fmt.Printf(string(response))
		// https://golang.org/pkg/regexp/#Regexp.FindAllStringSubmatch
		matches := re.FindAllSubmatch(response, -1)
		for _,match := range matches {
			if len(match) == 2 {
				country := string(match[1])
				if len(country) == 2 {
					countries = append(countries, strings.ToUpper(country))
				}
			}
		}
	}
	return
}

// getCIDR tries to extract a CIDR address from a whois response
func GetCIDR(response []byte) (CIDR string, err error) {

		patterns := map[string]string{
			"cidr":  `(?:a\.[[:blank:]]+\[Network Number\]|CIDR:|inet6num:|inetnum:)[[:blank:]]+([^[:space:]]+/[[:digit:]]+)`, // ARIN && JPNIC (also some RIPE
			"range": `(?:inetnum|inet6num):[[:blank:]]+([^[:space:]]+) - ([^[:space:]]+)`,                                     // RIPE, AFRINIC and APNIC, LACNIC
		}
		for format, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return CIDR, err
			}
			if re.Match(response) {
				allMatches := re.FindAllSubmatch(response, -1)
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
					_, _, err = net.ParseCIDR(CIDR)
					if err == nil && len(CIDR) > 0 {
						break
					}
				}
			}
		}
	return
}

// isIPAddress tries to parse a string to check if it's a valid IP address
// through https://golang.org/src/net/ip.go?s=15554:15579#L665
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
