package main

import (
	"flag"
	"fmt"
	"github.com/weregoat/goat-whois/pkg/whois"
	whoiSources "github.com/weregoat/goat-whois/pkg/whois/sources"
	whoisProgram "github.com/weregoat/goat-whois/pkg/whois/sources/program"
	whoisServer "github.com/weregoat/goat-whois/pkg/whois/sources/server"
)



func main() {
	var host string
	var path string
	var sources []whoiSources.Source

	flag.StringVar(&host,"server", "", "Whois server to start the query from")
	flag.StringVar(&path, "whois_client", "", "Whois client to use for the query")
	flag.Parse()
	targets := flag.Args()
	// If both client and server parameters are empty, we set them both with the defaults
	if len(host) == 0 && len(path) == 0 {
		path = whoisProgram.Default
		host = whoisServer.IANAServer
	}
	// Always the client comes first, if defined as is certainly better than my code
	if len(path) > 0 {
		program, err := whoisProgram.New(path)
		if err == nil {
			sources = append(sources, program)
		}
	}
	if len(host) > 0 {
		server, err := whoisServer.New(host)
		if err == nil {
			sources = append(sources, server)
		}
	}
	client := whois.New(sources...)
	for _,target := range targets {
		fmt.Printf("querying for %s\n", target)
		response := client.Query(target)
		if response.IsValid() {
			fmt.Printf("CIDR: %s\nCountryCode: %s\n---\n", response.CIDR, response.CountryCode)
		} else {
			if response.Error != nil {
				fmt.Printf("Error querying for %s: %s\n---\n", target, response.Error.Error())
			} else {
				fmt.Printf("No response\n---\n")
			}
		}
	}




}


