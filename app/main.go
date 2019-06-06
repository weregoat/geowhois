package main

import (
	"flag"
	"fmt"
	"goat-whois/whois"
	whoiSources "goat-whois/whois/sources"
	"goat-whois/whois/sources/program"
	whoisServer "goat-whois/whois/sources/server"
)



func main() {
	var host string
	var path string
	var sources []whoiSources.Source

	flag.StringVar(&host,"server", "", "Whois server to start the query from")
	flag.StringVar(&path, "whois_client", "", "Whois client to use for the query")
	flag.Parse()
	targets := flag.Args()
	if len(targets) == 0 {
		targets = []string{
			"internet-census.org",
			"maialinux.org",
			"69.175.97.170",
			"google.com",
			"185.112.146.34",
			"172.217.20.46",
			"2a00:1450:400f:806::200e",
			"2a02:750:9::1be",
			"2001:470:0:76::2",
			"179.6.221.254",
			"196.46.23.12",
			"202.214.194.239",
			"nigeria.gov.ng",
			"185.222.211.10",
			"parsdata.com",
			"serv-mail.info",
			"vipps.no",
		}
	}
	// If both client and server parameters are empty, we set them with the defaults
	if len(host) == 0 && len(path) == 0 {
		path = program.Default
		host = whoisServer.IANAServer
	}
	// Always the client comes first, if defined as is certainly better than my code
	if len(path) > 0 {
		program, err := program.New(path)
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
				//fmt.Printf("Response: %s\n---\n", string(response.Raw))
			} else {
				fmt.Printf("No response\n---\n")
			}
		}
	}




}


