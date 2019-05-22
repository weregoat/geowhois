package main

import (
	"flag"
	"fmt"
	"goat-whois/whois"
)



func main() {

	var host = flag.String("server", whois.IANAWhoisServer, "Whois server to start the query from")
	var path = flag.String("whois_client", whois.DefaultClient, "Whois client to use for the query")
	var internalOnly = flag.Bool("internal", false, "Use only internal program to query whois server")
	var clientOnly = flag.Bool("client", false, "Use only whois client to fetch a response")
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
		}
	}
	for _,target := range targets {
		fmt.Printf("querying for %s\n", target)
		client := whois.New()
		client.InternalOnly = *internalOnly
		client.ClientOnly = *clientOnly
		if len(*host) > 0 {
			client.Server = *host
			client.ClientOnly = false
		}
		if len(*path) > 0 {
			client.Path = *path
			client.InternalOnly = false
		}

		fmt.Printf("CIDR: %s\nCountryCode: %s\n---\n", client.GetCIDR(target), client.GetCountryCode(target))
	}




}


