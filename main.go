package main

import (
	"fmt"
	record2 "goat-whois/whois/record"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

const IANAWhoisServer = "whois.iana.org"
const WhoisPort = "43"
const WhoisProtocol = "tcp"


func main() {
	targets := [13]string{
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
	}
	for _,target := range targets {
		fmt.Printf("%s\n", target)
		count := 0
		server := IANAWhoisServer
		for count < 3 {
			response, err := query(server, target)
			if err != nil {
				return
			}
			refer, err := getReferral(response, target)
			if err != nil {
				log.Fatal(err)
			}
			if refer == server || len(refer) == 0 {
				record := record2.New(target, server)
				record.ParseResponse(response)
				if len(record.CIDR) > 0 {
					fmt.Printf("%s\n", record.CIDR)
				}
				if len(record.CountryCode) > 0 {
					fmt.Printf("%s\n", record.CountryCode)
				}
				if (len(record.CountryCode) + len(record.CIDR)) == 0 {
					fmt.Printf("%s\n", record.Raw)
				}
				break
			} else {
				fmt.Printf("Whois server %s refers to %v for domain %s\n", server, refer, target)
				server = refer
				count++
			}
		}
		fmt.Printf("---\n")
	}



}

func getReferral(response []byte, target string) (refer string, err error) {

	re := regexp.MustCompile(`(?:Registrar WHOIS Server|refer|whois):[[:blank:]]+([^[:space:]]+)[[:space:]]+`)
	//fmt.Printf(string(buffer))
	match := re.FindSubmatch(response)
	if len(match) > 0 {
		refer = strings.ToLower(strings.TrimSpace(string(match[1])))
	}
	return

}


func query(server, domain string) (response []byte, err error) {
	conn, err := net.DialTimeout(WhoisProtocol, net.JoinHostPort(server, WhoisPort), time.Second*30)
	if err != nil {
		log.Print(err)
		return
	}

	defer conn.Close()
	conn.Write([]byte(domain + "\r\n"))
	conn.SetReadDeadline(time.Now().Add(time.Second * 30))
	response, err = ioutil.ReadAll(conn)
	if err != nil {
		log.Print(err)
	}
	return
}
