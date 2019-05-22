package whois

import (
	"goat-whois/whois/response"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const IANAWhoisServer = "whois.iana.org"
const DefaultClient = "/usr/bin/whois"
const WhoisPort = "43"
const WhoisProtocol = "tcp"
const MaxRefer = 4

type client struct {
	Server string
	Path string
	Response *response.Response
	InternalOnly bool
	ClientOnly bool
}

func New() client {
	c := client{
		Server: IANAWhoisServer,
		Path: DefaultClient,
		InternalOnly: false,
		ClientOnly: false,
	}
	return c
}

func (c *client) GetCountryCode(resource string) string {
	if c.Response == nil {
		c.Query(resource)
	}
	return c.Response.CountryCode
}

func (c *client) GetCIDR(resource string) string {
	if c.Response == nil {
		c.Query(resource)
	}
	return c.Response.CIDR
}

func (c *client) Query(resource string) (data response.Response) {
	// Check the client exists
	path, err := exec.LookPath(c.Path)
	if err != nil {
		c.Path = path
	} else {
		c.Path = ""
	}
	payload, err := c.getResponse(resource)
	data = response.ParseResponse(resource, payload)
	c.Response = &data
	return data
}

func (c *client) queryServer(server, target string) (response []byte, err error){
	if len(server) == 0 {
		server = IANAWhoisServer
	}
	count := 0
	refer := server
	for count < MaxRefer {
		response, err = query(server, target)
		if err != nil {
			return
		}
		refer, err = getReferral(response)
		if err != nil {
			return
		}
		if refer == server || len(refer) == 0 {
			break
		} else {
			server = refer
			count++
		}
	}
	return
}

func (c *client) getResponse(resource string) (response []byte, err error) {
	if ! c.InternalOnly {
		response, err = exec.Command(c.Path, resource).Output()
	}
	if err != nil || len(response) == 0 {
		if ! c.ClientOnly {
			response, err = c.queryServer(c.Server, resource)
		}
	}
	return
}

func getReferral(response []byte) (refer string, err error) {

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

