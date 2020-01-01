package server

import (
	"github.com/weregoat/goat-whois/pkg/whois/response"
	"github.com/weregoat/goat-whois/pkg/whois/sources"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

const IANAServer = "whois.iana.org"
const Port = "43"
const Protocol = "tcp"
const MaxRefer = 4
const Timeout = time.Second*3

type server struct {
	source string
}

func New(hostname string) (sources.Source, error) {
	var err error
	if len(hostname) == 0 {
		hostname = IANAServer
	}
	source := server{hostname}
	return &source, err
}

func (s *server) Query(resource string) (data response.Response) {
	if len(s.source) > 0 {
		payload, err := s.queryServer(s.source, resource)
		if err == nil && len(payload) > 0 {
			data = response.ParseResponse(resource, payload)
		}
	}
	return data
}

func (s *server) String() string {
	return s.source
}

func (s *server) Class() sources.Class {
	return sources.Server
}

func (s *server) queryServer(server, target string) (response []byte, err error){
	if len(server) == 0 {
		server = IANAServer
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
	conn, err := net.DialTimeout(Protocol, net.JoinHostPort(server, Port), Timeout)
	if err != nil {
		log.Print(err)
		return
	}

	defer conn.Close()
	conn.Write([]byte(domain + "\r\n"))
	conn.SetReadDeadline(time.Now().Add(Timeout))
	response, err = ioutil.ReadAll(conn)
	if err != nil {
		log.Print(err)
	}
	return
}
