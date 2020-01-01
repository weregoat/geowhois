package program

import (
	"github.com/weregoat/goat-whois/pkg/whois/response"
	"github.com/weregoat/goat-whois/pkg/whois/sources"
	"os/exec"
)

const Default = "/usr/bin/whois"

type program struct {
	source string
}

func New(path string) (sources.Source, error) {
	var err error
	if len(path) == 0 {
		path = Default
	}
	source := program{}
	source.source, err = exec.LookPath(path)
	return &source, err
}

func (p *program) Query(resource string) (data response.Response) {
	var payload []byte
	// Check the source exists as a path
	path, err := exec.LookPath(p.source)
	if err == nil {
		payload, err = exec.Command(path, resource).Output()
	}
	if err == nil && len(payload) > 0 {
		data = response.ParseResponse(resource, payload)
	}
	return data
}

func (p *program) String() string {
	return p.source
}

func (p *program) Class() sources.Class {
	return sources.Program
}