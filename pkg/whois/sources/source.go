package sources

import "github.com/weregoat/goat-whois/pkg/whois/response"

type Class int

const (
	Program Class = iota
	Server
)

type Source interface {
	Query(resource string) response.Response
	String() string
	Class() Class
}
