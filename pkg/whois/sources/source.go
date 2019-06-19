package sources

import "github.com/weregoat/goat-whois/pkg/whois/response"

type Source interface {
	Query(resource string) response.Response
	String() string
}
