package sources

import "goat-whois/whois/response"

type Source interface {
	Query(resource string) response.Response
	String() string
}
