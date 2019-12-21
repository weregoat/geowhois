package whois

import (
	"github.com/weregoat/goat-whois/pkg/whois/response"
	"github.com/weregoat/goat-whois/pkg/whois/sources"
)

type Client struct {
	Sources []sources.Source
}

func New(sources ...sources.Source) Client {
	c := Client{}
	c.Sources = sources
	return c
}

func (c Client) Query(resource string) (data response.Response) {
	for _, source := range c.Sources {
		data = source.Query(resource)
		if data.IsValid() {
			break
		}
	}
	return data
}
