package whois

import (
	"github.com/weregoat/goat-whois/pkg/whois/response"
	"github.com/weregoat/goat-whois/pkg/whois/sources"
)

type client struct {
	Sources []sources.Source
}

func New(sources ...sources.Source) client {
	c := client{}
	c.Sources = sources
	return c
}

func (c *client) Query(resource string) (data response.Response) {
	for _, source := range c.Sources {
		data = source.Query(resource)
		if data.IsValid() {
			break
		}
	}
	return data
}
