package main

import (
	"context"

	"github.com/libdns/libdns"

	"github.com/libdns/powerdns"
)

func main() {
	p := &powerdns.Provider{
		ServerURL: "http://127.0.0.1:8081/", // required
		ServerID:  "localhost",              // if left empty, defaults to localhost.
		APIToken:  "key",                    // required
	}

	_, err := p.AppendRecords(context.Background(), "cavoj.net.", []libdns.Record{
		libdns.ServiceBinding{
			Name:     "pdns-test",
			Scheme:   "https",
			TTL:      0,
			Priority: 1,
			Target:   "cavoj.net.",
			Params: libdns.SvcParams{
				"ech": []string{"asdf"},
			},
		},
	})
	if err != nil {
		panic(err)
	}

}
