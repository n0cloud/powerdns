# powerdns provider for [`libdns`](https://github.com/libdns/libdns)

[![Github Actions](https://github.com/n0cloud/powerdns/actions/workflows/go.yml/badge.svg)](https://github.com/n0cloud/powerdns/actions/workflows/go.yml) [![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/n0cloud/powerdns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [PowerDNS](https://powerdns.com/), allowing you to manage DNS records.

This uses [mittwald/go-powerdns](https://github.com/mittwald/go-powerdns) under the covers to actually talk to powerdns.

To configure this, simply specify the server URL and the access token.

    package main

    import (
        "context"

        "github.com/libdns/libdns"
        "github.com/n0cloud/powerdns"
    )

    func main() {
        p := &powerdns.Provider{
            ServerURL: "http://localhost", // required
            ServerID:  "localhost",        // if left empty, defaults to localhost.
            APIToken:  "asdfasdfasdf",     // required
        }

        _, err := p.AppendRecords(context.Background(), "example.org.", []libdns.Record{
            {
                Name:  "_acme_whatever",
                Type:  "TXT",
                Value: "123456",
            },
        })
        if err != nil {
            panic(err)
        }

    }
