// Package powerdns implements a powerdns
package powerdns

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joeig/go-powerdns/v3"
	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with PowerDNS.
type Provider struct {
	// ServerURL is the location of the pdns server.
	ServerURL string `json:"server_url"`

	// ServerID is the id of the server.  localhost will be used
	// if this is omitted.
	ServerID string `json:"server_id,omitempty"`

	// APIToken is the auth token.
	APIToken string `json:"api_token,omitempty"`

	// Debug - can set this to stdout or stderr to dump
	// debugging information about the API interaction with
	// powerdns.  This will dump your auth token in plain text
	// so be careful.
	Debug string `json:"debug,omitempty"`

	mu sync.Mutex
	c  *client
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	fullZone, err := c.getZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	recs := make([]libdns.Record, 0)
	for _, rrset := range fullZone.RRsets {
		if rrset.Type == nil {
			continue
		}
		rrType := string(*rrset.Type)
		rrName := powerdns.StringValue(rrset.Name)
		ttl := time.Second * time.Duration(powerdns.Uint32Value(rrset.TTL))
		for _, r := range rrset.Records {
			content := powerdns.StringValue(r.Content)
			lrec, err := (libdns.RR{
				Type: rrType,
				Name: libdns.RelativeName(rrName, zone),
				Data: content,
				TTL:  ttl,
			}).Parse()
			if err != nil {
				return nil, err
			}
			recs = append(recs, lrec)
		}
	}
	return recs, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}

	// Get current zone state
	fullZone, err := c.getZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Convert input records to absolute names
	absRecords := convertNamesToAbsolute(zone, records)
	recHash := makeLDRecHash(absRecords)

	// Process each unique name+type combination
	for _, recs := range recHash {
		if len(recs) == 0 {
			continue
		}

		name := recs[0].Name
		rrType := recs[0].Type
		ttl := uint32(recs[0].TTL.Seconds())

		// Get new content values
		newContents := make([]string, 0, len(recs))
		for _, r := range recs {
			newContents = append(newContents, r.Data)
		}

		// Find existing RRset and merge
		existingRRset := findRRset(fullZone, name, rrType)
		existingContents := rrsetContents(existingRRset)
		mergedContents := mergeContents(existingContents, newContents)

		// Use Records.Change to update (works for both new and existing)
		err = c.Records.Change(ctx, zone, name, powerdns.RRType(rrType), ttl, mergedContents)
		if err != nil {
			return nil, err
		}
	}

	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}

	// Convert input records to absolute names
	absRecords := convertNamesToAbsolute(zone, records)
	recHash := makeLDRecHash(absRecords)

	// Process each unique name+type combination
	for _, recs := range recHash {
		if len(recs) == 0 {
			continue
		}

		name := recs[0].Name
		rrType := recs[0].Type
		ttl := uint32(recs[0].TTL.Seconds())

		// Collect all content values for this name+type
		contents := make([]string, 0, len(recs))
		for _, r := range recs {
			contents = append(contents, r.Data)
		}

		// Use Records.Change to replace
		err = c.Records.Change(ctx, zone, name, powerdns.RRType(rrType), ttl, contents)
		if err != nil {
			return nil, err
		}
	}

	return records, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}

	// Get current zone state
	fullZone, err := c.getZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Convert input records to absolute names
	absRecords := convertNamesToAbsolute(zone, records)
	recHash := makeLDRecHash(absRecords)

	// Process each unique name+type combination
	for _, recs := range recHash {
		if len(recs) == 0 {
			continue
		}

		name := recs[0].Name
		rrType := recs[0].Type

		// Find existing RRset
		existingRRset := findRRset(fullZone, name, rrType)
		if existingRRset == nil {
			// Nothing to delete
			continue
		}

		// Get contents to remove
		toRemove := make([]string, 0, len(recs))
		for _, r := range recs {
			toRemove = append(toRemove, r.Data)
		}

		// Remove specified contents from existing
		existingContents := rrsetContents(existingRRset)
		remainingContents := removeContents(existingContents, toRemove)

		if len(remainingContents) == 0 {
			// Delete entire RRset
			err = c.Records.Delete(ctx, zone, name, powerdns.RRType(rrType))
			if err != nil {
				return nil, err
			}
		} else {
			// Update with remaining contents
			ttl := powerdns.Uint32Value(existingRRset.TTL)
			err = c.Records.Change(ctx, zone, name, powerdns.RRType(rrType), ttl, remainingContents)
			if err != nil {
				return nil, err
			}
		}
	}

	return records, nil
}

func (p *Provider) client() (*client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c == nil {
		var err error
		if p.ServerID == "" {
			p.ServerID = "localhost"
		}
		var debug io.Writer
		switch strings.ToLower(p.Debug) {
		case "stdout", "yes", "true", "1":
			debug = os.Stdout
		case "stderr":
			debug = os.Stderr
		}
		p.c, err = newClient(p.ServerID, p.ServerURL, p.APIToken, debug)
		if err != nil {
			return nil, err
		}
	}
	return p.c, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
