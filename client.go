package powerdns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/joeig/go-powerdns/v3"
	"github.com/libdns/libdns"
	"github.com/libdns/powerdns/txtsanitize"
)

type client struct {
	*powerdns.Client
}

// debugTransport wraps http.RoundTripper to log requests/responses
type debugTransport struct {
	transport http.RoundTripper
	output    io.Writer
}

func (d *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dump, _ := httputil.DumpRequestOut(req, true)
	fmt.Fprintf(d.output, "Request:\n%s\n", dump)

	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	dump, _ = httputil.DumpResponse(resp, true)
	fmt.Fprintf(d.output, "Response:\n%s\n", dump)

	return resp, nil
}

func newClient(serverID, serverURL, apiToken string, debug io.Writer) (*client, error) {
	opts := []powerdns.NewOption{
		powerdns.WithAPIKey(apiToken),
	}

	if debug != nil {
		httpClient := &http.Client{
			Transport: &debugTransport{
				transport: http.DefaultTransport,
				output:    debug,
			},
		}
		opts = append(opts, powerdns.WithHTTPClient(httpClient))
	}

	c := powerdns.New(serverURL, serverID, opts...)
	return &client{Client: c}, nil
}

// getZone retrieves the full zone with all RRsets
func (c *client) getZone(ctx context.Context, zoneName string) (*powerdns.Zone, error) {
	return c.Zones.Get(ctx, zoneName)
}

// findRRset finds an RRset in a zone by name and type
func findRRset(zone *powerdns.Zone, name, rrType string) *powerdns.RRset {
	for _, rrset := range zone.RRsets {
		if powerdns.StringValue(rrset.Name) == name && rrset.Type != nil && string(*rrset.Type) == rrType {
			return &rrset
		}
	}
	return nil
}

// rrsetContents extracts content strings from an RRset
func rrsetContents(rrset *powerdns.RRset) []string {
	if rrset == nil {
		return nil
	}
	contents := make([]string, 0, len(rrset.Records))
	for _, r := range rrset.Records {
		contents = append(contents, powerdns.StringValue(r.Content))
	}
	return contents
}

// mergeContents merges existing contents with new ones, deduplicating
func mergeContents(existing, new []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(existing)+len(new))

	for _, c := range existing {
		normalized := strings.TrimSuffix(c, ".")
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, c)
		}
	}
	for _, c := range new {
		normalized := strings.TrimSuffix(c, ".")
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, c)
		}
	}
	return result
}

// removeContents removes specified contents from existing, returns remaining
func removeContents(existing, toRemove []string) []string {
	remove := make(map[string]bool)
	for _, c := range toRemove {
		remove[strings.TrimSuffix(c, ".")] = true
	}

	result := make([]string, 0, len(existing))
	for _, c := range existing {
		if !remove[strings.TrimSuffix(c, ".")] {
			result = append(result, c)
		}
	}
	return result
}

func key(name, rrType string) string {
	return name + ":" + rrType
}

func makeLDRecHash(records []libdns.RR) map[string][]libdns.RR {
	// Keep track of records grouped by name + type
	inHash := make(map[string][]libdns.RR)
	for _, r := range records {
		k := key(r.Name, r.Type)
		inHash[k] = append(inHash[k], r)
	}
	return inHash
}

func convertNamesToAbsolute(zone string, records []libdns.Record) []libdns.RR {
	out := make([]libdns.RR, len(records))
	for i, r := range records {
		svcb, ok := r.(libdns.ServiceBinding)
		if ok {
			out[i] = svcbToRr(svcb)
		} else {
			out[i] = r.RR()
		}
	}
	for i := range out {
		name := libdns.AbsoluteName(out[i].Name, zone)
		if !strings.HasSuffix(name, ".") {
			name = name + "."
		}
		out[i].Name = name
		if out[i].Type == "TXT" {
			out[i].Data = txtsanitize.TXTSanitize(out[i].Data)
		}
	}
	return out
}

// This function is taken from libdns itself.
func svcbToRr(s libdns.ServiceBinding) libdns.RR {
	var name string
	var recType string
	if s.Scheme == "https" || s.Scheme == "http" || s.Scheme == "wss" || s.Scheme == "ws" {
		recType = "HTTPS"
		name = s.Name
		if s.URLSchemePort == 443 || s.URLSchemePort == 80 {
			// Ok, we'll correct your mistake for you.
			s.URLSchemePort = 0
		}
	} else {
		recType = "SVCB"
		name = fmt.Sprintf("_%s.%s", s.Scheme, s.Name)
	}

	if s.URLSchemePort != 0 {
		name = fmt.Sprintf("_%d.%s", s.URLSchemePort, name)
	}

	var params string
	if s.Priority == 0 && len(s.Params) != 0 {
		// The SvcParams should be empty in AliasMode, so we'll fix that for
		// you.
		params = ""
	} else {
		params = paramsToString(s.Params)
	}

	return libdns.RR{
		Name: name,
		TTL:  s.TTL,
		Type: recType,
		Data: fmt.Sprintf("%d %s %s", s.Priority, s.Target, params),
	}
}

// This function is taken from libdns itself and modified to quote ECH params.
func paramsToString(params libdns.SvcParams) string {
	var sb strings.Builder
	for key, vals := range params {
		if sb.Len() > 0 {
			sb.WriteRune(' ')
		}
		sb.WriteString(key)
		var hasVal, needsQuotes bool
		if key == "ech" {
			needsQuotes = true
		}
		for _, val := range vals {
			if len(val) > 0 {
				hasVal = true
			}
			if strings.ContainsAny(val, `" `) {
				needsQuotes = true
			}
			if hasVal && needsQuotes {
				break
			}
		}
		if hasVal {
			sb.WriteRune('=')
		}
		if needsQuotes {
			sb.WriteRune('"')
		}
		for i, val := range vals {
			if i > 0 {
				sb.WriteRune(',')
			}
			val = strings.ReplaceAll(val, `"`, `\"`)
			val = strings.ReplaceAll(val, `,`, `\,`)
			sb.WriteString(val)
		}
		if needsQuotes {
			sb.WriteRune('"')
		}
	}
	return sb.String()
}
