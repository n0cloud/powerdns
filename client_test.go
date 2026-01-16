package powerdns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/joeig/go-powerdns/v3"
	"github.com/libdns/libdns"
)

func TestPDNSClient(t *testing.T) {
	var docker string
	var ok bool
	doRun, _ := strconv.ParseBool(os.Getenv("PDNS_RUN_INTEGRATION_TEST"))
	if !doRun {
		t.Skip("skipping because PDNS_RUN_INTEGRATION_TEST was not set")
	}
	if docker, ok = which("docker"); !ok {
		t.Skip("docker compose is not present, skipping")
	}
	err := runCmd(docker, "compose", "rm", "-sfv")
	if err != nil {
		t.Fatalf("docker compose failed: %s", err)
	}
	err = runCmd(docker, "compose", "down", "-v")
	if err != nil {
		t.Fatalf("docker compose failed: %s", err)
	}
	err = runCmd(docker, "compose", "up", "-d")
	if err != nil {
		t.Fatalf("docker compose failed: %s", err)
	}
	defer func() {
		if skipCleanup, _ := strconv.ParseBool(os.Getenv("PDNS_SKIP_CLEANUP")); !skipCleanup {
			runCmd(docker, "compose", "down", "-v")
		}
	}()

	time.Sleep(time.Second * 30) // give everything time to finish coming up

	p := &Provider{
		ServerURL: "http://localhost:8081",
		ServerID:  "localhost",
		APIToken:  "secret",
		Debug:     os.Getenv("PDNS_DEBUG"),
	}
	c, err := p.client()
	if err != nil {
		t.Fatalf("could not create client: %s", err)
	}

	// Create test zone using the new library
	ctx := context.Background()
	zoneName := "example.org."
	nameservers := []string{"ns1.example.org.", "ns2.example.org."}

	_, err = c.Zones.AddNative(ctx, zoneName, false, "", false, "", "", false, nameservers)
	if err != nil {
		t.Fatalf("failed to create test zone: %s", err)
	}

	// Add initial records to the zone
	err = c.Records.Add(ctx, zoneName, "1.example.org.", powerdns.RRTypeA, 60, []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"})
	if err != nil {
		t.Fatalf("failed to add A records: %s", err)
	}

	err = c.Records.Add(ctx, zoneName, "1.example.org.", powerdns.RRTypeTXT, 60, []string{`"This is text"`})
	if err != nil {
		t.Fatalf("failed to add TXT record: %s", err)
	}

	err = c.Records.Add(ctx, zoneName, "2.example.org.", powerdns.RRTypeA, 60, []string{"127.0.0.4", "127.0.0.5", "127.0.0.6"})
	if err != nil {
		t.Fatalf("failed to add A records for subdomain 2: %s", err)
	}

	for _, table := range []struct {
		name      string
		operation string
		zone      string
		Type      string
		records   []libdns.Record
		want      []string
	}{
		{
			name:      "Test Get Zone",
			operation: "records",
			zone:      "example.org.",
			records:   nil,
			Type:      "A",
			want:      []string{"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3", "2:127.0.0.4", "2:127.0.0.5", "2:127.0.0.6"},
		},
		{
			name:      "Test Append Zone A record",
			operation: "append",
			zone:      "example.org.",
			Type:      "A",
			records: []libdns.Record{
				libdns.Address{
					Name: "2",
					IP:   netip.MustParseAddr("127.0.0.7"),
				},
			},
			want: []string{"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3",
				"2:127.0.0.4", "2:127.0.0.5", "2:127.0.0.6", "2:127.0.0.7"},
		},
		{
			name:      "Test Append Zone TXT record",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records: []libdns.Record{
				libdns.TXT{
					Name: "1",
					Text: "\"This is also some text\"",
				},
			},
			want: []string{
				`1:"This is text"`,
				`1:"This is also some text"`,
			},
		},
		{
			name:      "Test Append Zone TXT record with weird formatting",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records: []libdns.Record{
				libdns.TXT{
					Name: "1",
					Text: "This is some weird text that isn't quoted",
				},
			},
			want: []string{
				`1:"This is text"`,
				`1:"This is also some text"`,
				`1:"This is some weird text that isn't quoted"`,
			},
		},
		{
			name:      "Test Append Zone TXT record with embedded quotes",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records: []libdns.Record{
				libdns.TXT{
					Name: "1",
					Text: `This is some weird text that "has embedded quoting"`,
				},
			},
			want: []string{`1:"This is text"`, `1:"This is also some text"`,
				`1:"This is some weird text that isn't quoted"`,
				`1:"This is some weird text that \"has embedded quoting\""`},
		},
		{
			name:      "Test Append Zone TXT record with unicode",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records: []libdns.Record{
				libdns.TXT{
					Name: "1",
					Text: `ç is equal to \195\167`,
				},
			},
			want: []string{`1:"This is text"`, `1:"This is also some text"`,
				`1:"This is some weird text that isn't quoted"`,
				`1:"This is some weird text that \"has embedded quoting\""`,
				`1:"ç is equal to \195\167"`,
			},
		},
		{
			name:      "Test Delete Zone",
			operation: "delete",
			zone:      "example.org.",
			Type:      "A",
			records: []libdns.Record{
				libdns.Address{
					Name: "2",
					IP:   netip.MustParseAddr("127.0.0.5"),
				},
			},
			want: []string{"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3", "2:127.0.0.4", "2:127.0.0.6", "2:127.0.0.7"},
		},
		{
			name:      "Test Append and Add Zone",
			operation: "append",
			zone:      "example.org.",
			Type:      "A",
			records: []libdns.Record{
				libdns.Address{
					Name: "2",
					IP:   netip.MustParseAddr("127.0.0.8"),
				},
				libdns.Address{
					Name: "3",
					IP:   netip.MustParseAddr("127.0.0.9"),
				},
			},
			want: []string{"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3",
				"2:127.0.0.4", "2:127.0.0.6", "2:127.0.0.7", "2:127.0.0.8",
				"3:127.0.0.9"},
		},
		{
			name:      "Test Set",
			operation: "set",
			zone:      "example.org.",
			Type:      "A",
			records: []libdns.Record{
				libdns.Address{
					Name: "2",
					IP:   netip.MustParseAddr("127.0.0.1"),
				},
				libdns.Address{
					Name: "1",
					IP:   netip.MustParseAddr("127.0.0.1"),
				},
			},
			want: []string{"1:127.0.0.1", "2:127.0.0.1", "3:127.0.0.9"},
		},
	} {
		t.Run(table.name, func(t *testing.T) {
			var err error
			switch table.operation {
			case "records":
				// fetch below
			case "append":
				_, err = p.AppendRecords(context.Background(), table.zone, table.records)
			case "set":
				_, err = p.SetRecords(context.Background(), table.zone, table.records)
			case "delete":
				_, err = p.DeleteRecords(context.Background(), table.zone, table.records)
			}

			if err != nil {
				t.Errorf("failed to %s records: %s", table.operation, err)
				return
			}

			// Fetch the zone
			recs, err := p.GetRecords(context.Background(), table.zone)
			if err != nil {
				t.Errorf("error fetching zone")
				return
			}
			var have []string
			for _, rr := range recs {
				if rr.RR().Type != table.Type {
					continue
				}
				have = append(have, fmt.Sprintf("%s:%s", rr.RR().Name, rr.RR().Data))
			}

			sort.Strings(have)
			sort.Strings(table.want)
			if !reflect.DeepEqual(have, table.want) {
				t.Errorf("assertion failed: have: %#v want %#v", have, table.want)
			}

		})
	}

}

func which(cmd string) (string, bool) {
	pth, err := exec.LookPath(cmd)
	if err != nil {
		return "", false
	}
	return pth, true
}

func runCmd(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
