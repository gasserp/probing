package geoip

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string, compress bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	data := []byte(content)
	if compress {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		data = buffer.Bytes()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCountries(t *testing.T) {
	path := writeFile(t, "country.csv.gz", strings.Join([]string{
		"0.0.0.0,0.255.255.255,ZZ",
		"1.0.0.0,1.0.0.255,AU",
		"1.0.1.0,1.0.3.255,CN",
		"5.0.0.0,5.0.0.255,ch",
		"2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE",
	}, "\n")+"\n", true)
	db, err := LoadCountries(path)
	if err != nil {
		t.Fatal(err)
	}
	for address, want := range map[string]string{
		"0.1.2.3":         "",
		"1.0.0.0":         "AU",
		"1.0.0.255":       "AU",
		"1.0.2.9":         "CN",
		"1.0.4.0":         "",
		"5.0.0.7":         "CH",
		"::ffff:1.0.0.1":  "AU",
		"2001:db8::1":     "DE",
		"2001:db9::1":     "",
		"255.255.255.255": "",
		"::":              "",
	} {
		if got := db.Country(netip.MustParseAddr(address)); got != want {
			t.Errorf("Country(%s) = %q, want %q", address, got, want)
		}
	}
	var missing *Countries
	if got := missing.Country(netip.MustParseAddr("1.0.0.1")); got != "" {
		t.Errorf("nil database returned %q", got)
	}
}

func TestNetworks(t *testing.T) {
	path := writeFile(t, "asn.csv", strings.Join([]string{
		`1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."`,
		`1.0.4.0,1.0.7.255,38803,"Gtelecom Pty Ltd"`,
		`1.0.8.0,1.0.8.255,0,"Reserved"`,
	}, "\n")+"\n", false)
	db, err := LoadNetworks(path)
	if err != nil {
		t.Fatal(err)
	}
	network, ok := db.Network(netip.MustParseAddr("1.0.0.9"))
	if !ok || network.Number != 13335 || network.Name != "Cloudflare, Inc." {
		t.Errorf("Network(1.0.0.9) = %+v, %v", network, ok)
	}
	if _, ok := db.Network(netip.MustParseAddr("1.0.8.1")); ok {
		t.Error("AS0 range resolved")
	}
	if _, ok := db.Network(netip.MustParseAddr("1.0.2.1")); ok {
		t.Error("gap resolved")
	}
}

func TestRejectsMalformedDatabases(t *testing.T) {
	for name, content := range map[string]string{
		"unordered": "1.0.1.0,1.0.1.255,CN\n1.0.0.0,1.0.0.255,AU\n",
		"inverted":  "1.0.1.0,1.0.0.255,CN\n",
		"mixed":     "1.0.0.0,::1,CN\n",
		"code":      "1.0.0.0,1.0.0.255,C1\n",
		"fields":    "1.0.0.0,1.0.0.255\n",
		"empty":     "",
	} {
		if _, err := LoadCountries(writeFile(t, name+".csv", content, false)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
