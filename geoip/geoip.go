// Package geoip maps addresses to countries and autonomous systems using the
// range CSV files that DB-IP publishes under CC BY 4.0 ("IP to Country Lite"
// and "IP to ASN Lite"). Both files list one inclusive address range per row,
// sorted by start address, IPv4 before IPv6:
//
//	start,end,CC
//	start,end,ASN,"AS name"
//
// The files may be gzip-compressed. Lookups are a binary search over the
// ranges; nothing is fetched at run time.
package geoip

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Network is an autonomous system as named in the ASN database.
type Network struct {
	Number uint32
	Name   string
}

type addrRange struct {
	start, end netip.Addr
	value      uint32
}

type table struct {
	ranges []addrRange
}

func (t *table) find(address netip.Addr) (uint32, bool) {
	if t == nil || !address.IsValid() {
		return 0, false
	}
	address = address.Unmap().WithZone("")
	index := sort.Search(len(t.ranges), func(i int) bool {
		return t.ranges[i].start.Compare(address) > 0
	})
	if index == 0 {
		return 0, false
	}
	candidate := t.ranges[index-1]
	if address.Compare(candidate.end) > 0 {
		return 0, false
	}
	return candidate.value, true
}

func (t *table) add(start, end string, value uint32) error {
	first, err := netip.ParseAddr(start)
	if err != nil {
		return fmt.Errorf("parse range start %q: %w", start, err)
	}
	last, err := netip.ParseAddr(end)
	if err != nil {
		return fmt.Errorf("parse range end %q: %w", end, err)
	}
	if first.Is4() != last.Is4() || last.Less(first) {
		return fmt.Errorf("invalid range %s-%s", start, end)
	}
	if n := len(t.ranges); n > 0 && !t.ranges[n-1].end.Less(first) {
		return fmt.Errorf("range %s-%s is out of order or overlaps", start, end)
	}
	t.ranges = append(t.ranges, addrRange{first, last, value})
	return nil
}

// Countries resolves addresses to ISO 3166-1 alpha-2 country codes.
type Countries struct {
	table
	codes []string
}

// Country returns the upper-case country code for address, or "" when the
// address is not covered or the database marks it as unknown (ZZ).
func (c *Countries) Country(address netip.Addr) string {
	if c == nil {
		return ""
	}
	index, ok := c.find(address)
	if !ok {
		return ""
	}
	return c.codes[index]
}

// Networks resolves addresses to autonomous systems.
type Networks struct {
	table
	networks []Network
}

// Network returns the autonomous system announcing address.
func (n *Networks) Network(address netip.Addr) (Network, bool) {
	if n == nil {
		return Network{}, false
	}
	index, ok := n.find(address)
	if !ok {
		return Network{}, false
	}
	return n.networks[index], true
}

// LoadCountries reads a DB-IP country CSV, plain or gzip-compressed.
func LoadCountries(path string) (*Countries, error) {
	db := &Countries{}
	index := map[string]uint32{}
	err := readRows(path, 3, func(row []string) error {
		code := strings.ToUpper(strings.TrimSpace(row[2]))
		if code == "ZZ" || code == "" {
			return nil
		}
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			return fmt.Errorf("invalid country code %q", row[2])
		}
		value, ok := index[code]
		if !ok {
			value = uint32(len(db.codes))
			index[code] = value
			db.codes = append(db.codes, code)
		}
		return db.add(row[0], row[1], value)
	})
	if err != nil {
		return nil, fmt.Errorf("load country database: %w", err)
	}
	if len(db.ranges) == 0 {
		return nil, errors.New("load country database: no ranges")
	}
	return db, nil
}

// LoadNetworks reads a DB-IP ASN CSV, plain or gzip-compressed.
func LoadNetworks(path string) (*Networks, error) {
	db := &Networks{}
	index := map[Network]uint32{}
	err := readRows(path, 4, func(row []string) error {
		number, err := strconv.ParseUint(strings.TrimSpace(row[2]), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid AS number %q", row[2])
		}
		if number == 0 {
			return nil
		}
		network := Network{Number: uint32(number), Name: strings.TrimSpace(row[3])}
		value, ok := index[network]
		if !ok {
			value = uint32(len(db.networks))
			index[network] = value
			db.networks = append(db.networks, network)
		}
		return db.add(row[0], row[1], value)
	})
	if err != nil {
		return nil, fmt.Errorf("load ASN database: %w", err)
	}
	if len(db.ranges) == 0 {
		return nil, errors.New("load ASN database: no ranges")
	}
	return db, nil
}

func readRows(path string, fields int, handle func([]string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	buffered := bufio.NewReaderSize(file, 1<<16)
	var input io.Reader = buffered
	if magic, err := buffered.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		decompressed, err := gzip.NewReader(buffered)
		if err != nil {
			return err
		}
		defer decompressed.Close()
		input = decompressed
	}
	reader := csv.NewReader(input)
	reader.FieldsPerRecord = fields
	reader.ReuseRecord = true
	for line := 1; ; line++ {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := handle(row); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
}
