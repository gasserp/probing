package denylist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	NeverBlockSchemaVersion = "probing.never-block/v1"
	MaxNeverBlockBytes      = 256 << 10
	MaxNeverBlockEntries    = 4096
	maxReasonBytes          = 200

	// maxIPSetTimeout is the kernel's IPSET_MAX_TIMEOUT in seconds.
	maxIPSetTimeout = 2147483 * time.Second

	documentation = "https://github.com/gasserp/probing/blob/main/docs/deny-list.md"
)

type neverBlockFile struct {
	SchemaVersion string            `json:"schema_version"`
	Entries       []neverBlockEntry `json:"entries"`
}

type neverBlockEntry struct {
	CIDR   string `json:"cidr"`
	Reason string `json:"reason"`
}

// LoadNeverBlock reads registry/never-block.json. A missing file means no
// entries.
func LoadNeverBlock(path string) ([]netip.Prefix, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("open never-block list: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxNeverBlockBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read never-block list: %w", err)
	}
	if len(data) > MaxNeverBlockBytes {
		return nil, errors.New("never-block list exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var parsed neverBlockFile
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode never-block list: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("never-block list has trailing data")
	}
	if parsed.SchemaVersion != NeverBlockSchemaVersion {
		return nil, errors.New("never-block list schema is invalid")
	}
	if len(parsed.Entries) > MaxNeverBlockEntries {
		return nil, errors.New("never-block list has too many entries")
	}
	prefixes := make([]netip.Prefix, 0, len(parsed.Entries))
	for i, entry := range parsed.Entries {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil || prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("never-block entry %d has an invalid cidr", i)
		}
		if entry.Reason == "" || len(entry.Reason) > maxReasonBytes || !utf8.ValidString(entry.Reason) {
			return nil, fmt.Errorf("never-block entry %d needs a reason of at most %d bytes", i, maxReasonBytes)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				return nil, fmt.Errorf("never-block entry %d has an invalid cidr", i)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func header(output *strings.Builder, name string, now time.Time) {
	fmt.Fprintf(output, "# probing deny list: %s\n", name)
	output.WriteString("# self-reported suspected probes\n")
	fmt.Fprintf(output, "# generated %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(output, "# %s\n", documentation)
}

func split(entries []Entry) (v4, v6 []Entry) {
	for _, entry := range entries {
		if entry.Prefix.Addr().Is4() {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}
	return v4, v6
}

func element(entry Entry) string {
	if entry.Prefix.Addr().Is4() {
		return entry.Prefix.Addr().String()
	}
	return entry.Prefix.String()
}

// Text renders one address or /64 per line.
func Text(name string, entries []Entry, now time.Time) []byte {
	var output strings.Builder
	header(&output, name, now)
	for _, entry := range entries {
		output.WriteString(element(entry))
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

// NFT renders an nftables script that declares the sets in table inet
// probing, then empties and refills them in one transaction.
func NFT(name string, entries []Entry, now time.Time) []byte {
	var output strings.Builder
	header(&output, name, now)
	fmt.Fprintf(&output, "table inet probing {\n")
	fmt.Fprintf(&output, "\tset %s_v4 { type ipv4_addr; flags timeout; }\n", name)
	fmt.Fprintf(&output, "\tset %s_v6 { type ipv6_addr; flags interval, timeout; }\n", name)
	output.WriteString("}\n")
	fmt.Fprintf(&output, "flush set inet probing %s_v4\n", name)
	fmt.Fprintf(&output, "flush set inet probing %s_v6\n", name)
	v4, v6 := split(entries)
	for _, family := range []struct {
		suffix  string
		entries []Entry
	}{{"v4", v4}, {"v6", v6}} {
		if len(family.entries) == 0 {
			continue
		}
		fmt.Fprintf(&output, "add element inet probing %s_%s {\n", name, family.suffix)
		for i, entry := range family.entries {
			separator := ","
			if i == len(family.entries)-1 {
				separator = ""
			}
			fmt.Fprintf(&output, "\t%s timeout %ds%s\n", element(entry), int64(entry.Timeout/time.Second), separator)
		}
		output.WriteString("}\n")
	}
	return []byte(output.String())
}

// IPSet renders an `ipset restore -exist` script that fills temporary sets
// and swaps them in. Timeouts are capped at the kernel's ipset maximum.
func IPSet(name string, entries []Entry, window time.Duration, now time.Time) []byte {
	var output strings.Builder
	header(&output, name, now)
	v4, v6 := split(entries)
	for _, family := range []struct {
		suffix, kind, family string
		entries              []Entry
	}{{"v4", "hash:ip", "inet", v4}, {"v6", "hash:net", "inet6", v6}} {
		set := "probing-" + name + "-" + family.suffix
		temporary := set + "-new"
		options := fmt.Sprintf("%s family %s timeout %d", family.kind, family.family, ipsetSeconds(window))
		fmt.Fprintf(&output, "create %s %s\n", set, options)
		fmt.Fprintf(&output, "create %s %s\n", temporary, options)
		fmt.Fprintf(&output, "flush %s\n", temporary)
		for _, entry := range family.entries {
			fmt.Fprintf(&output, "add %s %s timeout %d\n", temporary, element(entry), ipsetSeconds(entry.Timeout))
		}
		fmt.Fprintf(&output, "swap %s %s\n", temporary, set)
		fmt.Fprintf(&output, "destroy %s\n", temporary)
	}
	return []byte(output.String())
}

func ipsetSeconds(duration time.Duration) int64 {
	return int64(min(duration, maxIPSetTimeout) / time.Second)
}
