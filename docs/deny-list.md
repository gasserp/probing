# Deny list

The deny list turns accepted observations into files that firewalls can load
directly. Like every other public value, entries are **self-reported suspected
probes** with an expiry date, not a verdict.

## Lists

One list covers every service. An address that probes SSH is not trusted on
HTTP, and the reverse.

There are two lists, which differ in how long an address stays listed and how
much evidence it needs:

| List | Listed while | Evidence required |
|---|---|---|
| `recent` | last qualifying event ended less than 72 hours ago | one qualifying event |
| `persistent` | last qualifying event ended less than 30 days ago | qualifying events from at least 2 different `source_id`s, or on at least 3 different UTC days, within those 30 days |

The expiry is a sliding window measured from the address's last qualifying
event, not from when it was first seen. An address that keeps probing stays
listed, and one that stops ages out on its own.

`persistent` is the one for long-lived rules. `recent` is more aggressive but
forgets quickly, so a wrong entry disappears within three days.

Today every registered sensor belongs to the maintainer, so "2 different
sources" does not yet mean "confirmed by an independent operator", and the
3-day rule carries most `persistent` entries. Once other operators contribute,
the rule should require 2 different operators.

## Qualifying events

Only batches that central ingestion accepted count. The sensor kind comes from
the registry, never from the sensor.

| Source kind | Observation | Qualifies when |
|---|---|---|
| `decoy` | SSH authentication failure | always |
| `decoy` | HTTP rule match | always |
| `host` | HTTP rule match | always |
| `host` | SSH authentication failure | the same source reports at least 2 different usernames from that address within one UTC hour |

On a real host, a single user can mistype a password, run a cron job with a
stale credential, or offer several keys from an SSH agent, and so produce many
failures for one account. Legitimate users rarely fail with two different
usernames in the same hour, but scanners nearly always do. A scanner that only
ever tries `root` against a `host` sensor is therefore missed. Decoys still
catch it, and for a list that anyone may consume, a miss costs less than a
false listing. The failure count alone never qualifies an address.

Collectors close batches on UTC hour boundaries, so the 2-username rule is
evaluated within one batch. An hour split across two batches (a late event) is
not combined; this can only cause a miss, never a false listing.

Every counted event is evaluated at the end of its UTC hour bucket.

## Addresses

- IPv4 addresses are listed individually.
- IPv6 addresses are listed as their `/64`, because a single host usually
  controls a whole `/64` and can rotate through it.
- IPv4-mapped IPv6 addresses are listed as IPv4.

### Never listed

These are filtered when the lists are written, so changing them takes effect
on the next run without touching the stored state:

- unspecified, loopback, private, link-local, multicast, carrier-grade NAT
  (`100.64.0.0/10`), documentation, benchmarking, and other special-purpose
  ranges from the IANA IPv4 and IPv6 special-purpose registries;
- the CIDRs in `registry/never-block.json` in `probing-data`, which the
  maintainer reviews like the source registry. It holds critical shared
  infrastructure such as public DNS resolvers, and the public addresses of
  every registered sensor, which each registration adds.

`registry/never-block.json` is strict JSON:

```json
{
  "schema_version": "probing.never-block/v1",
  "entries": [
    {"cidr": "1.1.1.1/32", "reason": "Cloudflare public DNS resolver"}
  ]
}
```

A never-block entry that matches an address removes it from both lists. If the
file is missing, only the built-in special-purpose ranges apply.

## State

The acceptance ledger gains one record per address (IPv6: per `/64`), updated
in the same atomic acceptance step as the rest of the ledger, so each batch
counts exactly once:

```json
"deny_list": {
  "198.51.100.7": {
    "last_seen": "2026-09-30T14:00:00Z",
    "days": ["2026-09-12", "2026-09-29", "2026-09-30"],
    "sources": {"gasserp-azure-weu-01": "2026-09-30", "alice-home-pi-01": "2026-09-12"}
  }
}
```

(The address above comes from a documentation range and would itself never be
listed.)

- `last_seen` is the end of the latest qualifying hour bucket.
- `days` holds the UTC days with a qualifying event, newest 31 at most.
- `sources` maps each `source_id` to its latest qualifying day.

Each run deletes days and sources older than 30 days, and records whose
`last_seen` is older than 30 days. The ledger holds at most 50,000 records.
When a batch would exceed that, the records with the oldest `last_seen` are
evicted first. Reaching the cap never quarantines a batch.

The state starts empty: only batches accepted after this feature shipped
count, so `recent` fills within hours and `persistent` within days.

## Output

The hourly `pages` workflow builds the lists from the committed ledger and
`registry/never-block.json` with `probing-deny-list`, then publishes them with
the dashboard:

```text
https://gasserp.github.io/probing/deny-list/recent.txt
https://gasserp.github.io/probing/deny-list/recent.nft
https://gasserp.github.io/probing/deny-list/recent.ipset
https://gasserp.github.io/probing/deny-list/persistent.txt
https://gasserp.github.io/probing/deny-list/persistent.nft
https://gasserp.github.io/probing/deny-list/persistent.ipset
```

They are not committed to `probing-data`: every entry's remaining time changes
on every run, so hourly commits would rewrite every line and grow the
repository without bound. Building them hourly, rather than daily, keeps the
72-hour window accurate to the hour and lists a new scanner within about two
hours of its batch. Before publishing, the workflow loads every file into
`nft` and `ipset` in a throwaway network namespace, so a file that a firewall
would reject is never deployed; the previous version stays live and its
entries keep expiring.

Entries are sorted, IPv4 before IPv6. Every file starts with comment lines
giving the label, the list, the generation time, and a link to this document.

Every entry in the nftables and ipset files carries its own remaining time,
`last_seen` plus the window minus the generation time, rounded up to whole
seconds. A firewall that stops pulling updates therefore still expires every
entry by itself, after at most 72 hours or 30 days. The kernel caps ipset
timeouts at 2,147,483 seconds (about 24.8 days), so `persistent.ipset`
entries last at most that long.

### Plain text

One address or `/64` per line. For pfSense or OPNsense URL table aliases,
cloud firewall lists, or scripts. The header lines start with `#`; if a tool
does not skip comments, strip them with `grep -v '^#'`.

### nftables

The file declares the sets if they don't exist yet, then empties and refills
them in one transaction, so loading it with `nft -f` never leaves a gap:

```nft
table inet probing {
  set recent_v4 { type ipv4_addr; flags timeout; }
  set recent_v6 { type ipv6_addr; flags interval, timeout; }
}
flush set inet probing recent_v4
flush set inet probing recent_v6
add element inet probing recent_v4 { 198.51.100.7 timeout 212400s, … }
add element inet probing recent_v6 { 2001:db8:1:2::/64 timeout 3600s, … }
```

An `add element` line is left out when its set has no entries. The file never
declares chains or rules. Consumers load their own drop rule once, in the same
table, because nftables sets can only be referenced from their own table:

```nft
table inet probing {
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr @recent_v4 drop
    ip6 saddr @recent_v6 drop
  }
}
```

### ipset

For iptables. Load with `ipset restore -exist`. The file fills temporary sets
and swaps them in atomically:

```text
create probing-recent-v4 hash:ip family inet timeout 259200
create probing-recent-v4-new hash:ip family inet timeout 259200
flush probing-recent-v4-new
add probing-recent-v4-new 198.51.100.7 timeout 212400
swap probing-recent-v4-new probing-recent-v4
destroy probing-recent-v4-new
```

IPv6 uses `hash:net family inet6` with the same pattern.

### fail2ban

fail2ban bans addresses it finds in log files; it does not load external
lists. Load the nftables or ipset file on the same host instead, and keep
fail2ban for what it sees locally. Pushing list entries in with
`fail2ban-client set <jail> banip` would tie them to the jail's own ban time
and database, and would lose the per-entry expiry.

## Fetching

For example, hourly from cron:

```sh
curl -fsS https://gasserp.github.io/probing/deny-list/persistent.nft -o /etc/probing/persistent.nft &&
  nft -f /etc/probing/persistent.nft
```

Once an hour is enough; the lists are rebuilt once an hour.
Before loading, check the generation time in the header, and treat a list much
older than a few hours as a sign that ingestion has stopped.

## Removal

A wrongly listed address is removed by adding it to
`registry/never-block.json`. It drops out of both lists on the next ingestion
`pages` run, and consumers that pull hourly drop it within about two hours. Consumers
that stopped pulling drop it when its timeout runs out.
