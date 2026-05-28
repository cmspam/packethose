//go:build linux

package packethose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
)

// ClientStat is one client's byte counters as seen by the kernel
// accounting chains. Up is client->internet, Down is internet->client.
type ClientStat struct {
	Addr      netip.Addr
	UpBytes   uint64
	DownBytes uint64
}

// Stats reads the per-client byte counters from the kernel accounting
// sets. It returns nil when accounting is not installed. Counters are
// maintained entirely in the kernel; this only reads them, so polling it
// has no effect on tunnel throughput.
func (n *NFTInstaller) Stats() ([]ClientStat, error) {
	if !n.cfg.Enabled || !n.cfg.Accounting {
		return nil, nil
	}
	byAddr := map[netip.Addr]*ClientStat{}
	get := func(a netip.Addr) *ClientStat {
		s := byAddr[a]
		if s == nil {
			s = &ClientStat{Addr: a}
			byAddr[a] = s
		}
		return s
	}

	read := func(set string, up bool) error {
		out, err := n.listSet(set)
		if err != nil {
			return err
		}
		counters, err := parseNFTSetCounters(out)
		if err != nil {
			return fmt.Errorf("parse %s: %w", set, err)
		}
		for a, bytesN := range counters {
			if up {
				get(a).UpBytes = bytesN
			} else {
				get(a).DownBytes = bytesN
			}
		}
		return nil
	}

	type job struct {
		set string
		up  bool
		on  bool
	}
	jobs := []job{
		{"acct_up4", true, n.cfg.IPv4 && n.cfg.PoolV4.IsValid()},
		{"acct_down4", false, n.cfg.IPv4 && n.cfg.PoolV4.IsValid()},
		{"acct_up6", true, n.cfg.IPv6 && n.cfg.PoolV6.IsValid()},
		{"acct_down6", false, n.cfg.IPv6 && n.cfg.PoolV6.IsValid()},
	}
	for _, j := range jobs {
		if !j.on {
			continue
		}
		if err := read(j.set, j.up); err != nil {
			return nil, err
		}
	}

	out := make([]ClientStat, 0, len(byAddr))
	for _, s := range byAddr {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out, nil
}

func (n *NFTInstaller) listSet(name string) ([]byte, error) {
	cmd := exec.Command(nftBin, "-j", "list", "set", n.cfg.Family, n.cfg.TableName, name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft list set %s: %s", name, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// nft -j set listing shape (only the fields we read):
//
//	{"nftables":[{"metainfo":{...}},
//	  {"set":{"name":"acct_up4","elem":[
//	    {"elem":{"val":"10.66.0.10","counter":{"packets":1,"bytes":42}}}, ...]}}]}
type nftDump struct {
	Nftables []nftDumpItem `json:"nftables"`
}

type nftDumpItem struct {
	Set *nftSetDump `json:"set"`
}

type nftSetDump struct {
	Name string            `json:"name"`
	Elem []json.RawMessage `json:"elem"`
}

type nftElemWrap struct {
	Elem *nftElemBody `json:"elem"`
}

type nftElemBody struct {
	Val     string      `json:"val"`
	Counter *nftCounter `json:"counter"`
}

type nftCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// parseNFTSetCounters extracts per-address byte counts from `nft -j list
// set` output. Elements without a counter (plain membership) are
// skipped. It tolerates the two shapes nft emits for a counted element.
func parseNFTSetCounters(data []byte) (map[netip.Addr]uint64, error) {
	var dump nftDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return nil, err
	}
	out := map[netip.Addr]uint64{}
	for _, item := range dump.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			// Counted elements arrive as {"elem":{"val":...,"counter":...}}.
			var wrap nftElemWrap
			if err := json.Unmarshal(raw, &wrap); err == nil && wrap.Elem != nil && wrap.Elem.Counter != nil {
				if a, err := netip.ParseAddr(wrap.Elem.Val); err == nil {
					out[a] = wrap.Elem.Counter.Bytes
				}
				continue
			}
			// Some versions inline the body without the extra "elem" key.
			var body nftElemBody
			if err := json.Unmarshal(raw, &body); err == nil && body.Counter != nil {
				if a, err := netip.ParseAddr(body.Val); err == nil {
					out[a] = body.Counter.Bytes
				}
			}
		}
	}
	return out, nil
}
