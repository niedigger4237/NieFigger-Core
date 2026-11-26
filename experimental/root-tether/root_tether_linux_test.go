//go:build linux

package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
)

func nfP(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestNieFiggerRootTetherPlan(t *testing.T) {
	base := rootTetherExclusions{v4: []netip.Prefix{nfP("10.0.0.0/8"), nfP("255.255.255.255/32"), nfP("169.254.0.0/16"), nfP("224.0.0.0/24")}}
	old := rootTetherExclusions{v4: []netip.Prefix{nfP("192.168.43.0/24")}}
	next := rootTetherExclusions{v4: []netip.Prefix{nfP("192.168.99.0/24")}}
	current := Options{Name:"asterisk0", AutoRoute:true, IPRoute2TableIndex:2022, IPRoute2RuleIndex:9000,
		Inet4Address: []netip.Prefix{nfP("172.19.0.1/30")}, IncludeInterface: []string{"lo","ap0"}}
	current.Inet4RouteExcludeAddress, _ = rootTetherUnion(base.v4, old.v4, true)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name:"asterisk0", Index:42}}
	p, err := planRootTetherRefresh(current, link, base, old, next, []string{"rndis0"})
	if err != nil { t.Fatal(err) }
	if len(p.addRules) != 1 || len(p.removeRules) != 1 ||
		p.addRules[0].IifName != "rndis0" || p.removeRules[0].IifName != "ap0" {
		t.Fatalf("unexpected selector delta %+v", p)
	}
	if len(p.addRoutes) == 0 || len(p.removeRoutes) == 0 { t.Fatal("missing route delta") }
	for _, prefix := range base.v4 {
		found := false
		for _, actual := range p.next.Inet4RouteExcludeAddress { if actual == prefix { found = true } }
		if !found { t.Fatalf("lost immutable exclusion %v", prefix) }
	}
	if current.IncludeInterface[1] != "ap0" { t.Fatal("mutated live options") }
	same, err := planRootTetherRefresh(current, link, base, old, old, []string{"ap0"})
	if err != nil || len(same.addRules)+len(same.removeRules)+len(same.addRoutes)+len(same.removeRoutes) != 0 { t.Fatalf("non-idempotent: %v %v", same, err) }
	off, err := planRootTetherRefresh(current, link, base, old, rootTetherExclusions{}, nil)
	if err != nil || len(off.next.IncludeInterface) != 1 || off.next.IncludeInterface[0] != "lo" { t.Fatalf("phone-only plan: %v %v", off, err) }
	if _, err = planRootTetherRefresh(current, link, base, old, next, []string{"wlan+"}); err == nil { t.Fatal("wildcard admitted") }
	if _, err = planRootTetherRefresh(current, link, base, rootTetherExclusions{}, next, []string{"rndis0"}); err == nil { t.Fatal("baseline drift admitted") }
}

func TestNieFiggerRootTetherIPv6Exclusions(t *testing.T) {
	base := []netip.Prefix{nfP("fe80::/10"), nfP("ff02::/16"), nfP("fd00::/8")}
	result, err := rootTetherUnion(base, []netip.Prefix{nfP("2001:db8:1::/64"), nfP("fe80::/10")}, false)
	if err != nil || len(result) != 4 { t.Fatalf("IPv6 union: %v %v", result, err) }
	if _, err := rootTetherUnion(base, []netip.Prefix{nfP("192.168.0.0/16")}, false); err == nil { t.Fatal("wrong family admitted") }
}
