//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"sort"

	"github.com/sagernet/netlink"
)

// Experimental: build a delta from sing-tun's existing route/rule generators.
// No kernel mutation, no changes to NativeTun.options or its live TUN fd.
type rootTetherPlan struct {
	next Options
	oldRules, newRules []*netlink.Rule
	oldRoutes, newRoutes []netlink.Route
	addRules, removeRules []*netlink.Rule
	addRoutes, removeRoutes []netlink.Route
}

type rootTetherExclusions struct {
	v4, v6 []netip.Prefix
}

// The caller must retain the immutable effective exclusions from startup,
// including SRS-derived ranges. Only the separately tracked tether ranges
// may be replaced. An unexpected current config aborts the transaction.
func rootTetherUnion(base, dynamic []netip.Prefix, ipv4 bool) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(base)+len(dynamic))
	seen := make(map[netip.Prefix]bool)
	for _, group := range [][]netip.Prefix{base, dynamic} {
		for _, p := range group {
			if !p.IsValid() || p.Addr().Is4() != ipv4 || p.Addr().Is4In6() {
				return nil, fmt.Errorf("invalid route exclusion %v", p)
			}
			p = p.Masked()
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() == out[j].Addr() {
			return out[i].Bits() < out[j].Bits()
		}
		return out[i].Addr().Less(out[j].Addr())
	})
	return out, nil
}

func rootTetherNames(downstreams []string, tunName string) ([]string, error) {
	names := []string{"lo"}
	seen := map[string]bool{"lo": true}
	for _, name := range downstreams {
		if len(name) == 0 || len(name) > 15 || name == "." || name == ".." ||
			name == tunName || name == "hevtun0" || name == "all" || name == "default" || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate downstream %q", name)
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return nil, fmt.Errorf("non-exact downstream %q", name)
			}
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names[1:])
	return names, nil
}

func rootTetherDifference[T any](a, b []T) []T {
	var result []T
	for _, x := range a {
		found := false
		for _, y := range b {
			if reflect.DeepEqual(x, y) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, x)
		}
	}
	return result
}

func rootTetherSamePrefixes(a, b []netip.Prefix, ipv4 bool) bool {
	aa, err := rootTetherUnion(a, nil, ipv4)
	if err != nil { return false }
	bb, err := rootTetherUnion(b, nil, ipv4)
	return err == nil && reflect.DeepEqual(aa, bb)
}

func rootTetherSelectorRule(r *netlink.Rule, allowed []string) bool {
	if r == nil || r.IifName == "lo" || r.IifName == "" || r.Goto < 0 {
		return false
	}
	// A change may only be a plain input-interface GOTO rule, not
	// a UID, mark, source, destination or global-priority rule.
	expected := netlink.NewRule()
	expected.Family, expected.Priority = r.Family, r.Priority
	expected.IifName, expected.Goto = r.IifName, r.Goto
	if !reflect.DeepEqual(r, expected) { return false }
	for _, name := range allowed {
		if name == r.IifName { return true }
	}
	return false
}

func planRootTetherRefresh(current Options, link netlink.Link, base, oldDynamic, newDynamic rootTetherExclusions, downstreams []string) (*rootTetherPlan, error) {
	if current.Name != "asterisk0" || !current.AutoRoute || current.AutoRedirectMarkMode ||
		current.FileDescriptor != 0 || current.EXP_ExternalConfiguration || current.NetNs != "" ||
		current.IPRoute2TableIndex <= 0 || current.IPRoute2RuleIndex <= 0 ||
		current.IPRoute2TableIndex == 253 || current.IPRoute2TableIndex == 254 || current.IPRoute2TableIndex == 255 ||
		(runtime.GOOS == "android" && current.InterfaceMonitor == nil) ||
		len(current.ExcludeInterface) != 0 || len(current.IncludeInterface) == 0 ||
		current.IncludeInterface[0] != "lo" || link == nil || link.Attrs().Index <= 0 ||
		link.Attrs().Name != current.Name {
		return nil, fmt.Errorf("unsupported managed ROOT TUN configuration")
	}
	oldNames, err := rootTetherNames(current.IncludeInterface[1:], current.Name)
	if err != nil { return nil, err }
	newNames, err := rootTetherNames(downstreams, current.Name)
	if err != nil { return nil, err }
	old4, err := rootTetherUnion(base.v4, oldDynamic.v4, true)
	if err != nil { return nil, err }
	old6, err := rootTetherUnion(base.v6, oldDynamic.v6, false)
	if err != nil { return nil, err }
	if !rootTetherSamePrefixes(current.Inet4RouteExcludeAddress, old4, true) ||
		!rootTetherSamePrefixes(current.Inet6RouteExcludeAddress, old6, false) {
		return nil, fmt.Errorf("effective exclusions differ from startup baseline")
	}
	next := current
	next.IncludeInterface = newNames
	next.Inet4RouteExcludeAddress, err = rootTetherUnion(base.v4, newDynamic.v4, true)
	if err != nil { return nil, err }
	next.Inet6RouteExcludeAddress, err = rootTetherUnion(base.v6, newDynamic.v6, false)
	if err != nil { return nil, err }
	// Generate using isolated instances: do not mutate the running NativeTun.
	oldTun, newTun := &NativeTun{options: current}, &NativeTun{options: next}
	oldRules, newRules := oldTun.rules(), newTun.rules()
	p := &rootTetherPlan{next: next, oldRules: oldRules, newRules: newRules,
		addRules: rootTetherDifference(newRules, oldRules),
		removeRules: rootTetherDifference(oldRules, newRules)}
	for _, r := range p.addRules {
		if !rootTetherSelectorRule(r, newNames) { return nil, fmt.Errorf("unexpected added policy rule") }
	}
	for _, r := range p.removeRules {
		if !rootTetherSelectorRule(r, oldNames) { return nil, fmt.Errorf("unexpected removed policy rule") }
	}
	oldRoutes, err := oldTun.routes(link)
	if err != nil { return nil, err }
	newRoutes, err := newTun.routes(link)
	if err != nil { return nil, err }
	p.oldRoutes, p.newRoutes = oldRoutes, newRoutes
	p.addRoutes = rootTetherDifference(newRoutes, oldRoutes)
	p.removeRoutes = rootTetherDifference(oldRoutes, newRoutes)
	return p, nil
}
