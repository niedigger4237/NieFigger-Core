//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// This experiment is deliberately not called by the live TUN lifecycle yet.
// The caller must hold the same lock as Close, routeUpdate and all other
// native route mutations, verify the TUN/downstream ifindices and protect
// downstream forwarding during a non-atomic multi-message transaction.
type rootTetherKernel interface {
	rules() ([]netlink.Rule, error)
	routes(table int) ([]netlink.Route, error)
	addRule(*netlink.Rule) error
	delRule(*netlink.Rule) error
	addRoute(*netlink.Route) error
	delRoute(*netlink.Route) error
}

type rootTetherNetlink struct{}

func (rootTetherNetlink) rules() ([]netlink.Rule, error) {
	return netlink.RuleList(netlink.FAMILY_ALL)
}
func (rootTetherNetlink) routes(table int) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
}
func (rootTetherNetlink) addRule(r *netlink.Rule) error { return netlink.RuleAdd(r) }
func (rootTetherNetlink) delRule(r *netlink.Rule) error { return netlink.RuleDel(r) }
func (rootTetherNetlink) addRoute(r *netlink.Route) error { return netlink.RouteAdd(r) }
func (rootTetherNetlink) delRoute(r *netlink.Route) error { return netlink.RouteDel(r) }

// RuleList in the pinned netlink version omits action Type and MarkSet.
// Compare only the representation it actually returns; never use these
// normalized copies to delete a rule. Deletions use the generated selector.
func rootTetherRuleKey(r netlink.Rule) netlink.Rule {
	r.Type = 0
	r.MarkSet = false
	if r.Table == 0 { r.Table = -1 }
	return r
}

// A kernel dump supplies defaults absent from the generated route. Normalize
// only documented defaults; any unexpected nexthop, metric, protocol or
// additional route attributes cause preflight to reject the entire update.
func rootTetherRouteKey(r netlink.Route) netlink.Route {
	if r.Dst == nil {
		if r.Family == unix.AF_INET { r.Dst = &net.IPNet{IP:net.IPv4zero.To4(), Mask:net.CIDRMask(0,32)} }
		if r.Family == unix.AF_INET6 { r.Dst = &net.IPNet{IP:net.IPv6zero, Mask:net.CIDRMask(0,128)} }
	}
	if r.Dst != nil {
		bits, size := r.Dst.Mask.Size()
		if size == 32 {
			r.Family = unix.AF_INET
			r.Dst = &net.IPNet{IP:r.Dst.IP.To4(), Mask:net.CIDRMask(bits,size)}
		} else if size == 128 {
			r.Family = unix.AF_INET6
			r.Dst = &net.IPNet{IP:r.Dst.IP.To16(), Mask:net.CIDRMask(bits,size)}
		}
	}
	if r.Gw != nil {
		if r.Family == unix.AF_INET { r.Gw = r.Gw.To4() } else { r.Gw = r.Gw.To16() }
	}
	if r.Protocol == 0 { r.Protocol = netlink.RouteProtocol(unix.RTPROT_BOOT) }
	if r.Type == 0 { r.Type = unix.RTN_UNICAST }
	// Linux assigns the default user IPv6 route metric when omitted.
	if r.Family == unix.AF_INET6 && r.Priority == 0 { r.Priority = 1024 }
	return r
}

type rootTetherState struct {
	rules []netlink.Rule
	routes []netlink.Route
}

func rootTetherStateOf(rules []*netlink.Rule, routes []netlink.Route) rootTetherState {
	s := rootTetherState{}
	for _, r := range rules { s.rules = append(s.rules, rootTetherRuleKey(*r)) }
	for _, r := range routes { s.routes = append(s.routes, rootTetherRouteKey(r)) }
	return s
}

func rootTetherRead(k rootTetherKernel, p *rootTetherPlan) (rootTetherState,error) {
	rules, err := k.rules()
	if err != nil { return rootTetherState{}, err }
	routes, err := k.routes(p.next.IPRoute2TableIndex)
	if err != nil { return rootTetherState{}, err }
	s := rootTetherState{}
	for _, r := range rules {
		if r.Priority >= p.next.IPRoute2RuleIndex && r.Priority <= p.next.IPRoute2RuleIndex+10 {
			s.rules = append(s.rules, rootTetherRuleKey(r))
		}
	}
	for _, r := range routes {
		if r.Table != p.next.IPRoute2TableIndex { return rootTetherState{}, fmt.Errorf("unexpected table in dump") }
		s.routes = append(s.routes, rootTetherRouteKey(r))
	}
	return s,nil
}

// Multiset equality also rejects duplicate rules, not merely missing entries.
func rootTetherEqualSet[T any](a,b []T) bool {
	if len(a) != len(b) { return false }
	used := make([]bool,len(b))
	for _, x := range a {
		found := false
		for i,y := range b {
			if !used[i] && reflect.DeepEqual(x,y) { used[i], found = true,true; break }
		}
		if !found { return false }
	}
	return true
}
func (s rootTetherState) equal(t rootTetherState) bool {
	return rootTetherEqualSet(s.rules,t.rules) && rootTetherEqualSet(s.routes,t.routes)
}

type rootTetherOp struct {
	add bool
	rule *netlink.Rule
	route *netlink.Route
}

func rootTetherEdit[T any](a []T, x T, add bool) ([]T,error) {
	out := append([]T(nil),a...)
	for i,y := range out {
		if reflect.DeepEqual(x,y) {
			if add { return nil, fmt.Errorf("duplicate object") }
			return append(out[:i],out[i+1:]...),nil
		}
	}
	if !add { return nil, fmt.Errorf("missing object") }
	return append(out,x),nil
}
func (o rootTetherOp) predict(s rootTetherState) (rootTetherState,error) {
	var err error
	if o.rule != nil { s.rules,err = rootTetherEdit(s.rules,rootTetherRuleKey(*o.rule),o.add) } else {
		s.routes,err = rootTetherEdit(s.routes,rootTetherRouteKey(*o.route),o.add)
	}
	return s,err
}
func (o rootTetherOp) execute(k rootTetherKernel) error {
	if o.rule != nil {
		if o.add { return k.addRule(o.rule) }
		return k.delRule(o.rule)
	}
	if o.add { return k.addRoute(o.route) }
	return k.delRoute(o.route)
}
func (o rootTetherOp) inverse() rootTetherOp { o.add = !o.add; return o }

// A non-nil uncertainty error means the caller MUST NOT continue with the old
// or new snapshot as if it were confirmed: require verified lifecycle recovery.
var errRootTetherUncertain = errors.New("ROOT TUN kernel state not confirmed")

type rootTetherStep struct {
	op rootTetherOp
	before, after rootTetherState
}

// runRootTetherTransaction performs only exact add/delete operations, never
// flushes tables, never uses RouteReplace, and never resets the TUN interface.
// It checks the entire owned table and policy window before and after each
// mutation. Netlink ACK failure alone is not proof the operation did not run.
func runRootTetherTransaction(k rootTetherKernel, p *rootTetherPlan) error {
	if k == nil || p == nil { return fmt.Errorf("missing tether transaction") }
	old := rootTetherStateOf(p.oldRules,p.oldRoutes)
	want := rootTetherStateOf(p.newRules,p.newRoutes)
	current,err := rootTetherRead(k,p)
	if err != nil { return err }
	if !current.equal(old) { return fmt.Errorf("ROOT TUN preflight: owned routes or rules differ") }
	var ops []rootTetherOp
	// Withdraw obsolete selectors before route changes. Add new routes before
	// deleting obsolete routes to reduce gaps; admit new selectors last.
	// This is not atomic: integration must guard forwarding while in progress.
	for _,r := range p.removeRules { ops = append(ops,rootTetherOp{rule:r}) }
	for i := range p.addRoutes { ops = append(ops,rootTetherOp{add:true,route:&p.addRoutes[i]}) }
	for i := range p.removeRoutes { ops = append(ops,rootTetherOp{route:&p.removeRoutes[i]}) }
	for _,r := range p.addRules { ops = append(ops,rootTetherOp{add:true,rule:r}) }
	// Prove the entire delta before touching the kernel.
	predicted := old
	for _,op := range ops {
		predicted,err = op.predict(predicted)
		if err != nil { return err }
	}
	if !predicted.equal(want) { return fmt.Errorf("invalid ROOT TUN delta") }
	var journal []rootTetherStep
	rollback := func(cause error) error {
		for i:=len(journal)-1;i>=0;i-- {
			step := journal[i]
			state,e := rootTetherRead(k,p)
			if e != nil || !state.equal(step.after) {
				return errors.Join(cause,errRootTetherUncertain,fmt.Errorf("rollback precondition changed: %v",e))
			}
			undoErr := step.op.inverse().execute(k)
			state,e = rootTetherRead(k,p)
			if e != nil || !state.equal(step.before) {
				return errors.Join(cause,errRootTetherUncertain,fmt.Errorf("rollback verification: %v / %v",undoErr,e))
			}
		}
		state,e := rootTetherRead(k,p)
		if e != nil || !state.equal(old) { return errors.Join(cause,errRootTetherUncertain) }
		return cause
	}
	for _,op := range ops {
		observed,e := rootTetherRead(k,p)
		if e != nil || !observed.equal(current) {
			return errors.Join(errRootTetherUncertain,fmt.Errorf("kernel changed before mutation: %v",e))
		}
		after,e := op.predict(current)
		if e != nil { return rollback(e) }
		ack := op.execute(k)
		observed,e = rootTetherRead(k,p)
		if e != nil { return errors.Join(errRootTetherUncertain,ack,e) }
		if observed.equal(after) {
			journal = append(journal,rootTetherStep{op,current,after})
			current = after
			if ack != nil { return rollback(ack) }
		} else if observed.equal(current) {
			if ack == nil { ack = fmt.Errorf("kernel ACK did not produce expected state") }
			return rollback(ack)
		} else {
			// External mutation or unreadable partial result: do not delete
			// objects whose ownership can no longer be verified.
			return errors.Join(errRootTetherUncertain,ack,fmt.Errorf("unexpected post-operation state"))
		}
	}
	final,e := rootTetherRead(k,p)
	if e != nil || !final.equal(want) { return errors.Join(errRootTetherUncertain,e) }
	return nil
}
