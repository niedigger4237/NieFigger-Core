//go:build linux

package tun

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/sagernet/netlink"
)

type rootTetherLink struct {
	name string
	index int
}

type rootTetherRefreshRequest struct {
	base, oldDynamic, newDynamic rootTetherExclusions
	downstreams []rootTetherLink
}

type rootTetherLookup func(string) (netlink.Link, error)

func verifyRootTetherLink(lookup rootTetherLookup, name string, index int) (netlink.Link, error) {
	if index <= 0 { return nil, fmt.Errorf("invalid ifindex: %s", name) }
	link, err := lookup(name)
	if err != nil { return nil, err }
	if link == nil || link.Attrs() == nil || link.Attrs().Name != name || link.Attrs().Index != index {
		return nil, fmt.Errorf("link identity changed: %s", name)
	}
	return link, nil
}

// Guard all kernel operations. If a link or Android VPN policy changes
// during a transaction, require recovery rather than trusting a stale name.
type rootTetherCheckedKernel struct {
	rootTetherKernel
	check func() error
}
func (k rootTetherCheckedKernel) rules() ([]netlink.Rule,error) {
	if err:=k.check();err!=nil{return nil,err};return k.rootTetherKernel.rules()
}
func (k rootTetherCheckedKernel) routes(table int) ([]netlink.Route,error) {
	if err:=k.check();err!=nil{return nil,err};return k.rootTetherKernel.routes(table)
}
func (k rootTetherCheckedKernel) addRule(r *netlink.Rule) error {
	if err:=k.check();err!=nil{return err};return k.rootTetherKernel.addRule(r)
}
func (k rootTetherCheckedKernel) delRule(r *netlink.Rule) error {
	if err:=k.check();err!=nil{return err};return k.rootTetherKernel.delRule(r)
}
func (k rootTetherCheckedKernel) addRoute(r *netlink.Route) error {
	if err:=k.check();err!=nil{return err};return k.rootTetherKernel.addRoute(r)
}
func (k rootTetherCheckedKernel) delRoute(r *netlink.Route) error {
	if err:=k.check();err!=nil{return err};return k.rootTetherKernel.delRoute(r)
}

// Experimental private entry point. Do not connect to IPC until the caller
// can guard forwarding and hold that guard through verified recovery.
func (t *NativeTun) refreshRootTether(r rootTetherRefreshRequest) error {
	if runtime.GOOS!="android" || os.Geteuid()!=0 { return fmt.Errorf("requires Android root") }
	return t.refreshRootTetherWith(r,rootTetherNetlink{},netlink.LinkByName)
}

func (t *NativeTun) refreshRootTetherWith(r rootTetherRefreshRequest, k rootTetherKernel, lookup rootTetherLookup) error {
	t.rootTetherMu.Lock()
	defer t.rootTetherMu.Unlock()
	if t.rootTetherClosed {return os.ErrClosed}
	if t.rootTetherUncertain {return errRootTetherUncertain}
	if !t.rootTetherStarted || t.rootTetherIndex<=0 || k==nil || lookup==nil {return fmt.Errorf("TUN not ready")}
	monitor:=t.options.InterfaceMonitor
	if runtime.GOOS=="android" && monitor==nil {return fmt.Errorf("missing Android monitor")}
	vpn,override:=false,false
	if monitor!=nil {vpn,override=monitor.AndroidVPNEnabled(),monitor.OverrideAndroidVPN()}
	names:=make([]string,0,len(r.downstreams))
	for _,d:=range r.downstreams {names=append(names,d.name)}
	if _,err:=rootTetherNames(names,t.options.Name);err!=nil{return err}
	check:=func()error{
		if monitor!=nil && (vpn!=monitor.AndroidVPNEnabled() || override!=monitor.OverrideAndroidVPN()) {return fmt.Errorf("Android VPN policy changed")}
		if _,err:=verifyRootTetherLink(lookup,t.options.Name,t.rootTetherIndex);err!=nil{return err}
		for _,d:=range r.downstreams {if _,err:=verifyRootTetherLink(lookup,d.name,d.index);err!=nil{return err}}
		return nil
	}
	if err:=check();err!=nil{return err}
	link,err:=verifyRootTetherLink(lookup,t.options.Name,t.rootTetherIndex)
	if err!=nil{return err}
	p,err:=planRootTetherRefresh(t.options,link,r.base,r.oldDynamic,r.newDynamic,names)
	if err!=nil{return err}
	if err=check();err!=nil{return err}
	err=runRootTetherTransaction(rootTetherCheckedKernel{k,check},p)
	if errors.Is(err,errRootTetherUncertain) {t.rootTetherUncertain=true;return err}
	if err!=nil{return err}
	if err=check();err!=nil {t.rootTetherUncertain=true;return errors.Join(errRootTetherUncertain,err)}
	// Do not replace the whole options struct: packet I/O uses its MTU.
	t.options.IncludeInterface=p.next.IncludeInterface
	t.options.Inet4RouteExcludeAddress=p.next.Inet4RouteExcludeAddress
	t.options.Inet6RouteExcludeAddress=p.next.Inet6RouteExcludeAddress
	t.rootTetherManaged=true
	return nil
}
