//go:build linux && !android

package tun

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/netlink"
)

func TestNieFiggerRootTetherLifecycle(t *testing.T) {
	base:=rootTetherExclusions{v4:[]netip.Prefix{nfP("255.255.255.255/32"),nfP("10.0.0.0/8")}}
	old:=rootTetherExclusions{v4:[]netip.Prefix{nfP("192.168.43.0/24")}}
	next:=rootTetherExclusions{v4:[]netip.Prefix{nfP("192.168.99.0/24")}}
	options:=Options{Name:"asterisk0",AutoRoute:true,IPRoute2TableIndex:2022,IPRoute2RuleIndex:9000,
		Inet4Address:[]netip.Prefix{nfP("172.19.0.1/30")},IncludeInterface:[]string{"lo","ap0"}}
	options.Inet4RouteExcludeAddress,_=rootTetherUnion(base.v4,old.v4,true)
	link:=func(name string,index int) netlink.Link {return &netlink.Dummy{LinkAttrs:netlink.LinkAttrs{Name:name,Index:index}}}
	p,err:=planRootTetherRefresh(options,link("asterisk0",42),base,old,next,[]string{"rndis0"})
	if err!=nil {t.Fatal(err)}
	initial:=rootTetherStateOf(p.oldRules,p.oldRoutes)
	req:=rootTetherRefreshRequest{base:base,oldDynamic:old,newDynamic:next,downstreams:[]rootTetherLink{{"rndis0",55}}}
	native:=&NativeTun{options:options,rootTetherIndex:42}
	fake:=&rootTetherFake{state:initial}
	lookup:=func(name string)(netlink.Link,error){
		if name=="asterisk0"{return link(name,42),nil}
		if name=="rndis0"{return link(name,55),nil}
		return nil,errors.New("unknown link")
	}
	if err=native.refreshRootTetherWith(req,fake,lookup);err==nil||fake.calls!=0{t.Fatal("refresh before start")}
	native.rootTetherStarted=true
	req.downstreams[0].index=56
	if err=native.refreshRootTetherWith(req,fake,lookup);err==nil||fake.calls!=0{t.Fatal("reused link accepted")}
	req.downstreams[0].index=55
	if err=native.refreshRootTetherWith(req,fake,lookup);err!=nil{t.Fatal(err)}
	if !native.rootTetherManaged||native.options.IncludeInterface[1]!="rndis0"||!fake.state.equal(rootTetherStateOf(p.newRules,p.newRoutes)){t.Fatal("snapshot not committed")}
	if err=native.UpdateRouteOptions(options);err==nil{t.Fatal("generic update admitted")}
	native.rootTetherClosed=true
	if err=native.refreshRootTetherWith(req,fake,lookup);!errors.Is(err,os.ErrClosed){t.Fatalf("closed: %v",err)}
	native=&NativeTun{options:options,rootTetherIndex:42,rootTetherStarted:true}
	fake=&rootTetherFake{state:initial,failAt:2,failAfter:true,foreignAfter:true}
	if err=native.refreshRootTetherWith(req,fake,lookup);!errors.Is(err,errRootTetherUncertain)||!native.rootTetherUncertain{t.Fatalf("uncertain: %v",err)}
	if native.options.IncludeInterface[1]!="ap0"{t.Fatal("published uncertain config")}
	if err=native.UpdateRouteOptions(options);!errors.Is(err,errRootTetherUncertain){t.Fatal("generic update after uncertainty")}
	calls:=fake.calls
	if err=native.refreshRootTetherWith(req,fake,lookup);!errors.Is(err,errRootTetherUncertain)||fake.calls!=calls{t.Fatal("mutation after uncertainty")}
	native.routeUpdate(nil,FlagAndroidVPNUpdate)
	native.rootTetherClosed=true
	native.rootTetherUncertain=false
	native.routeUpdate(nil,FlagAndroidVPNUpdate)
}
