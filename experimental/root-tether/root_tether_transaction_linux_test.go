//go:build linux

package tun

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type rootTetherFake struct {
	state rootTetherState
	calls int
	failAt int
	failAfter bool
	failRollback bool
	foreignAfter bool
}
func (f *rootTetherFake) rules() ([]netlink.Rule,error) { return append([]netlink.Rule(nil),f.state.rules...),nil }
func (f *rootTetherFake) routes(int) ([]netlink.Route,error) { return append([]netlink.Route(nil),f.state.routes...),nil }
func (f *rootTetherFake) apply(o rootTetherOp) error {
	f.calls++
	if f.calls == f.failAt && !f.failAfter || f.failRollback && f.calls > f.failAt { return errors.New("injected failure") }
	next,err := o.predict(f.state)
	if err != nil { return err }
	f.state = next
	if f.calls == f.failAt {
		if f.foreignAfter {
			r := netlink.NewRule()
			r.Priority,r.Family,r.IifName,r.Goto = 9000,unix.AF_INET,"foreign0",9002
			f.state.rules=append(f.state.rules,*r)
		}
		return errors.New("injected lost ACK")
	}
	return nil
}
func (f *rootTetherFake) addRule(r *netlink.Rule) error { return f.apply(rootTetherOp{add:true,rule:r}) }
func (f *rootTetherFake) delRule(r *netlink.Rule) error { return f.apply(rootTetherOp{rule:r}) }
func (f *rootTetherFake) addRoute(r *netlink.Route) error { return f.apply(rootTetherOp{add:true,route:r}) }
func (f *rootTetherFake) delRoute(r *netlink.Route) error { return f.apply(rootTetherOp{route:r}) }

func rootTetherTestPlan() *rootTetherPlan {
	rule := func(name string)*netlink.Rule {
		r := netlink.NewRule()
		r.Family,r.Priority,r.Goto,r.IifName=unix.AF_INET,9000,9002,name
		return r
	}
	lo,old,newR := rule("lo"),rule("ap0"),rule("rndis0")
	r1 := netlink.Route{Table:2022,LinkIndex:42,Dst:prefixToIPNet(nfP("0.0.0.0/1"))}
	r2 := netlink.Route{Table:2022,LinkIndex:42,Dst:prefixToIPNet(nfP("128.0.0.0/1"))}
	return &rootTetherPlan{next:Options{IPRoute2TableIndex:2022,IPRoute2RuleIndex:9000},
		oldRules:[]*netlink.Rule{lo,old},newRules:[]*netlink.Rule{lo,newR},
		addRules:[]*netlink.Rule{newR},removeRules:[]*netlink.Rule{old},
		oldRoutes:[]netlink.Route{r1},newRoutes:[]netlink.Route{r2},
		addRoutes:[]netlink.Route{r2},removeRoutes:[]netlink.Route{r1}}
}

func TestNieFiggerRootTetherTransaction(t *testing.T) {
	p:=rootTetherTestPlan()
	old,want:=rootTetherStateOf(p.oldRules,p.oldRoutes),rootTetherStateOf(p.newRules,p.newRoutes)
	f:= &rootTetherFake{state:old}
	if err:=runRootTetherTransaction(f,p);err!=nil || !f.state.equal(want) || f.calls!=4 {
		t.Fatalf("success: %v calls=%d",err,f.calls)
	}
	for at:=1;at<=4;at++ {
		for _,after:=range []bool{false,true} {
			f=&rootTetherFake{state:old,failAt:at,failAfter:after}
			err:=runRootTetherTransaction(f,p)
			if err==nil || errors.Is(err,errRootTetherUncertain) || !f.state.equal(old) {
				t.Fatalf("rollback at %d after=%v: %v",at,after,err)
			}
		}
	}
	f=&rootTetherFake{state:old,failAt:2,failRollback:true}
	if err:=runRootTetherTransaction(f,p);!errors.Is(err,errRootTetherUncertain) { t.Fatalf("unconfirmed rollback: %v",err) }
	f=&rootTetherFake{state:old,failAt:2,failAfter:true,foreignAfter:true}
	if err:=runRootTetherTransaction(f,p);!errors.Is(err,errRootTetherUncertain) || f.calls!=2 { t.Fatalf("foreign race: %v",err) }
	f=&rootTetherFake{state:rootTetherState{rules:append(append([]netlink.Rule(nil),old.rules...),old.rules[0]),routes:old.routes}}
	if err:=runRootTetherTransaction(f,p);err==nil || f.calls!=0 { t.Fatalf("duplicate preflight: %v",err) }
	f=&rootTetherFake{state:old}
	p.addRules=nil
	if err:=runRootTetherTransaction(f,p);err==nil || f.calls!=0 { t.Fatalf("invalid delta: %v",err) }
}
