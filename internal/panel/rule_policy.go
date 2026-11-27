package panel

import (
	"errors"
	"fmt"

	"kaze/internal/proto"
)

// The same owner policy is applied to proposed rules and to copies of stored
// rules. Never persist a runtime rejection as a manual pause.
type rulePolicy struct {
	all    []*Group
	groups groupSet
	plans  map[int64][]int64
}

func loadRulePolicy(q dbq) (*rulePolicy, error) {
	groups, err := listGroups(q)
	if err != nil {
		return nil, err
	}
	plans, err := listPlans(q, true)
	if err != nil {
		return nil, err
	}
	p := &rulePolicy{all: groups, groups: toGroupSet(groups), plans: make(map[int64][]int64, len(plans))}
	for _, plan := range plans {
		p.plans[plan.ID] = plan.Groups
	}
	return p, nil
}
func rulePortRanges(g *Group) [][2]int {
	ranges, _ := parsePortRange(g.Config.PortRange)
	if len(ranges) == 0 {
		return [][2]int{{10000, 60000}}
	}
	return ranges
}
func (p *rulePolicy) authorize(owner *User, r *Rule) error {
	allowed := func(g *Group, role string) bool {
		return g != nil && g.Type == role && (owner.IsAdmin() || g.Public || containsID(p.plans[owner.PlanID], g.ID))
	}
	ig := p.groups[r.InGroup]
	if !allowed(ig, proto.RoleIn) {
		return errors.New("入口组不存在或无权使用")
	}
	if !owner.IsAdmin() && r.TLSMode != proto.TLSModeChild && r.ListenPort != 0 && !portInRange(rulePortRanges(ig), r.ListenPort) {
		return fmt.Errorf("监听端口需在 %s 范围内", ig.Config.PortRange)
	}
	if !owner.IsAdmin() && r.TLSMode != proto.TLSModeParent {
		if ig.Config.TLSInboundPolicy == 1 && r.TLSMode == "" {
			return errors.New("该入口组只允许 TLS 入站规则")
		}
		if ig.Config.TLSInboundPolicy == 2 && r.TLSMode != proto.TLSModeChild {
			return errors.New("该入口组只允许 TLS 子规则")
		}
	}
	if r.TLSMode != "" {
		if containsStr(ig.Config.BlockedProtocols, "tls") {
			return errors.New("入口组屏蔽了 TLS")
		}
		for _, name := range r.TLS.SNI {
			if (len(ig.Config.AllowedHosts) > 0 && !suffixMatch(name, ig.Config.AllowedHosts)) || suffixMatch(name, ig.Config.BlockedHosts) {
				return fmt.Errorf("入口组不允许 SNI %s", name)
			}
		}
	}
	if r.TLSMode == proto.TLSModeParent {
		return nil
	}
	if ig.Config.DisableUDP {
		if r.Proto == "udp" {
			return errors.New("该入口组已禁用 UDP")
		}
		r.Proto = "tcp"
	}
	if r.OutGroup == 0 {
		if ig.Config.DirectMode == 1 && !owner.IsAdmin() {
			return errors.New("该入口组不允许直接转发,请选择出口组")
		}
		return nil
	}
	if ig.Config.DirectMode == 2 {
		return errors.New("该入口组只允许直接转发")
	}
	og := p.groups[r.OutGroup]
	if !allowed(og, proto.RoleOut) && !allowed(og, proto.RoleChain) {
		return errors.New("出口组不存在或无权使用")
	}
	if _, _, ok := p.groups.hops(r.OutGroup); !ok {
		return errors.New("出口组配置不完整")
	}
	if len(ig.Config.AllowedOut) > 0 && !containsID(ig.Config.AllowedOut, r.OutGroup) {
		return errors.New("该入口组不允许使用所选出口组")
	}
	return nil
}
