// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin_test

import (
	"strings"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type SystemdUserControlInterfaceSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&SystemdUserControlInterfaceSuite{
	iface: builtin.MustInterface("systemd-user-control"),
})

func (s *SystemdUserControlInterfaceSuite) SetUpTest(c *C) {
	var mockPlugSnapInfoYaml = `name: other
version: 1.0
apps:
 app:
  command: foo
  plugs: [systemd-user-control]
`
	var mockSlotSnapInfoYaml = `name: core
version: 0
type: os
slots:
  systemd-user-control:
`
	s.plug, s.plugInfo = MockConnectedPlug(c, mockPlugSnapInfoYaml, nil, "systemd-user-control")

	s.slot, s.slotInfo = MockConnectedSlot(c, mockSlotSnapInfoYaml, nil, "systemd-user-control")
}

func (s *SystemdUserControlInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "systemd-user-control")
}

func (s *SystemdUserControlInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *SystemdUserControlInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *SystemdUserControlInterfaceSuite) TestUsedSecuritySystems(c *C) {
	// connected plugs have a non-nil security snippet for apparmor
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)
	apparmorSpec := apparmor.NewSpecification(appSet)
	err = apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot)
	c.Assert(err, IsNil)
	aasnippets := apparmorSpec.Snippets()
	c.Assert(aasnippets, HasLen, 1)
	c.Assert(aasnippets["snap.other.app"], HasLen, 1)
	c.Assert(string(aasnippets["snap.other.app"][0]), testutil.Contains, "bus=session")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "bus=system")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "UpdateActivationEnvironment")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "SetEnvironment")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "UnsetEnvironment")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "UnsetAndSetEnvironment")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "member=GetUnit")
	c.Assert(string(aasnippets["snap.other.app"][0]), Not(testutil.Contains), "path=/org/freedesktop/systemd1/unit/**")
}

func (s *SystemdUserControlInterfaceSuite) TestUnitControlIsLimitedToSessionLeaders(c *C) {
	for _, sessionSnap := range []string{"ubuntu-desktop-session", "plasma-desktop-session"} {
		mockPlugSnapInfoYaml := "name: " + sessionSnap + `
version: 1.0
apps:
 ` + sessionSnap + `:
  command: foo
  plugs: [systemd-user-control]
 plasma-kwin-wayland:
  command: kwin
  plugs: [systemd-user-control]
 other:
  command: bar
  plugs: [systemd-user-control]
`
		var mockSlotSnapInfoYaml = `name: core
version: 0
type: os
slots:
  systemd-user-control:
`
		plug, _ := MockConnectedPlug(c, mockPlugSnapInfoYaml, nil, "systemd-user-control")
		slot, _ := MockConnectedSlot(c, mockSlotSnapInfoYaml, nil, "systemd-user-control")

		appSet, err := interfaces.NewSnapAppSet(plug.Snap(), nil)
		c.Assert(err, IsNil)
		spec := apparmor.NewSpecification(appSet)
		c.Assert(spec.AddConnectedPlug(s.iface, plug, slot), IsNil)
		snippets := spec.Snippets()

		leaderTag := "snap." + sessionSnap + "." + sessionSnap
		leaderRules := strings.Join(snippets[leaderTag], "\n")
		c.Assert(leaderRules, testutil.Contains, "member={GetUnit,StartUnit,ResetFailed}")
		c.Assert(leaderRules, testutil.Contains, "member=PropertiesChanged")
		if sessionSnap == "ubuntu-desktop-session" {
			c.Assert(leaderRules, testutil.Contains, "member=UpdateActivationEnvironment")
			c.Assert(leaderRules, testutil.Contains, "member=UnsetAndSetEnvironment")
		} else {
			c.Assert(leaderRules, Not(testutil.Contains), "member=UpdateActivationEnvironment")
			c.Assert(leaderRules, Not(testutil.Contains), "member=UnsetAndSetEnvironment")
		}
		if sessionSnap == "plasma-desktop-session" {
			c.Assert(leaderRules, testutil.Contains, "member={ListUnitFilesByPatterns,Reload,SetEnvironment,UnsetEnvironment}")
			c.Assert(leaderRules, testutil.Contains, "interface=org.freedesktop.DBus.Properties\n        member=Get")
		} else {
			c.Assert(leaderRules, Not(testutil.Contains), "member=SetEnvironment")
		}

		if sessionSnap == "plasma-desktop-session" {
			kwinRules := strings.Join(snippets["snap."+sessionSnap+".plasma-kwin-wayland"], "\n")
			c.Assert(kwinRules, testutil.Contains, "member=UpdateActivationEnvironment")
			c.Assert(kwinRules, testutil.Contains, "interface=org.freedesktop.systemd1.Manager\n        member=SetEnvironment")
			c.Assert(kwinRules, Not(testutil.Contains), "member=StartUnit")
		}

		otherRules := strings.Join(snippets["snap."+sessionSnap+".other"], "\n")
		c.Assert(otherRules, Not(testutil.Contains), "org.freedesktop.systemd1.Manager")
		c.Assert(otherRules, Not(testutil.Contains), "org.freedesktop.systemd1/unit/")
		c.Assert(otherRules, Not(testutil.Contains), "UpdateActivationEnvironment")
	}
}

func (s *SystemdUserControlInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
