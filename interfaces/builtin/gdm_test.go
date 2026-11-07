// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type gdmSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&gdmSuite{
	iface: builtin.MustInterface("gdm"),
})

func (s *gdmSuite) SetUpTest(c *C) {
	const mockPlugInfoYaml = `
name: other
version: 0
apps:
 app:
  command: foo
  plugs: [gdm]
`
	const mockSlotInfoYaml = `
name: core
version: 1.0
type: os
slots:
 gdm:
  interface: gdm
`

	s.plug, s.plugInfo = MockConnectedPlug(c, mockPlugInfoYaml, nil, "gdm")
	s.slot, s.slotInfo = MockConnectedSlot(c, mockSlotInfoYaml, nil, "gdm")
}

func (s *gdmSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "gdm")
}

func (s *gdmSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *gdmSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *gdmSuite) TestConnectedPlugSnippet(c *C) {
	apparmorSpec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.other.app"})

	snippet := apparmorSpec.SnippetForTag("snap.other.app")
	c.Assert(snippet, testutil.Contains, `dbus (send)
    bus=system
    path=/org/gnome/DisplayManager/Manager
    interface=org.gnome.DisplayManager.Manager
    member=OpenSession
    peer=(label=gdm),`)
	c.Assert(snippet, testutil.Contains, `/run/gdm3/dbus/dbus-* rw,`)
	c.Assert(snippet, Not(testutil.Contains), "member=RegisterSession")
	c.Assert(snippet, Not(testutil.Contains), "member=OpenReauthenticationChannel")
}

func (s *gdmSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
