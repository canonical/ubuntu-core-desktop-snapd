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

type gdmSessionControlSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&gdmSessionControlSuite{
	iface: builtin.MustInterface("gdm-session-control"),
})

func (s *gdmSessionControlSuite) SetUpTest(c *C) {
	const mockPlugInfoYaml = `
name: other
version: 0
apps:
 app:
  command: foo
  plugs: [gdm-session-control]
`
	const mockSlotInfoYaml = `
name: core
version: 1.0
type: os
slots:
 gdm-session-control:
  interface: gdm-session-control
`

	s.plug, s.plugInfo = MockConnectedPlug(c, mockPlugInfoYaml, nil, "gdm-session-control")
	s.slot, s.slotInfo = MockConnectedSlot(c, mockSlotInfoYaml, nil, "gdm-session-control")
}

func (s *gdmSessionControlSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "gdm-session-control")
}

func (s *gdmSessionControlSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *gdmSessionControlSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *gdmSessionControlSuite) TestConnectedPlugSnippet(c *C) {
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
	c.Assert(snippet, Not(testutil.Contains), "member=RegisterSession")
}

func (s *gdmSessionControlSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
