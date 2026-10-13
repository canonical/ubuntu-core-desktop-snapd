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

type kdeKauthSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&kdeKauthSuite{
	iface: builtin.MustInterface("kde-kauth"),
})

func (s *kdeKauthSuite) SetUpTest(c *C) {
	const mockPlugInfoYaml = `
name: other
version: 0
apps:
 app:
  command: foo
  plugs: [kde-kauth]
`
	const mockSlotInfoYaml = `
name: core
version: 1.0
type: os
slots:
 kde-kauth:
  interface: kde-kauth
`

	s.plug, s.plugInfo = MockConnectedPlug(c, mockPlugInfoYaml, nil, "kde-kauth")
	s.slot, s.slotInfo = MockConnectedSlot(c, mockSlotInfoYaml, nil, "kde-kauth")
}

func (s *kdeKauthSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "kde-kauth")
}

func (s *kdeKauthSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *kdeKauthSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *kdeKauthSuite) TestConnectedPlugSnippet(c *C) {
	apparmorSpec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.other.app"})

	snippet := apparmorSpec.SnippetForTag("snap.other.app")
	c.Assert(snippet, testutil.Contains, `dbus (send)
    bus=system
    path=/
    interface=org.kde.kf6auth
    member={performAction,stopAction},`)
	c.Assert(snippet, testutil.Contains, `dbus (receive)
    bus=system
    path=/
    interface=org.kde.kf6auth
    member=remoteSignal
    peer=(label=unconfined),`)
}

func (s *kdeKauthSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
