// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type AccountDaemonSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&AccountDaemonSuite{
	iface: builtin.MustInterface("account-daemon"),
})

const accountDaemonMockPlugSnapInfo = `name: other
version: 1.0
apps:
 app2:
  command: foo
  plugs: [account-daemon]
`

const accountDaemonMockSlotSnapInfo = `name: core
version: 1.0
type: os
slots:
 account-daemon:
  interface: account-daemon
apps:
 app1:
`

func (s *AccountDaemonSuite) SetUpTest(c *C) {
	s.slot, s.slotInfo = MockConnectedSlot(c, accountDaemonMockSlotSnapInfo, nil, "account-daemon")
	s.plug, s.plugInfo = MockConnectedPlug(c, accountDaemonMockPlugSnapInfo, nil, "account-daemon")
}

func (s *AccountDaemonSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "account-daemon")
}

func (s *AccountDaemonSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *AccountDaemonSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *AccountDaemonSuite) TestUsedSecuritySystems(c *C) {
	// connected plugs have a non-nil security snippet for apparmor
	apparmorSpec := apparmor.NewSpecification(s.plug.AppSet())
	err := apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot)
	fmt.Println(apparmorSpec.Snippets())
	fmt.Println(apparmorSpec.SecurityTags())
	fmt.Println(apparmorSpec.SnapAppSet())
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.other.app2"})
	c.Assert(apparmorSpec.SnippetForTag("snap.other.app2"), testutil.Contains, "/usr/sbin/usermod")
	c.Assert(apparmorSpec.SnippetForTag("snap.other.app2"), testutil.Contains, "/etc/login.defs")

	apparmorSpecSlot := apparmor.NewSpecification(s.slot.AppSet())
	err = apparmorSpecSlot.AddConnectedSlot(s.iface, s.plug, s.slot)
	c.Assert(err, IsNil)
	apparmorSpecSlot.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpecSlot.SecurityTags(), DeepEquals, []string{"snap.core.app1"})
	c.Assert(apparmorSpecSlot.SnippetForTag("snap.core.app1"), testutil.Contains, "/{,usr/}sbin/chpasswd")
	c.Assert(apparmorSpecSlot.SnippetForTag("snap.core.app1"), testutil.Contains, "/{,usr/}bin/passwd")
	c.Assert(apparmorSpecSlot.SnippetForTag("snap.core.app1"), testutil.Contains, "/{,usr/}bin/chage")
	c.Assert(apparmorSpecSlot.SnippetForTag("snap.core.app1"), testutil.Contains, "/{,usr/}sbin/user{add,del,mod}")
	c.Assert(apparmorSpecSlot.SnippetForTag("snap.core.app1"), testutil.Contains, "/usr/bin/lsattr")

	seccompSpec := seccomp.NewSpecification(s.slot.AppSet())
	err = seccompSpec.AddConnectedSlot(s.iface, s.plug, s.slot)
	c.Assert(err, IsNil)
	err = seccompSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.core.app1"})
	c.Assert(err, IsNil)
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "chown")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "chown32")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "chownat")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "fchown")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "fchown32")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "fchownat")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "bind")
	c.Check(seccompSpec.SnippetForTag("snap.core.app1"), testutil.Contains, "socket AF_NETLINK")
}

func (s *AccountDaemonSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
