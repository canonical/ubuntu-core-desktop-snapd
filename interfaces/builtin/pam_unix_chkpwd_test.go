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
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type pamUnixChkpwdSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&pamUnixChkpwdSuite{
	iface: builtin.MustInterface("pam-unix-chkpwd"),
})

func (s *pamUnixChkpwdSuite) SetUpTest(c *C) {
	const mockPlugInfoYaml = `
name: other
version: 0
apps:
 app:
  command: foo
  plugs: [pam-unix-chkpwd]
`
	const mockSlotInfoYaml = `
name: core
version: 1.0
type: os
slots:
 pam-unix-chkpwd:
  interface: pam-unix-chkpwd
`

	s.plug, s.plugInfo = MockConnectedPlug(c, mockPlugInfoYaml, nil, "pam-unix-chkpwd")
	s.slot, s.slotInfo = MockConnectedSlot(c, mockSlotInfoYaml, nil, "pam-unix-chkpwd")
}

func (s *pamUnixChkpwdSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "pam-unix-chkpwd")
}

func (s *pamUnixChkpwdSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *pamUnixChkpwdSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *pamUnixChkpwdSuite) TestConnectedPlugSnippet(c *C) {
	apparmorSpec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.other.app"})

	snippet := apparmorSpec.SnippetForTag("snap.other.app")
	c.Assert(snippet, testutil.Contains, `/usr/sbin/unix_chkpwd Px,`)
	c.Assert(snippet, testutil.Contains, `/usr/sbin/pam_extrausers_chkpwd Ux,`)
	c.Assert(snippet, testutil.Contains, `/run/faillock/ rw,`)
	c.Assert(snippet, testutil.Contains, `/run/faillock/** rwk,`)
	c.Assert(snippet, testutil.Contains, `/usr/lib/core/lockout-not-enabled.sh ix,`)
	c.Assert(snippet, testutil.Contains, `/etc/writable/account-locked.enable r,`)
}

func (s *pamUnixChkpwdSuite) TestSecCompSpec(c *C) {
	seccompSpec := seccomp.NewSpecification(s.plug.AppSet())
	c.Assert(seccompSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(seccompSpec.Snippets(), HasLen, 1)
	c.Check(seccompSpec.SnippetForTag("snap.other.app"), testutil.Contains, "socket AF_NETLINK - NETLINK_AUDIT")
}

func (s *pamUnixChkpwdSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
