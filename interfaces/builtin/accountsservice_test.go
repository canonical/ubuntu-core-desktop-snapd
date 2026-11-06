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
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/dbus"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type AccountsserviceInterfaceSuite struct {
	testutil.BaseTest

	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&AccountsserviceInterfaceSuite{
	iface: builtin.MustInterface("accountsservice"),
})

const accountsserviceConsumerYaml = `name: consumer
version: 0
apps:
 app:
  plugs: [accountsservice]
`

const accountsserviceConsumerTwoAppsYaml = `name: consumer
version: 0
apps:
 app1:
  plugs: [accountsservice]
 app2:
  plugs: [accountsservice]
 app3:
`

const accountsserviceProducerYaml = `name: producer
version: 0
apps:
 app:
  slots: [accountsservice]
`

const accountsserviceProducerTwoAppsYaml = `name: producer
version: 0
apps:
 app1:
  slots: [accountsservice]
 app2:
  slots: [accountsservice]
`

func (s *AccountsserviceInterfaceSuite) SetUpTest(c *C) {
	s.plug, s.plugInfo = MockConnectedPlug(c, accountsserviceConsumerYaml, nil, "accountsservice")
	s.slot, s.slotInfo = MockConnectedSlot(c, accountsserviceProducerYaml, nil, "accountsservice")
}

func (s *AccountsserviceInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "accountsservice")
}

func (s *AccountsserviceInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *AccountsserviceInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *AccountsserviceInterfaceSuite) TestUsedSecuritySystems(c *C) {
	// connected plugs have a non-nil security snippet for apparmor
	apparmorSpec := apparmor.NewSpecification(s.plug.AppSet())
	err := apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(apparmorSpec.SnippetForTag("snap.consumer.app"), testutil.Contains, "dbus (send)")

	// permanent slots have a non-nil security snippet for apparmor
	apparmorSpec = apparmor.NewSpecification(s.slot.AppSet())
	err = apparmorSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(apparmorSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "/var/lib/extrausers/** rwkl")

	// permanent slots have a non-nil security snippet for seccomp
	seccompSpec := seccomp.NewSpecification(s.slot.AppSet())
	err = seccompSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	group, err := osutil.FindGidOwning("/etc/shadow")
	c.Assert(err, IsNil)
	c.Check(seccompSpec.SnippetForTag("snap.producer.app"), testutil.Contains,
		fmt.Sprintf("\nfchown - u:root %v\n", group))

	// no dbus permanent-slot snippet comes from this interface (name
	// ownership is provided by the plain dbus interface slot the provider
	// snap declares alongside it)
	dbusSpec := dbus.NewSpecification(s.slot.AppSet())
	err = dbusSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), HasLen, 0)
}

func (s *AccountsserviceInterfaceSuite) TestAppArmorSpec(c *C) {
	// The label uses short form when exactly one app is bound to the slot
	spec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.app"),`)

	// The label glob when all apps are bound to the slot
	slot, _ := MockConnectedSlot(c, accountsserviceProducerTwoAppsYaml, nil, "accountsservice")
	spec = apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.*"),`)

	// The label uses alternation when some, but not all, apps are bound
	// to the plug (app3 declares no plugs)
	plug, _ := MockConnectedPlug(c, accountsserviceConsumerTwoAppsYaml, nil, "accountsservice")
	spec = apparmor.NewSpecification(s.slot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `peer=(label="snap.consumer{.app1,.app2}"),`)

	// permanent slot snippet carries the peer-less receive rules
	spec = apparmor.NewSpecification(s.slot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.slotInfo), IsNil)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, "dbus (receive)\n    bus=system\n    path=/org/freedesktop/Accounts{,/User[0-9]*}\n    interface=org.freedesktop.Accounts{,.User},")
	// the helpers and databases
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/{,usr/}sbin/adduser ixr,`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/{,usr/}bin/perl ixr,`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/var/lib/AccountsService/** rwkl,`)
}

func (s *AccountsserviceInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, false)
	c.Assert(si.ImplicitOnClassic, Equals, false)
	c.Assert(si.Summary, Equals, `allows operating as or interacting with the AccountsService user-account service`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "accountsservice")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "deny-auto-connection: true")
}

func (s *AccountsserviceInterfaceSuite) TestAutoConnect(c *C) {
	c.Assert(s.iface.AutoConnect(s.plugInfo, s.slotInfo), Equals, true)
}

func (s *AccountsserviceInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
