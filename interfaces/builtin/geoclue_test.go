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
	"github.com/snapcore/snapd/interfaces/dbus"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type GeoclueInterfaceSuite struct {
	testutil.BaseTest

	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&GeoclueInterfaceSuite{
	iface: builtin.MustInterface("geoclue"),
})

const geoclueConsumerYaml = `name: consumer
version: 0
apps:
 app:
  plugs: [geoclue]
`

const geoclueConsumerTwoAppsYaml = `name: consumer
version: 0
apps:
 app1:
  plugs: [geoclue]
 app2:
  plugs: [geoclue]
 app3:
`

const geoclueProducerYaml = `name: producer
version: 0
apps:
 app:
  slots: [geoclue]
`

const geoclueProducerTwoAppsYaml = `name: producer
version: 0
apps:
 app1:
  slots: [geoclue]
 app2:
  slots: [geoclue]
`

func (s *GeoclueInterfaceSuite) SetUpTest(c *C) {
	s.plug, s.plugInfo = MockConnectedPlug(c, geoclueConsumerYaml, nil, "geoclue")
	s.slot, s.slotInfo = MockConnectedSlot(c, geoclueProducerYaml, nil, "geoclue")
}

func (s *GeoclueInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "geoclue")
}

func (s *GeoclueInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *GeoclueInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *GeoclueInterfaceSuite) TestUsedSecuritySystems(c *C) {
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
	c.Assert(apparmorSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "/etc/geoclue/** r")
	c.Assert(apparmorSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "network inet dgram")

	// permanent slots have a non-nil security snippet for seccomp
	seccompSpec := seccomp.NewSpecification(s.slot.AppSet())
	err = seccompSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(seccompSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "bind")

	// no dbus permanent-slot snippet comes from this interface (name
	// ownership is provided by the plain dbus interface slot the provider
	// snap declares alongside it)
	dbusSpec := dbus.NewSpecification(s.slot.AppSet())
	err = dbusSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), HasLen, 0)
}

func (s *GeoclueInterfaceSuite) TestAppArmorSpec(c *C) {
	// The label uses short form when exactly one app is bound to the slot
	spec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.app"),`)

	// The label glob when all apps are bound to the slot
	slot, _ := MockConnectedSlot(c, geoclueProducerTwoAppsYaml, nil, "geoclue")
	spec = apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.*"),`)

	// The label uses alternation when some, but not all, apps are bound
	// to the plug (app3 declares no plugs)
	plug, _ := MockConnectedPlug(c, geoclueConsumerTwoAppsYaml, nil, "geoclue")
	spec = apparmor.NewSpecification(s.slot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `peer=(label="snap.consumer{.app1,.app2}"),`)

	// permanent slot snippet carries the peer-less receive rules
	spec = apparmor.NewSpecification(s.slot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.slotInfo), IsNil)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, "dbus (receive)\n    bus=system\n    path=/org/freedesktop/GeoClue2{,/**}\n    interface=org.freedesktop.GeoClue2.{Manager,Client,Location},")
	// the data-source sends and the agent calls
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/fi/w1/wpa_supplicant1{,/**}`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/org/freedesktop/ModemManager1{,/**}`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `path=/org/freedesktop/GeoClue2/Agent`)
	// the config
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/etc/geoclue/** r,`)
}

func (s *GeoclueInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, false)
	c.Assert(si.ImplicitOnClassic, Equals, false)
	c.Assert(si.Summary, Equals, `allows operating as or interacting with the geoclue location service`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "geoclue")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "deny-auto-connection: true")
}

func (s *GeoclueInterfaceSuite) TestAutoConnect(c *C) {
	c.Assert(s.iface.AutoConnect(s.plugInfo, s.slotInfo), Equals, true)
}

func (s *GeoclueInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
