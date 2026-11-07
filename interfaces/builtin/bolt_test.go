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

type BoltInterfaceSuite struct {
	testutil.BaseTest

	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&BoltInterfaceSuite{
	iface: builtin.MustInterface("bolt"),
})

const boltConsumerYaml = `name: consumer
version: 0
apps:
 app:
  plugs: [bolt]
`

const boltConsumerTwoAppsYaml = `name: consumer
version: 0
apps:
 app1:
  plugs: [bolt]
 app2:
  plugs: [bolt]
 app3:
`

const boltProducerYaml = `name: producer
version: 0
apps:
 app:
  slots: [bolt]
`

const boltProducerTwoAppsYaml = `name: producer
version: 0
apps:
 app1:
  slots: [bolt]
 app2:
  slots: [bolt]
`

func (s *BoltInterfaceSuite) SetUpTest(c *C) {
	s.plug, s.plugInfo = MockConnectedPlug(c, boltConsumerYaml, nil, "bolt")
	s.slot, s.slotInfo = MockConnectedSlot(c, boltProducerYaml, nil, "bolt")
}

func (s *BoltInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "bolt")
}

func (s *BoltInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *BoltInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *BoltInterfaceSuite) TestUsedSecuritySystems(c *C) {
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
	c.Assert(apparmorSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "/var/lib/boltd/** rwkl")
	// the bus entries under /sys/bus/thunderbolt/devices are symlinks
	// into /sys/devices and apparmor mediates on the resolved path, so
	// the write access must be granted on the resolved domain paths
	c.Assert(apparmorSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "/sys/bus/thunderbolt/** rwkl")
	c.Assert(apparmorSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "/sys/devices/**/domain[0-9]*/** rw")

	// permanent slots have a non-nil security snippet for seccomp
	seccompSpec := seccomp.NewSpecification(s.slot.AppSet())
	err = seccompSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(seccompSpec.SnippetForTag("snap.producer.app"), testutil.Contains, "socket AF_NETLINK - NETLINK_KOBJECT_UEVENT")

	// no dbus permanent-slot snippet comes from this interface (name
	// ownership is provided by the plain dbus interface slot the provider
	// snap declares alongside it)
	dbusSpec := dbus.NewSpecification(s.slot.AppSet())
	err = dbusSpec.AddPermanentSlot(s.iface, s.slotInfo)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), HasLen, 0)
}

func (s *BoltInterfaceSuite) TestAppArmorSpec(c *C) {
	// The label uses short form when exactly one app is bound to the slot
	spec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.app"),`)

	// The label glob when all apps are bound to the slot
	slot, _ := MockConnectedSlot(c, boltProducerTwoAppsYaml, nil, "bolt")
	spec = apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.*"),`)

	// The label uses alternation when some, but not all, apps are bound
	// to the plug (app3 declares no plugs)
	plug, _ := MockConnectedPlug(c, boltConsumerTwoAppsYaml, nil, "bolt")
	spec = apparmor.NewSpecification(s.slot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `peer=(label="snap.consumer{.app1,.app2}"),`)

	// permanent slot snippet carries the peer-less receive rules
	spec = apparmor.NewSpecification(s.slot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.slotInfo), IsNil)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, "dbus (receive)\n    bus=system\n    path=/org/freedesktop/bolt{,/**}\n    interface=org.freedesktop.bolt1.{Manager,Domain,Device,Power},")
	// the thunderbolt sysfs access and the state directory: writes go
	// through the resolved /sys/devices paths (the bus entries are
	// symlinks, e.g. /sys/bus/thunderbolt/devices/0-1/authorized is
	// /sys/devices/pci…/…/domain0/0-1/authorized once resolved)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/sys/bus/thunderbolt/** rwkl,`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/sys/devices/**/domain[0-9]*/** rw,`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/sys/devices/**/wmi_bus/**/force_power rw,`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `/var/lib/boltd/** rwkl,`)
}

func (s *BoltInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, false)
	c.Assert(si.ImplicitOnClassic, Equals, false)
	c.Assert(si.Summary, Equals, `allows operating as or interacting with the bolt thunderbolt service`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "bolt")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "deny-auto-connection: true")
}

func (s *BoltInterfaceSuite) TestAutoConnect(c *C) {
	c.Assert(s.iface.AutoConnect(s.plugInfo, s.slotInfo), Equals, true)
}

func (s *BoltInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
