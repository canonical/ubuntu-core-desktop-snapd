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
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type DesktopLegacyInterfaceSuite struct {
	iface        interfaces.Interface
	coreSlotInfo *snap.SlotInfo
	coreSlot     *interfaces.ConnectedSlot
	plugInfo     *snap.PlugInfo
	plug         *interfaces.ConnectedPlug
}

var _ = Suite(&DesktopLegacyInterfaceSuite{
	iface: builtin.MustInterface("desktop-legacy"),
})

const desktopLegacyConsumerYaml = `name: consumer
version: 0
apps:
 app:
  plugs: [desktop-legacy]
`

const desktopLegacyCoreYaml = `name: core
version: 0
type: os
slots:
  desktop-legacy:
`

func (s *DesktopLegacyInterfaceSuite) SetUpTest(c *C) {
	s.plug, s.plugInfo = MockConnectedPlug(c, desktopLegacyConsumerYaml, nil, "desktop-legacy")
	s.coreSlot, s.coreSlotInfo = MockConnectedSlot(c, desktopLegacyCoreYaml, nil, "desktop-legacy")
}

func (s *DesktopLegacyInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "desktop-legacy")
}

func (s *DesktopLegacyInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.coreSlotInfo), IsNil)
}

func (s *DesktopLegacyInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *DesktopLegacyInterfaceSuite) TestAppArmorSpec(c *C) {
	// connected plug to core slot
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)
	spec := apparmor.NewSpecification(appSet)
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.coreSlot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "# Description: Can access common desktop legacy methods")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "#include <abstractions/dbus-accessibility-strict>")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(addr="@/tmp/ibus/dbus-*"),`)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `deny /var/lib/snapd/desktop/applications/mimeinfo.cache r,`)

	// a11y provider peers: the org.a11y.Bus owner (session
	// bus) and the registry (private bus) are pinned to the provider's
	// label plus the legacy unconfined provider; name ownership does
	// not enforce the role, so the pin replaces the earlier generic
	// snap.* reach
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "interface=org.a11y.Bus\n    member=GetAddress\n    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	// the session-bus status read surface: reads only, scoped to
	// the served object path - no Set for confined clients
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "path=/org/a11y/bus\n    interface=org.freedesktop.DBus.Properties\n    member={Get,GetAll}\n    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "path=/org/a11y/bus\n    interface=org.freedesktop.DBus.Introspectable\n    member=Introspect\n    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	// ... for the narrowed client receives on the accessibility bus:
	// the unnamed catch-all receive is GONE. What remains,
	// per surface:
	// 1. provider-lifecycle receives pinned to the provider's label
	//    (driver bus-lifecycle signals, the registry's Ping health
	//    check, the Id assignment, listener bookkeeping, delivered key
	//    events)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"interface=org.freedesktop.DBus\n"+
			"    member={NameAcquired,NameLost,NameOwnerChanged}\n"+
			"    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n    path=/\n"+
			"    interface=org.freedesktop.DBus.Peer\n    member=Ping\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"member=EventListener{Registered,Deregistered}\n"+
			"    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"member=NotifyListeners{Sync,Async}\n"+
			"    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	// 2a. reader-ROLE-only interfaces: accepted from any peer - the
	//     kernel checks the sender side too and ONLY reader-granted
	//     profiles carry those sends
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"{org.a11y.atspi.Text,org.a11y.atspi.EditableText,org.a11y.atspi.Action,org.a11y.atspi.Component,org.a11y.atspi.Selection,org.a11y.atspi.Hypertext,org.a11y.atspi.Hyperlink,org.a11y.atspi.Document,org.a11y.atspi.Table,org.a11y.atspi.TableCell}\"\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),")
	// 2b. desktop-legacy-shared read surfaces: PINNED to the provider's
	//     label (the send side cannot discriminate - a desktop-legacy-
	//     only snap holds the same sends, so the receive is the wall)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"{org.a11y.atspi.Accessible,org.a11y.atspi.Application,org.freedesktop.DBus.Properties,org.a11y.atspi.Collection,org.a11y.atspi.Cache}\"\n"+
			"    member=\"Get*\"\n"+
			"    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"path=\"/**/a11y/*\"\n"+
			"    interface=org.freedesktop.DBus.Properties\n"+
			"    member=Set\n"+
			"    peer=(label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	// 3. event/cache broadcasts: the shared trust domain (its
	//    documented accepted risk)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n"+
			"    interface=org.a11y.atspi.Event.Object\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),")
	// and the isolation line: NO unnamed receive on the private bus survives
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains),
		"dbus (receive)\n    bus=accessibility\n    peer=")
	// ... and for the registry sends (the registry lives in the
	// provider's label with a confined provider, unconfined on the fat
	// base)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "member=\"Embed\"\n    peer=(name=org.a11y.atspi.Registry, label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	// the pre-reader-role desktop-legacy READ sends
	// are DROPPED — the reader role (the accessibility-provider
	// connected plug) is the one complete statement of the reader
	// send-set, so desktop-legacy no longer grants the tree reads
	// (Accessible Get*, Properties Get{,All}, Collection GetMatches,
	// Application GetApplicationBusAddress) toward {snap.*,unconfined}
	// at any path shape. Assert their ABSENCE (a desktop-legacy-only
	// consumer profile must carry ZERO read-send rules to non-own
	// peers — the mechanical audit criterion).
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "interface=\"org.a11y.atspi.Accessible\"\n    member=\"Get*\"\n    peer=(label=\"{snap.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "interface=\"org.freedesktop.DBus.Properties\"\n    member=\"Get{,All}\"\n    peer=(label=\"{snap.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "interface=\"org.a11y.atspi.Collection\"\n    member=\"GetMatches\"\n    peer=(label=\"{snap.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "interface=\"org.a11y.atspi.Application\"\n    member=\"GetApplicationBusAddress\"\n    peer=(label=\"{snap.*,unconfined}\"),")
	// the event broadcasts are interface-scoped and STAY (the
	// accepted-risk broadcast class); the cache send is NARROWED to the
	// broadcasts (Add/RemoveAccessible) — the GetItems unicast READ
	// half is dropped (the reader role grants it member-scoped)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "path=\"/org/a11y/atspi/cache\"\n    interface=\"org.a11y.atspi.Cache\"\n    member=\"{AddAccessible,RemoveAccessible}\"\n    peer=(label=\"{snap.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "path=\"/org/a11y/atspi/cache\"\n    interface=\"org.a11y.atspi.Cache\"\n    peer=")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "path=\"/**/a11y/*\"\n    interface=\"org.a11y.atspi.Event.Object\"\n    peer=(name=org.freedesktop.DBus, label=\"{snap.*,unconfined}\"),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "member=\"GetRegisteredEvents\"\n    peer=(name=org.a11y.atspi.Registry, label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),")
	// no snap.* at-spi socket rule - the provider binds the
	// conventional path, and a snap.* wildcard would admit every
	// snap's socket (X11-property redirection)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), `snap.*/at-spi/bus*`)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `owner /{,var/}run/user/[0-9]*/at-spi/bus* rw,`)
	// the peer widening is scoped to the a11y member set: session-bus
	// services (e.g. notifications) keep the plain unconfined peer
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "member=\"{GetCapabilities,GetServerInformation,Notify,CloseNotification}\"\n    peer=(label=unconfined),")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "bus=session\n    peer=(label=\"{snap.*,unconfined}\"),")

	// getDesktopFileRules() rules
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `# This leaks the names of snaps with desktop files`)
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `/var/lib/snapd/desktop/applications/ r,`)

	// connected plug to core slot
	appSet, err = interfaces.NewSnapAppSet(s.coreSlot.Snap(), nil)
	c.Assert(err, IsNil)
	spec = apparmor.NewSpecification(appSet)
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, s.coreSlot), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)
}

func (s *DesktopLegacyInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, true)
	c.Assert(si.ImplicitOnClassic, Equals, true)
	c.Assert(si.Summary, Equals, `allows privileged access to desktop legacy methods`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "desktop-legacy")
}

func (s *DesktopLegacyInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}

// Test how desktop-legacy interface interacts desktop-file-ids attribute in desktop interface.
var _ = Suite(&desktopFileRulesBaseSuite{
	iface:    "desktop-legacy",
	slotYaml: desktopLegacyCoreYaml,
})
