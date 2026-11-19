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

type AccessibilityProviderInterfaceSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
}

var _ = Suite(&AccessibilityProviderInterfaceSuite{
	iface: builtin.MustInterface("accessibility-provider"),
})

const accessibilityProviderSlotYaml = `name: provider
version: 0
apps:
 bus:
  command: bin/bus
  slots: [accessibility-provider]
slots:
  accessibility-provider:
`

const accessibilityProviderPlugYaml = `name: reader
version: 0
apps:
 orca:
  command: bin/orca
  plugs: [accessibility-provider]
plugs:
  accessibility-provider:
`

func (s *AccessibilityProviderInterfaceSuite) SetUpTest(c *C) {
	s.slotInfo = MockSlot(c, accessibilityProviderSlotYaml, nil, "accessibility-provider")
}

func (s *AccessibilityProviderInterfaceSuite) TestSanitizePlug(c *C) {
	plugInfo := MockPlug(c, accessibilityProviderPlugYaml, nil, "accessibility-provider")
	c.Assert(interfaces.BeforePreparePlug(s.iface, plugInfo), IsNil)
}

func (s *AccessibilityProviderInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "accessibility-provider")
}

func (s *AccessibilityProviderInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *AccessibilityProviderInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}

func (s *AccessibilityProviderInterfaceSuite) TestPermanentSlotAppArmorEmpty(c *C) {
	// T29 C1: the slot must grant NOTHING on installation - every
	// provider privilege rides the connection
	appSet, err := interfaces.NewSnapAppSet(s.slotInfo.Snap, nil)
	c.Assert(err, IsNil)
	spec := apparmor.NewSpecification(appSet)
	c.Assert(spec.AddPermanentSlot(s.iface, s.slotInfo), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)
	c.Assert(spec.SnippetForTag("snap.provider.bus"), Equals, "")
}

func (s *AccessibilityProviderInterfaceSuite) TestConnectedSlotAppArmor(c *C) {
	plug, _ := MockConnectedPlug(c, accessibilityProviderPlugYaml, nil, "accessibility-provider")
	slot, _ := MockConnectedSlot(c, accessibilityProviderSlotYaml, nil, "accessibility-provider")
	appSet, err := interfaces.NewSnapAppSet(slot.Snap(), nil)
	c.Assert(err, IsNil)
	spec := apparmor.NewSpecification(appSet)
	c.Assert(spec.AddConnectedSlot(s.iface, plug, slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.provider.bus"})
	snippet := spec.SnippetForTag("snap.provider.bus")
	// the libapparmor kernel-query capability: aa_find_mountpoint reads
	// /proc/<pid>/mounts (setmntent) to locate securityfs and
	// aa_query_label opens /sys/kernel/security/apparmor/.access O_RDWR
	// (write the query, read the answer); without these the confined
	// dbus-daemon fail-opens at bus_apparmor_pre_init (T18 E2) - and
	// with T29 C1 the grants ride the CONNECTION, not the installation
	c.Assert(snippet, testutil.Contains, "@{PROC}/@{pid}/mounts                   r,\n")
	c.Assert(snippet, testutil.Contains, "/sys/kernel/security/apparmor/.access   rw,\n")
	// the conventional socket path (the launcher overrides XDG_RUNTIME_DIR)
	c.Assert(snippet, testutil.Contains, "owner /run/user/[0-9]*/at-spi/   rw,\n")
	c.Assert(snippet, testutil.Contains, "owner /run/user/[0-9]*/at-spi/** rw,\n")
	// the provider-side accessibility-bus contract, peers pinned to the
	// provider's own label plus unconfined
	c.Assert(snippet, testutil.Contains,
		"dbus (bind)\n    bus=accessibility\n    name=org.a11y.atspi.Registry,\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n    peer=(label=\"{snap.@{SNAP_INSTANCE_NAME}.*,unconfined}\"),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n    peer=(label=\"{snap.@{SNAP_INSTANCE_NAME}.*,unconfined}\"),\n")
	// the app-facing join surface for desktop-legacy clients (gate 2):
	// the driver handshake mirrored from
	// abstractions/dbus-accessibility-strict and the registration /
	// reader calls mirrored from desktop-legacy's pinned registry
	// sends - every rule scoped by path/interface/member, receive-only,
	// never the unnamed tree-walking surface (T17 D3)
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n    path=/org/freedesktop/DBus\n"+
			"    interface=org.freedesktop.DBus\n"+
			"    member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName}\n"+
			"    peer=(label=snap.*),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n    path=/org/a11y/atspi/accessible/root\n"+
			"    interface=org.a11y.atspi.Socket\n    member=Embed\n"+
			"    peer=(label=snap.*),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n    path=/org/a11y/atspi/registry\n"+
			"    interface=org.a11y.atspi.Registry\n    member=GetRegisteredEvents\n"+
			"    peer=(label=snap.*),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=accessibility\n    path=/org/a11y/atspi/registry/deviceeventcontroller\n"+
			"    interface=org.a11y.atspi.DeviceEventController\n"+
			"    member={GetDeviceEventListeners,GetKeystrokeListeners,NotifyListenersSync}\n"+
			"    peer=(label=snap.*),\n")
	// the session-bus status object surface (reads only, scoped to the
	// served object path; Set is deliberately not granted to confined
	// peers)
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=session\n    path=/org/a11y/bus\n"+
			"    interface=org.freedesktop.DBus.Properties\n    member={Get,GetAll}\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (receive)\n    bus=session\n    path=/org/a11y/bus\n"+
			"    interface=org.freedesktop.DBus.Introspectable\n    member=Introspect\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),\n")
	// the provider-to-app sends the registration contract needs (T24):
	// the registry's 30s Peer.Ping health check (an app whose ping
	// errors is DISABLED and removed from the desktop tree), the
	// Application.Id assignment after Embed, and the listener
	// bookkeeping broadcasts
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n    path=/\n"+
			"    interface=org.freedesktop.DBus.Peer\n    member=Ping\n"+
			"    peer=(label=snap.*),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n    path=/org/a11y/atspi/accessible/root\n"+
			"    interface=org.freedesktop.DBus.Properties\n    member=Set\n"+
			"    peer=(label=snap.*),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n    path=/org/a11y/atspi/registry\n"+
			"    interface=org.a11y.atspi.Registry\n"+
			"    member=EventListener{Registered,Deregistered}\n"+
			"    peer=(name=org.freedesktop.DBus, label=snap.*),\n")
	// the device event controller's keystroke-listener bookkeeping
	// broadcast (T30: 433 denials registryd->gnome-shell on the T28
	// final bake with the rule absent)
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n"+
			"    path=/org/a11y/atspi/registry/deviceeventcontroller\n"+
			"    interface=org.a11y.atspi.DeviceEventListener\n"+
			"    member=KeystrokeListener{Registered,Deregistered}\n"+
			"    peer=(name=org.freedesktop.DBus, label=snap.*),\n")
	// no unnamed snap.* receive on the private bus (T17 D3 isolation
	// line) and no system-bus rules here
	c.Assert(snippet, Not(testutil.Contains), "bus=system")
	c.Assert(snippet, Not(testutil.Contains),
		"dbus (receive)\n    bus=accessibility\n    peer=(label=\"{snap.*,")
}

func (s *AccessibilityProviderInterfaceSuite) TestConnectedPlugAppArmor(c *C) {
	// connected accessibility-provider plug on a reader snap, against
	// the provider slot (the a11y snap's own bus app in production;
	// same-snap implicit connection)
	plug, _ := MockConnectedPlug(c, accessibilityProviderPlugYaml, nil, "accessibility-provider")
	slot, _ := MockConnectedSlot(c, accessibilityProviderSlotYaml, nil, "accessibility-provider")
	appSet, err := interfaces.NewSnapAppSet(plug.Snap(), nil)
	c.Assert(err, IsNil)
	spec := apparmor.NewSpecification(appSet)
	c.Assert(spec.AddConnectedPlug(s.iface, plug, slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.reader.orca"})
	snippet := spec.SnippetForTag("snap.reader.orca")

	// the reader send-set is derived from at-spi2-core's interface XML
	// (T29 C4), not chased denial-by-denial. Text reads + caret control:
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n"+
			"    path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"org.a11y.atspi.Text\"\n    member=\"Get*\"\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),\n")
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n"+
			"    path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"org.a11y.atspi.Text\"\n"+
			"    member=\"{SetCaretOffset,AddSelection,RemoveSelection,SetSelection,ScrollSubstringTo,ScrollSubstringToPoint}\"\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),\n")
	// EditableText, Action (incl. DoAction), Component (incl.
	// GrabFocus), Selection, Document, Table:
	c.Assert(snippet, testutil.Contains,
		"member=\"{SetTextContents,InsertText,CopyText,CutText,DeleteText,PasteText}\"")
	c.Assert(snippet, testutil.Contains,
		"member=\"DoAction\"")
	c.Assert(snippet, testutil.Contains,
		"member=\"{Contains,GrabFocus,SetExtents,SetPosition,SetSize,ScrollTo,ScrollToPoint}\"")
	c.Assert(snippet, testutil.Contains,
		"member=\"{GetSelectedChild,SelectChild,DeselectSelectedChild,IsChildSelected,SelectAll,ClearSelection,DeselectChild}\"")
	c.Assert(snippet, testutil.Contains,
		"interface=\"org.a11y.atspi.Document\"")
	c.Assert(snippet, testutil.Contains,
		"interface=\"org.a11y.atspi.Table\"")
	c.Assert(snippet, testutil.Contains,
		"interface=\"org.a11y.atspi.TableCell\"")
	// Value.SetCurrentValue is the Properties.Set rule:
	c.Assert(snippet, testutil.Contains,
		"interface=\"org.freedesktop.DBus.Properties\"\n    member=\"Set\"")
	// the GTK4 cache read:
	c.Assert(snippet, testutil.Contains,
		"path=\"/org/a11y/atspi/cache\"\n    interface=\"org.a11y.atspi.Cache\"\n"+
			"    member=\"GetItems\"")
	// the handshake liveness probe (T32/T33: 3x Peer.Ping orca ->
	// gnome-shell DENIED at path=/ on the private bus during the
	// post-login handshake - the reader role's app-peer Ping send):
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n    path=/\n"+
			"    interface=org.freedesktop.DBus.Peer\n    member=Ping\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),\n")
	// the tree-read sends completed by T29 C2 (previously only in
	// desktop-legacy): Accessible Get* at all three shapes, Properties
	// Get{,All}, Collection GetMatches, GetApplicationBusAddress
	c.Assert(snippet, testutil.Contains,
		"dbus (send)\n    bus=accessibility\n"+
			"    path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"org.a11y.atspi.Accessible\"\n    member=\"Get*\"\n"+
			"    peer=(label=\"{snap.*,unconfined}\"),\n")
	c.Assert(snippet, testutil.Contains,
		"path=\"/**/a11y/*\"\n    interface=\"org.a11y.atspi.Accessible\"\n"+
			"    member=\"Get*\"")
	c.Assert(snippet, testutil.Contains,
		"path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"org.freedesktop.DBus.Properties\"\n"+
			"    member=\"Get{,All}\"")
	c.Assert(snippet, testutil.Contains,
		"path=\"/org/a11y/atspi/accessible/[0-9]*\"\n"+
			"    interface=\"org.a11y.atspi.Collection\"\n"+
			"    member=\"GetMatches\"")
	c.Assert(snippet, testutil.Contains,
		"path=\"/org/a11y/atspi/accessible/root\"\n"+
			"    interface=\"org.a11y.atspi.Application\"\n"+
			"    member=\"GetApplicationBusAddress\"")
	// the registry-side sends are pinned to the registry name on the
	// provider's label glob (the same peer shape as desktop-legacy's
	// existing registry sends):
	c.Assert(snippet, testutil.Contains,
		"member=\"{RegisterEvent,DeregisterEvent,GetRegisteredEvents}\"\n"+
			"    peer=(name=org.a11y.atspi.Registry, label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),\n")
	c.Assert(snippet, testutil.Contains,
		"member=\"{RegisterKeystrokeListener,DeregisterKeystrokeListener,GetKeystrokeListeners,GenerateKeyboardEvent,GenerateMouseEvent,NotifyListenersSync,NotifyListenersAsync}\"\n"+
			"    peer=(name=org.a11y.atspi.Registry, label=\"{snap.ubuntu-desktop-a11y.*,unconfined}\"),\n")
	// every app-tree interface rides the same application-peer
	// alternation; the plug adds NO receive rules at all (the reader's
	// receives come from desktop-legacy's narrowed client receive) and
	// no registry receives beyond the provider slot's own:
	c.Assert(snippet, Not(testutil.Contains), "dbus (receive)")
	c.Assert(snippet, Not(testutil.Contains), "bus=system")
	c.Assert(snippet, Not(testutil.Contains), "peer=(label=\"{snap.ubuntu-desktop-a11y.*")
}

func (s *AccessibilityProviderInterfaceSuite) TestSecCompPermanentSlotEmpty(c *C) {
	// T29 C1: nothing on installation
	appSet, err := interfaces.NewSnapAppSet(s.slotInfo.Snap, nil)
	c.Assert(err, IsNil)
	spec := seccomp.NewSpecification(appSet)
	c.Assert(spec.AddPermanentSlot(s.iface, s.slotInfo), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)
	c.Assert(spec.SnippetForTag("snap.provider.bus"), Equals, "")
}

func (s *AccessibilityProviderInterfaceSuite) TestSecCompConnectedSlot(c *C) {
	plug, _ := MockConnectedPlug(c, accessibilityProviderPlugYaml, nil, "accessibility-provider")
	slot, _ := MockConnectedSlot(c, accessibilityProviderSlotYaml, nil, "accessibility-provider")
	appSet, err := interfaces.NewSnapAppSet(slot.Snap(), nil)
	c.Assert(err, IsNil)
	spec := seccomp.NewSpecification(appSet)
	c.Assert(spec.AddConnectedSlot(s.iface, plug, slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.provider.bus"})
	snippet := spec.SnippetForTag("snap.provider.bus")
	// aa_getcon() (dbus bus_apparmor_full_init) needs the LSM
	// self-attribute syscall; the strict template denies it and
	// libapparmor does not fall back to /proc attr on EPERM (T29 C1:
	// rides the connection)
	c.Assert(snippet, testutil.Contains, "\nlsm_get_self_attr\n")
}

func (s *AccessibilityProviderInterfaceSuite) TestBaseDeclarationSlots(c *C) {
	// T29 C1: the slot is super-privileged - installation denied by the
	// base declaration (only a snap-declaration can allow it; the
	// custom-device/opengl-driver-libs posture), never auto-connected.
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "allow-installation: false")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "deny-auto-connection: true")
	// and the plug side keeps its T30 gating
	c.Assert(si.BaseDeclarationPlugs, testutil.Contains, "allow-installation: false")
}
