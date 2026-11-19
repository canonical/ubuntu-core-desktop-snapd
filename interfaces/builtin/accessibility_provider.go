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

package builtin

import (
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
)

// The accessibility-provider interface supports running the session
// accessibility provider (org.a11y.Bus, the AT-SPI bus and registry) as
// a strictly-confined provider snap (ubuntu-desktop-a11y). It follows
// the fprintd/accountsservice/bolt/geoclue provider-snap pattern: the
// plain dbus slot supplies activation and name ownership of org.a11y.Bus
// on the session bus, this interface supplies everything the provider's
// own daemon needs on top of that.
//
// The slot side carries, in the CONNECTED-slot snippet, the libapparmor
// kernel-query capability (the provider's private accessibility
// dbus-daemon mediates its own bus, which requires the daemon to answer
// label queries through libapparmor: aa_is_enabled() resolves securityfs
// with setmntent("/proc/mounts") (aa_find_mountpoint), and
// aa_query_label() opens /sys/kernel/security/apparmor/.access O_RDWR to
// submit a query and read the answer — without these dbus'
// bus_apparmor_pre_init() fail-opens: the daemon behaves as if AppArmor
// was not present and mediates nothing (T18 E2)), the LSM
// self-attribute syscall (aa_getcon for the daemon's own label), the
// conventional socket path, and the provider-side accessibility-bus
// contract. The same two-rule query shape is what the
// thumbnailer-service interface ships for its aa_query_label use.
//
// Privilege placement (T29 C1): NOTHING is granted by the permanent
// slot snippet. Installation of the slot is denied by the base
// declaration unless a snap-declaration explicitly allows it (the
// snapd-control/kernel-module-control/custom-device posture: the
// capability is super-privileged — the .access query discloses the
// AppArmor policy of all processes); --dangerous local installs still
// pass snapd's minimal candidate check (interfaces/policy/policy.go
// checks only snap-type constraints of allow-installation for
// --dangerous candidates and ignores deny rules), so local testing is
// not affected. Every grant rides a CONNECTION: a slot with no
// connected plug contributes no rules at all. On Ubuntu Core Desktop
// the gadget wiring connects the provider snap's reader plug
// same-snap, which is what keeps the provider daemon's privileges in
// place (and makes them disappear on disconnect — the consent model).
//
// The plug side carries the reader role (see the comment above
// accessibilityProviderConnectedPlugAppArmor): the complete
// screen-reader send-set on the private bus (T29 C2: the role is the
// one statement of what a reader may send; desktop-legacy keeps its
// client surface for non-reader flows). The base declaration gates the
// plug to installation + manual connection (never auto); the a11y
// snap's orca app holds it as a same-snap connection.
const accessibilityProviderSummary = `allows operating as the accessibility (AT-SPI) bus provider`

const accessibilityProviderBaseDeclarationPlugs = `
  accessibility-provider:
    allow-installation: false
    deny-auto-connection: true
`

const accessibilityProviderBaseDeclarationSlots = `
  accessibility-provider:
    allow-installation: false
    deny-auto-connection: true
`

// The plug side is the READER role (T11 §2: "define the reader contract
// from at-spi2-core's interface list, once, as a reader role"; T29 C4):
// what a screen reader must be able to SEND on the private bus, derived
// from at-spi2-core's interface XML (xml/*.xml, 2.60.x) rather than
// chased denial-by-denial. The member lists below are the complete
// 2.60 interface surfaces a reader drives: the app-tree interfaces
// (Text, EditableText, Action, Component, Selection, Hypertext/
// Hyperlink, Document, Table, TableCell, Cache) toward application
// peers, the connection-root Peer.Ping liveness probe of those peers
// (the post-login handshake member, T32/T33), and the registry-side
// interfaces (Registry event
// registration, the DeviceEventController key/mouse listener and
// synthetic-event surface) toward the registry, which runs inside the
// provider. Value has no methods in the XML (properties only): reads
// ride the client's Properties Get{,All} grant and SetCurrentValue is
// the Properties.Set rule below. The review's "RegisterDeviceEvent-
// Listener"/"NotifyKeys" DEC members do not exist in 2.60: device
// events register through Registry.RegisterEvent (mouse:* types), and
// the DEC surface is the seven methods in its XML. The tree-read
// sends (Accessible Get*, Properties Get{,All}, Collection
// GetMatches, Application GetApplicationBusAddress) complete the role
// (T29 C2): a reader holding this plug needs no other grant to walk
// and drive an application tree. desktop-legacy keeps the general
// client surface (handshake, registration, events, the same reads) so
// non-reader clients are unchanged; narrowing it further is the
// upstream-time work (the fork's narrowed CLIENT RECEIVE is what
// enforces the isolation line today).
//
// Peer discipline (T17 D3, maintained): every app-tree rule keeps the
// exact peer alternation of the reader sends desktop-legacy already
// carries ({snap.*,unconfined}); every registry rule keeps
// desktop-legacy's pinned registry peer
// (name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,
// unconfined}"). No rule is unnamed, no new peer class is introduced.
const accessibilityProviderConnectedPlugAppArmor = `
# Description: Can act as the accessibility (AT-SPI) screen reader
# toward the provider's private bus: read and drive application trees,
# register event/keystroke listeners and synthesise input via the
# registry's device-event controller.

# --- application-tree sends (three object-path shapes, mirroring the
# reader Get* sends desktop-legacy already carries: the registration
# root, the classic numeric layout and the GTK4 context paths).
# Peers are the application peers (the join-surface clients), the same
# alternation every existing reader read uses.
#
# org.a11y.atspi.Text: content reads, attribute runs, extents, the
# caret and selection control (SetCaretOffset is orca's caret
# navigation; the Add/Remove/SetSelection members are text selection).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Text"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Text"
    member="{SetCaretOffset,AddSelection,RemoveSelection,SetSelection,ScrollSubstringTo,ScrollSubstringToPoint}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Text"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Text"
    member="{SetCaretOffset,AddSelection,RemoveSelection,SetSelection,ScrollSubstringTo,ScrollSubstringToPoint}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Text"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Text"
    member="{SetCaretOffset,AddSelection,RemoveSelection,SetSelection,ScrollSubstringTo,ScrollSubstringToPoint}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.EditableText (the six members of the interface).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.EditableText"
    member="{SetTextContents,InsertText,CopyText,CutText,DeleteText,PasteText}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.EditableText"
    member="{SetTextContents,InsertText,CopyText,CutText,DeleteText,PasteText}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.EditableText"
    member="{SetTextContents,InsertText,CopyText,CutText,DeleteText,PasteText}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Action (Get* = Get{Description,Name,LocalizedName,
# KeyBinding,Actions}) plus the activation call.
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Action"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Action"
    member="DoAction"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Action"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Action"
    member="DoAction"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Action"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Action"
    member="DoAction"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Component (Get* = Get{AccessibleAtPoint,Extents,
# Position,Size,Layer,MDIZOrder,Alpha}) plus Contains, GrabFocus, the
# geometry setters and the scrolling calls.
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Component"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Component"
    member="{Contains,GrabFocus,SetExtents,SetPosition,SetSize,ScrollTo,ScrollToPoint}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Component"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Component"
    member="{Contains,GrabFocus,SetExtents,SetPosition,SetSize,ScrollTo,ScrollToPoint}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Component"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Component"
    member="{Contains,GrabFocus,SetExtents,SetPosition,SetSize,ScrollTo,ScrollToPoint}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Selection (the seven members).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Selection"
    member="{GetSelectedChild,SelectChild,DeselectSelectedChild,IsChildSelected,SelectAll,ClearSelection,DeselectChild}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Selection"
    member="{GetSelectedChild,SelectChild,DeselectSelectedChild,IsChildSelected,SelectAll,ClearSelection,DeselectChild}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Selection"
    member="{GetSelectedChild,SelectChild,DeselectSelectedChild,IsChildSelected,SelectAll,ClearSelection,DeselectChild}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Hypertext and the Hyperlink members (hyperlink state
# is queried on the same accessible objects that carry Hypertext).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Hypertext"
    member="{GetNLinks,GetLink,GetLinkIndex}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Hypertext"
    member="{GetNLinks,GetLink,GetLinkIndex}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Hypertext"
    member="{GetNLinks,GetLink,GetLinkIndex}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Hyperlink"
    member="{GetObject,GetURI,IsValid}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Hyperlink"
    member="{GetObject,GetURI,IsValid}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Hyperlink"
    member="{GetObject,GetURI,IsValid}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Document (the five members; document TEXT rides the
# Text interface on the same object - the XML has no GetTextContents).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Document"
    member="{GetLocale,GetAttributeValue,GetAttributes,GetTextSelections,SetTextSelections}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Document"
    member="{GetLocale,GetAttributeValue,GetAttributes,GetTextSelections,SetTextSelections}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Document"
    member="{GetLocale,GetAttributeValue,GetAttributes,GetTextSelections,SetTextSelections}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Table (the 20 members of the interface) and TableCell.
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Table"
    member="{GetAccessibleAt,GetIndexAt,GetRowAtIndex,GetColumnAtIndex,GetRowDescription,GetColumnDescription,GetRowExtentAt,GetColumnExtentAt,GetRowHeader,GetColumnHeader,GetSelectedRows,GetSelectedColumns,IsRowSelected,IsColumnSelected,IsSelected,AddRowSelection,AddColumnSelection,RemoveRowSelection,RemoveColumnSelection,GetRowColumnExtentsAtIndex}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Table"
    member="{GetAccessibleAt,GetIndexAt,GetRowAtIndex,GetColumnAtIndex,GetRowDescription,GetColumnDescription,GetRowExtentAt,GetColumnExtentAt,GetRowHeader,GetColumnHeader,GetSelectedRows,GetSelectedColumns,IsRowSelected,IsColumnSelected,IsSelected,AddRowSelection,AddColumnSelection,RemoveRowSelection,RemoveColumnSelection,GetRowColumnExtentsAtIndex}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Table"
    member="{GetAccessibleAt,GetIndexAt,GetRowAtIndex,GetColumnAtIndex,GetRowDescription,GetColumnDescription,GetRowExtentAt,GetColumnExtentAt,GetRowHeader,GetColumnHeader,GetSelectedRows,GetSelectedColumns,IsRowSelected,IsColumnSelected,IsSelected,AddRowSelection,AddColumnSelection,RemoveRowSelection,RemoveColumnSelection,GetRowColumnExtentsAtIndex}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.TableCell"
    member="{GetRowColumnSpan,GetColumnHeaderCells,GetRowHeaderCells}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.TableCell"
    member="{GetRowColumnSpan,GetColumnHeaderCells,GetRowHeaderCells}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.TableCell"
    member="{GetRowColumnSpan,GetColumnHeaderCells,GetRowHeaderCells}"
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Cache GetItems (the GTK4 cache object the client
# populates; mirrors desktop-legacy's T24 grant).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/cache"
    interface="org.a11y.atspi.Cache"
    member="GetItems"
    peer=(label="{snap.*,unconfined}"),

# --- tree-read sends (T29 C2 completion of the reader role): these
# were previously granted ONLY by desktop-legacy; the reader role is
# the one complete statement of the reader send-set, so they are
# enumerated here too. org.a11y.atspi.Accessible Get* is the tree walk
# itself (GetChildAtIndex, GetChildren, GetRole, GetState,
# GetAttributes...); org.freedesktop.DBus.Properties Get{,All} the
# property reads (Name, Description); org.a11y.atspi.Collection
# GetMatches the pyatspi tree search; org.a11y.atspi.Application
# GetApplicationBusAddress the registration address fetch. Same three
# path shapes and the same application-peer alternation as every
# reader send above (T25: 1267 denials, all Accessible Get* at
# /org/a11y/atspi/accessible/<n>; T26: Collection GetMatches).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Accessible"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Accessible"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Accessible"
    member="Get*"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.freedesktop.DBus.Properties"
    member="Get{,All}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.freedesktop.DBus.Properties"
    member="Get{,All}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.freedesktop.DBus.Properties"
    member="Get{,All}"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Collection"
    member="GetMatches"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Collection"
    member="GetMatches"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Collection"
    member="GetMatches"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Application"
    member="GetApplicationBusAddress"
    peer=(label="{snap.*,unconfined}"),

# The reader's liveness probe of application peers: the reader pings
# each app peer with org.freedesktop.DBus.Peer.Ping at the connection
# root during its startup handshake (T32/T33 verbatim AVCs, 3x orca ->
# gnome-shell on the private bus at path=/, the same shape the
# registry's own health check uses - T24's slot-side rule). The ping
# targets application peers, so it keeps the application-peer
# alternation of every reader send above.
dbus (send)
    bus=accessibility
    path=/
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label="{snap.*,unconfined}"),

# org.a11y.atspi.Value.SetCurrentValue: Value has no methods in the
# interface XML - it is properties-only (MinimumValue/MaximumValue/
# CurrentValue). The reads ride the client Properties Get{,All} grant;
# setting the value is this Properties.Set rule, scoped to the same
# three application-tree shapes and the same application peers as every
# reader send above (a reader that can read the whole tree can also
# drive its Value properties; kept explicit here so the role is the
# one complete statement of the reader send-set).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.freedesktop.DBus.Properties"
    member="Set"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.freedesktop.DBus.Properties"
    member="Set"
    peer=(label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.freedesktop.DBus.Properties"
    member="Set"
    peer=(label="{snap.*,unconfined}"),

# --- registry-side sends (the registry and the DeviceEventController
# live in at-spi2-registryd inside the provider). Peer pinned exactly
# like desktop-legacy's existing registry sends: the registry name on
# the provider's label glob, plus the legacy unconfined registry.
# Registration: the reader's event listeners (RegisterEvent covers the
# device/mouse event types too) and the DEC keystroke-listener
# keysets; Generate{Keyboard,Mouse}Event is the reader's synthetic
# input path (flat-review click, key synthesis) - it flows through the
# registry daemon, which mediates the real input device, not directly
# to applications.
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/registry"
    interface="org.a11y.atspi.Registry"
    member="{RegisterEvent,DeregisterEvent,GetRegisteredEvents}"
    peer=(name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/registry/deviceeventcontroller"
    interface="org.a11y.atspi.DeviceEventController"
    member="{RegisterKeystrokeListener,DeregisterKeystrokeListener,GetKeystrokeListeners,GenerateKeyboardEvent,GenerateMouseEvent,NotifyListenersSync,NotifyListenersAsync}"
    peer=(name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
`

const accessibilityProviderConnectedSlotAppArmor = `
# Description: Allow the accessibility provider's confined bus daemon to
# use the libapparmor kernel-query interface and to run its private
# (type=accessibility) D-Bus bus under AppArmor mediation. This
# discloses the AppArmor policy for all processes to the daemon via
# query answers; the unnamed dbus rules below admit only the provider's
# own peers, and the remaining rules are the path/interface/member-
# scoped app-facing join surface for desktop-legacy clients.
#
# Privilege placement (T29 C1): every rule here is a CONNECTED-slot
# grant — a slot with no connected plug contributes no rules at all,
# and a disconnect removes all of them. The base declaration denies
# installation of this slot unless a snap-declaration explicitly
# allows it, so no snap can obtain these grants merely by declaring
# the slot.

# aa_find_mountpoint(): setmntent("/proc/mounts") to locate securityfs
@{PROC}/@{pid}/mounts                   r,
# aa_query_label(): open .access O_RDWR (write the query, read the result)
/sys/kernel/security/apparmor/.access   rw,

# The launcher binds its bus socket on the conventional at-spi runtime
# path (T11 §3): launch-a11y-bus overrides XDG_RUNTIME_DIR to the host
# per-uid runtime dir, so unmodified client policy (desktop-legacy's
# stock /run/user/<uid>/at-spi/bus* rule) reaches the socket and no
# snap.* wildcard is needed anywhere.
#
# The socket path is part of the interface contract (T41 C8 evidence):
# a revision that moves the socket (e.g. by overriding XDG_RUNTIME_DIR)
# is out of contract and fails LOUDLY, not silently — the mkdir at the
# moved path is denied (verbatim T41 AVC), the launcher's anonymous
# /tmp fallback address is unreachable by clients (desktop-legacy's
# socket rule pins the conventional path), and clients crash-loop on
# the dangling address. The path is deliberately NOT derived from snap
# metadata: no declared-path metadata exists (the path is an
# at-spi2-core compiled-in convention set by the launcher), and the
# client-side socket rule lives in desktop-legacy, which cannot see a
# provider slot attribute. A path change is forbidden by contract; any
# future support for relocated sockets needs a cross-interface
# mechanism that moves the client rule too (upstream work).
owner /run/user/[0-9]*/at-spi/   rw,
owner /run/user/[0-9]*/at-spi/** rw,

# The private bus (type=accessibility) contract for the provider's own
# daemon and registry (both run under this snap's label). The kernel
# evaluates these rules when the daemon queries: driver-destined
# messages (Hello, AddMatch, ListNames, GetConnection*), the registry's
# name ownership, driver-originated signals (NameAcquired,
# NameOwnerChanged), and calls routed to the registry. Peers are the
# provider's own apps (same-snap clients plus the launcher and
# at-spi2-registryd, which share the bus app's profile) and unconfined
# host processes; cross-snap clients join via their own consent path
# (upstream: the provider-interface client rules). Derived from the
# T19 phase-1 live matrix under real mediation.
dbus (bind)
    bus=accessibility
    name=org.a11y.atspi.Registry,
dbus (receive)
    bus=accessibility
    peer=(label="{snap.@{SNAP_INSTANCE_NAME}.*,unconfined}"),
dbus (send)
    bus=accessibility
    peer=(label="{snap.@{SNAP_INSTANCE_NAME}.*,unconfined}"),

# Provider-to-app sends (T24 live evidence, thin image: the calculator
# registered and was then dropped from the desktop tree by the
# registry's health check). The contract is not receive-only: the
# registry and daemon address cross-snap clients too. All rules are
# interface/member/path-scoped and never name-less reads of app trees.
#
# The registry health-checks every registered application with
# org.freedesktop.DBus.Peer.Ping at path "/" every 30s
# (registryd/registry.c ping_applications) and DISABLES an app whose
# ping errors ("Disabling unresponsive app", ChildrenChanged remove) -
# with the unnamed send rule pinned to the provider's own peers, every
# cross-snap app was disabled half a minute after registering.
dbus (send)
    bus=accessibility
    path=/
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label=snap.*),

# The registry assigns each application its Id property after Embed
# (call_set_id: org.freedesktop.DBus.Properties.Set on the app's root
# object, which every at-spi app hosts at
# /org/a11y/atspi/accessible/root).
dbus (send)
    bus=accessibility
    path=/org/a11y/atspi/accessible/root
    interface=org.freedesktop.DBus.Properties
    member=Set
    peer=(label=snap.*),

# The registry broadcasts listener bookkeeping when a reader registers
# or deregisters an event (impl_RegisterEvent / remove_events), and the
# device event controller its keystroke-listener bookkeeping
# (deviceeventcontroller.c: KeystrokeListener{Registered,Deregistered}
# on the DeviceEventListener interface at the DEC path - 433 denials on
# the T28 final bake, all registryd->gnome-shell, with the rule absent).
dbus (send)
    bus=accessibility
    path=/org/a11y/atspi/registry
    interface=org.a11y.atspi.Registry
    member=EventListener{Registered,Deregistered}
    peer=(name=org.freedesktop.DBus, label=snap.*),
dbus (send)
    bus=accessibility
    path=/org/a11y/atspi/registry/deviceeventcontroller
    interface=org.a11y.atspi.DeviceEventListener
    member=KeystrokeListener{Registered,Deregistered}
    peer=(name=org.freedesktop.DBus, label=snap.*),

# The app-facing join surface for desktop-legacy clients (T17 D1, gate
# 2): unmodified store apps reach this provider with only their
# desktop-legacy plug (they cannot declare per-provider plugs), so the
# receives below mirror, for peer=(label=snap.*), exactly the messages
# the client side grants toward this snap:
# abstractions/dbus-accessibility-strict's driver handshake and
# desktop-legacy's pinned org.a11y.atspi.Registry sends. Every rule is
# scoped by path/interface/member - this is deliberately NOT the
# unnamed tree-walking surface (T17 D3): the provider never reads app
# trees; only readers do, under their own client rules.
#
# The consent model, stated honestly (T29 C3): the socket connect is
# NOT a per-provider consent act — desktop-legacy auto-connects for
# every store snap, so the only peers denied at the socket are snaps
# without desktop-legacy (the must-deny; gate 7 proves exactly that
# trivial case). Admission to the bus therefore means "any GUI snap".
# What gates the PRIVILEGED access on top of admission:
#   - installation of this slot: denied by the base declaration unless
#     a snap-declaration allows it (T29 C1);
#   - every rule in this snippet: rides the connection (removed on
#     disconnect);
#   - tree reads across snaps: a reader grant — the a11y client
#     receive in desktop-legacy admits reader-surface calls only from
#     reader-role senders (kernel-checked on the sender side) or the
#     provider's label (T29 C2);
#   - the session-bus GetAddress path: the only leg still behind an
#     explicit plug consent (dbus-a11y-bus-client), wired manually.

# Live evidence (thin image, a11y x2, snapd g61): gnome-calculator,
# gnome-shell and xdg-desktop-portal-gtk all connect to the private bus
# socket and are denied at the Hello receive (mask=receive
# label=snap.ubuntu-desktop-a11y.bus peer_label=<client>), while the
# session-bus GetAddress passes both sides - the join was the wall.
dbus (receive)
    bus=accessibility
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName}
    peer=(label=snap.*),

# Tree registration: the app embeds its root object into the registry
# (the atk-bridge/GTK4 registration call, gtk_at_spi_root_register) -
# the mirror of desktop-legacy's pinned Socket.Embed send.
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/accessible/root
    interface=org.a11y.atspi.Socket
    member=Embed
    peer=(label=snap.*),

# The reader-side registry and device-event-controller calls, mirrored
# from desktop-legacy's remaining sends pinned to
# name=org.a11y.atspi.Registry, so a cross-snap reader can run its full
# flow against this provider.
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/registry
    interface=org.a11y.atspi.Registry
    member=GetRegisteredEvents
    peer=(label=snap.*),
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/registry/deviceeventcontroller
    interface=org.a11y.atspi.DeviceEventController
    member={GetDeviceEventListeners,GetKeystrokeListeners,NotifyListenersSync}
    peer=(label=snap.*),

# The status object the launcher serves on the session bus next to
# org.a11y.Bus (/org/a11y/bus): property READS are the GTK 4.16+ a11y
# activation gate (org.a11y.Status.IsEnabled) and the gate-2 probe gap
# (busctl introspect of org.a11y.Status was denied for every peer - the
# generic dbus-slot receive rules pin org.a11y.Bus, and their
# name-derived path /org/a11y/Bus mismatches the served object path).
# Reads only: a confined client must not be able to flip a11y state
# from here; the write route stays with unconfined callers and the
# gsettings/dconf path. The generic dbus-slot snippets cannot express
# this scoping, so the provider interface carries it (the slot-hosting
# snap's profile is the launcher's profile).
dbus (receive)
    bus=session
    path=/org/a11y/bus
    interface=org.freedesktop.DBus.Properties
    member={Get,GetAll}
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=session
    path=/org/a11y/bus
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label="{snap.*,unconfined}"),
`

const accessibilityProviderConnectedSlotSecComp = `
# Description: Allow libapparmor's aa_getcon() (read own confinement)
# via the LSM self-attribute syscall. dbus' bus_apparmor_full_init()
# calls aa_getcon() for the daemon's own label when mediation is
# enabled; the strict template's syscall filter denies lsm_get_self_attr
# (kernel 6.8+), libapparmor treats the EPERM as "syscall present but
# denied at the hook level" and does NOT fall back to /proc/<pid>/attr,
# and the bus exits with "Error getting AppArmor context of bus"
# (T19 phase-1 capture). Read-only use; lsm_set_self_attr stays denied.
# Connected-slot grant (T29 C1): rides the connection like every other
# provider privilege.
lsm_get_self_attr
`

type accessibilityProviderInterface struct{}

func (iface *accessibilityProviderInterface) Name() string {
	return "accessibility-provider"
}

func (iface *accessibilityProviderInterface) StaticInfo() interfaces.StaticInfo {
	return interfaces.StaticInfo{
		Summary:              accessibilityProviderSummary,
		BaseDeclarationPlugs: accessibilityProviderBaseDeclarationPlugs,
		BaseDeclarationSlots: accessibilityProviderBaseDeclarationSlots,
	}
}

func (iface *accessibilityProviderInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(accessibilityProviderConnectedSlotAppArmor)
	return nil
}

func (iface *accessibilityProviderInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(accessibilityProviderConnectedPlugAppArmor)
	return nil
}

func (iface *accessibilityProviderInterface) SecCompConnectedSlot(spec *seccomp.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(accessibilityProviderConnectedSlotSecComp)
	return nil
}

func (iface *accessibilityProviderInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// provider capability, never auto-connected
	return false
}

func init() {
	registerIface(&accessibilityProviderInterface{})
}
