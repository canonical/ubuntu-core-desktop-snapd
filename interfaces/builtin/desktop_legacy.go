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

package builtin

import (
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
)

const desktopLegacySummary = `allows privileged access to desktop legacy methods`

// While this gives privileged access to legacy methods we should auto-connect
// this transitional interface since most desktop applications will need it.
// When safe alternative methods are added to the desktop interface by default,
// we can consider making this manually connected.
const desktopLegacyBaseDeclarationSlots = `
  desktop-legacy:
    allow-installation:
      slot-snap-type:
        - core
`

const desktopLegacyConnectedPlugAppArmor = `
# Description: Can access common desktop legacy methods. This gives privileged
# access to the user's input.

# accessibility (a11y)
# Two peer classes, scoped differently (T17 D3):
#
# - Provider peers (the org.a11y.Bus owner on the session bus and the
#   at-spi registry on the private bus, which with a confined provider
#   both run under the provider snap's label) are pinned to
#   snap.ubuntu-desktop-a11y.* plus the legacy unconfined provider.
#   Name ownership is NOT what enforces this (a squatter could own
#   org.a11y.Bus today - that is D4's reservation problem); the pin
#   removes the generic snap.* reach these rules had under 1826bfd5af.
#
# - Application peers (event broadcasts and tree reads between a11y
#   clients, e.g. the screen reader reading application trees) keep the
#   wide {snap.*,unconfined} alternation: org.a11y.atspi is not
#   designed for application isolation (upstream's comment below), and
#   pinning those peers to the provider's label would break every
#   legitimate shell->app and reader->app read. The accessibility bus
#   is a shared trust domain; the long-term fix for scoping these is
#   provider-interface label work (T11 §2/§5), not this file.
#include <abstractions/dbus-session-strict>
dbus (send)
    bus=session
    path=/org/a11y/bus
    interface=org.a11y.Bus
    member=GetAddress
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
# The status object next to GetAddress: property READS are the GTK
# 4.16+ a11y activation gate (org.a11y.Status.IsEnabled). Read-only -
# a client must not be able to flip a11y state from here (the write
# route stays with unconfined callers and the gsettings/dconf path);
# the launcher-side receive for this surface lives in the
# accessibility-provider slot snippet.
dbus (send)
    bus=session
    path=/org/a11y/bus
    interface=org.freedesktop.DBus.Properties
    member={Get,GetAll}
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (send)
    bus=session
    path=/org/a11y/bus
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),

#include <abstractions/dbus-accessibility-strict>

# Allow access to the non-abstract D-Bus socket used by at-spi > 2.42.0
#   https://gitlab.gnome.org/GNOME/at-spi2-core/-/issues/43
# With a confined provider the launcher binds its socket on this
# conventional path (launch-a11y-bus overrides XDG_RUNTIME_DIR to the
# host per-uid runtime dir), so no snap.* path rule exists: a snap.*
# wildcard here would admit every snap's at-spi socket, letting an
# X11-property-poisoning attacker redirect clients to its own bus
# (T17 D2).
owner /{,var/}run/user/[0-9]*/at-spi/bus* rw,

# Allow access to the socket used by speech-dispatcher
owner /{,var/}run/user/[0-9]*/speech-dispatcher/speechd.sock rw,

# Allow the accessibility services in the user session to reach us, on
# the private bus, through the three surfaces a NON-READER a11y client
# must accept (T29 C2: the catch-all unnamed receive is gone — it was
# the cross-snap tree-read hole; a desktop-legacy-only snap could read
# every other snap's tree by directly messaging its objects). The
# kernel checks BOTH sides of every message: the sender's send rule
# AND the receiver's receive rule — each block below leans on that.
#
# 1. Provider-lifecycle: what the registry/bus daemon legitimately
# sends to every client (liveness probe, Id assignment, listener
# bookkeeping, delivered key events) and the driver's own
# bus-lifecycle signals. Pinned to the provider's label plus the
# legacy unconfined provider (the established provider-peer pin).
# Reads app trees? No — every rule is member- and path-scoped.
dbus (receive)
    bus=accessibility
    interface=org.freedesktop.DBus
    member={NameAcquired,NameLost,NameOwnerChanged}
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path=/
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/accessible/root
    interface=org.freedesktop.DBus.Properties
    member=Set
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/registry
    interface=org.a11y.atspi.Registry
    member=EventListener{Registered,Deregistered}
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/registry/deviceeventcontroller
    interface=org.a11y.atspi.DeviceEventListener
    member=KeystrokeListener{Registered,Deregistered}
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
# delivered keyboard events: the DEC calls NotifyListeners{Sync,Async}
# ON the registered listener's connection (the listener flow that
# orca's key grabs ride); sent by the registry under the provider's
# label
dbus (receive)
    bus=accessibility
    path=/org/a11y/atspi/registry/deviceeventcontroller
    interface=org.a11y.atspi.DeviceEventController
    member=NotifyListeners{Sync,Async}
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
#
# 2. Reader method calls. Two kernel-gated classes:
#    a. The reader-ROLE-ONLY interfaces (Text, EditableText, Action,
#       Component, Selection, Hypertext, Hyperlink, Document, Table,
#       TableCell): ONLY profiles carrying the reader grant (the
#       accessibility-provider connected plug) have send rules for
#       these, so accepting them from any confined/unconfined peer
#       cannot admit a desktop-legacy-only snap — its send side is
#       denied first. Interface-scoped (any member), three path
#       shapes, mirroring the reader role's sends.
#    b. The shared read surfaces (Accessible Get*, Properties
#       Get{,All}, Collection GetMatches,
#       Application GetApplicationBusAddress, Cache GetItems) plus
#       Properties.Set (the reader's Value drive). T45 (owner ruling):
#       the desktop-legacy read SENDS for these surfaces are GONE —
#       the only confined senders left are reader-role profiles, which
#       all sit under the provider's label glob, so this pin is what
#       admits the reader; a desktop-legacy-only snap is denied at its
#       own send side first and at this wall second (the T43 wall kept
#       as defence in depth; the unconfined leg keeps the fat-line
#       unconfined provider working).
dbus (receive)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="{org.a11y.atspi.Text,org.a11y.atspi.EditableText,org.a11y.atspi.Action,org.a11y.atspi.Component,org.a11y.atspi.Selection,org.a11y.atspi.Hypertext,org.a11y.atspi.Hyperlink,org.a11y.atspi.Document,org.a11y.atspi.Table,org.a11y.atspi.TableCell}"
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="{org.a11y.atspi.Text,org.a11y.atspi.EditableText,org.a11y.atspi.Action,org.a11y.atspi.Component,org.a11y.atspi.Selection,org.a11y.atspi.Hypertext,org.a11y.atspi.Hyperlink,org.a11y.atspi.Document,org.a11y.atspi.Table,org.a11y.atspi.TableCell}"
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/**/a11y/*"
    interface="{org.a11y.atspi.Text,org.a11y.atspi.EditableText,org.a11y.atspi.Action,org.a11y.atspi.Component,org.a11y.atspi.Selection,org.a11y.atspi.Hypertext,org.a11y.atspi.Hyperlink,org.a11y.atspi.Document,org.a11y.atspi.Table,org.a11y.atspi.TableCell}"
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="{org.a11y.atspi.Accessible,org.a11y.atspi.Application,org.freedesktop.DBus.Properties,org.a11y.atspi.Collection,org.a11y.atspi.Cache}"
    member="Get*"
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="{org.a11y.atspi.Accessible,org.a11y.atspi.Application,org.freedesktop.DBus.Properties,org.a11y.atspi.Collection,org.a11y.atspi.Cache}"
    member="Get*"
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/**/a11y/*"
    interface="{org.a11y.atspi.Accessible,org.a11y.atspi.Application,org.freedesktop.DBus.Properties,org.a11y.atspi.Collection,org.a11y.atspi.Cache}"
    member="Get*"
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface=org.freedesktop.DBus.Properties
    member=Set
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface=org.freedesktop.DBus.Properties
    member=Set
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (receive)
    bus=accessibility
    path="/**/a11y/*"
    interface=org.freedesktop.DBus.Properties
    member=Set
    peer=(label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
#
# 3. Event and cache broadcasts (the one shared trust domain, T29 C5's
# accepted risk, now stated): apps broadcast events and cache updates
# and every a11y client receives them — interface-scoped, any member,
# any peer. This is the RECEIVE counterpart of the interface-scoped
# event SENDS above; spoofed broadcasts are the documented C5 risk,
# unchanged by this narrowing.
dbus (receive)
    bus=accessibility
    interface=org.a11y.atspi.Event.Object
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    interface=org.a11y.atspi.Event.Window
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    interface=org.a11y.atspi.Event.Document
    peer=(label="{snap.*,unconfined}"),
dbus (receive)
    bus=accessibility
    interface=org.a11y.atspi.Cache
    peer=(label="{snap.*,unconfined}"),
# NOTE (T29 C2, D3 line): there is deliberately NO unnamed receive on
# bus=accessibility here — no rule without an interface condition and
# no receive with a bare snap.* peer survives this narrowing.

# Provider peers: the registry runs under the provider's label with a
# confined provider (at-spi2-registryd shares the bus app's profile);
# with the legacy fat provider it is unconfined.
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Socket"
    member="Embed"
    peer=(name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/registry"
    interface="org.a11y.atspi.Registry"
    member="GetRegisteredEvents"
    peer=(name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/registry/deviceeventcontroller"
    interface="org.a11y.atspi.DeviceEventController"
    member="Get{DeviceEvent,Keystroke}Listeners"
    peer=(name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/registry/deviceeventcontroller"
    interface="org.a11y.atspi.DeviceEventController"
    member="NotifyListenersSync"
    peer=(name=org.a11y.atspi.Registry, label="{snap.ubuntu-desktop-a11y.*,unconfined}"),

# org.a11y.atspi is not designed for application isolation and these rules
# can be used to send change events for other processes. The event
# surfaces are scoped by INTERFACE (not member): the upstream member
# lists are stale against GTK4's emissions (it also emits
# SelectionChanged, BoundsChanged, TextSelectionChanged, window
# events...), and events are broadcasts whose content readers already
# get through the Get* rules - the shared trust domain is the peer
# alternation (T24: the cache broadcasts were denied member-by-member).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Event.Object"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/root"
    interface="org.a11y.atspi.Event.Window"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),
# T45 (owner ruling): the desktop-legacy READ sends are DROPPED. The
# reader role (the accessibility-provider connected plug) is the one
# complete statement of the reader send-set, so the pre-reader-role
# sends desktop-legacy granted to {snap.*,unconfined} are obsolete
# (T29 C2's endpoint). Gone from this file: the tree reads at all
# three path shapes — org.a11y.atspi.Accessible Get*, org.freedesktop
# .DBus.Properties Get{,All} at root, /org/a11y/atspi/accessible/
# [0-9]* and /**/a11y/*; org.a11y.atspi.Collection GetMatches and
# org.a11y.atspi.Application GetApplicationBusAddress at their classic
# shapes — and the GetItems (unicast read) half of the cache rule,
# which is narrowed to the Add/RemoveAccessible broadcasts. What
# remains at these shapes is the event/broadcast class (below) and the
# registry-pinned sends. Non-reader clients never legitimately read
# other snaps' trees; readers carry these sends from the reader role.
# The GTK4 a11y object layout (gtkatspiroot.c): an application registers
# its root at /org/a11y/atspi/accessible/root and hosts its widget
# contexts under <application-object-path>/a11y/<context-id> (e.g.
# /org/gnome/Calculator/a11y/f7b095c8-... - the context id is a UUID in
# current GTK4, and /org/gtk/application/<name>/a11y/<n> for the
# non-GApplication shape). The classic-layout rules above and below
# only cover /org/a11y/atspi/accessible/..., where readers were
# historically unconfined and unmediated. The reader grants at the
# GTK4 paths live in the reader role (the accessibility-provider
# connected plug — T24 live evidence: the calculator registers, then
# every reader-side query at its context paths is denied); the
# desktop-legacy read sends at this shape are dropped (T45).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Event.Object"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/accessible/[0-9]*"
    interface="org.a11y.atspi.Event.Window"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),
# The CLASSIC numeric object paths (pre-GTK4 atspi layout): apps that
# are not GTK4 (gnome-shell, gtk3 apps) host their tree at
# /org/a11y/atspi/accessible/<n>. T45 (owner ruling): the reader sends
# that were granted here for the confined reader — org.a11y.atspi
# .Accessible Get* (added bafad9d025 after the T25 gate evidence: 1267
# denials, all Accessible Get* at /org/a11y/atspi/accessible/<n>,
# sender snap.ubuntu-desktop-a11y.orca, peer
# snap.ubuntu-desktop-session.gnome-shell) and org.a11y.atspi
# .Collection GetMatches (added 986a18cefa after the T26 greeter
# re-test) — are DROPPED with the rest of the pre-reader-role
# desktop-legacy read sends; the reader role grants both at this
# shape. A desktop-legacy-only snap that tries to read them is denied
# at its own send side first (no send rule survives) and at the pinned
# Get* receives in the block above second (the T43 wall, unchanged).
# the GTK4 context paths (see the comment above)
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Event.Object"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Event.Window"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),
dbus (send)
    bus=accessibility
    path="/**/a11y/*"
    interface="org.a11y.atspi.Event.Document"
    peer=(name=org.freedesktop.DBus, label="{snap.*,unconfined}"),

# T45 (owner ruling): the cache send is NARROWED to the broadcasts.
# org.a11y.atspi.Cache GetItems is a unicast READ of another snap's
# cached tree — that read-send is dropped (the reader role grants
# Cache GetItems, member-scoped); Add/RemoveAccessible stay, the
# C5-class broadcast surface, matching the receive side (the
# org.a11y.atspi.Cache receive in the event block above is unchanged).
dbus (send)
    bus=accessibility
    path="/org/a11y/atspi/cache"
    interface="org.a11y.atspi.Cache"
    member="{AddAccessible,RemoveAccessible}"
    peer=(label="{snap.*,unconfined}"),


# ibus
# subset of ibus abstraction
/usr/lib/@{multiarch}/gtk-2.0/[0-9]*/immodules/im-ibus.so mr,
owner @{HOME}/.config/ibus/      r,
owner @{HOME}/.config/ibus/bus/  r,
owner @{HOME}/.config/ibus/bus/* r,

# allow communicating with ibus-daemon (this allows sniffing key events)
unix (connect, receive, send)
    type=stream
    peer=(addr="@/tmp/ibus/dbus-*"),

unix (connect, receive, send)
    type=stream
    peer=(addr="@@{HOME}/.cache/ibus/dbus-*"),

# when running with glib >= 2.75.0, ibus uses a regular socket
owner @{HOME}/.cache/ibus/dbus-* rw,


# mozc
# allow communicating with mozc server
unix (connect, receive, send)
     type=stream
     peer=(addr="@tmp/.mozc.*"),

# gcin
# allow communicating with gcin server
unix (connect, receive, send)
     type=stream
     peer=(addr="@tmp/gcin-*/socket*"),

# fcitx
# allow communicating with fcitx dbus service
dbus send
    bus=fcitx
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName}
    peer=(name=org.freedesktop.DBus),

owner @{HOME}/.config/fcitx/dbus/* r,

# allow creating an input context
dbus send
    bus={fcitx,session}
    path=/inputmethod
    interface=org.fcitx.Fcitx.InputMethod
    member=CreateIC*
    peer=(label=unconfined),

# allow setting up and tearing down the input context
dbus send
    bus={fcitx,session}
    path=/inputcontext_[0-9]*
    interface=org.fcitx.Fcitx.InputContext
    member="{Close,Destroy,Enable}IC"
    peer=(label=unconfined),

dbus send
    bus={fcitx,session}
    path=/inputcontext_[0-9]*
    interface=org.fcitx.Fcitx.InputContext
    member=Reset
    peer=(label=unconfined),

# allow service to send us signals
dbus receive
    bus=fcitx
    peer=(label=unconfined),

dbus receive
    bus=session
    interface=org.fcitx.Fcitx.*
    peer=(label=unconfined),

# use the input context
dbus send
    bus={fcitx,session}
    path=/inputcontext_[0-9]*
    interface=org.fcitx.Fcitx.InputContext
    member="Focus{In,Out}"
    peer=(label=unconfined),

dbus send
    bus={fcitx,session}
    path=/inputcontext_[0-9]*
    interface=org.fcitx.Fcitx.InputContext
    member="{CommitPreedit,Set*}"
    peer=(label=unconfined),

# this is an information leak and allows key and mouse sniffing. If the input
# context path were tied to the process' security label, this would not be an
# issue.
dbus send
    bus={fcitx,session}
    path=/inputcontext_[0-9]*
    interface=org.fcitx.Fcitx.InputContext
    member="{MouseEvent,ProcessKeyEvent}"
    peer=(label=unconfined),

# this method does not exist with the sunpinyin backend (at least), so allow
# it for other input methods. This may consitute an information leak (which,
# again, could be avoided if the path were tied to the process' security
# label).
dbus send
    bus={fcitx,session}
    path=/inputcontext_[0-9]*
    interface=org.freedesktop.DBus.Properties
    member=GetAll
    peer=(label=unconfined),

# gtk2/gvfs gtk_show_uri()
dbus (send)
    bus=session
    path=/org/gtk/vfs/mounttracker
    interface=org.gtk.vfs.MountTracker
    member=ListMountableInfo,
dbus (send)
    bus=session
    path=/org/gtk/vfs/mounttracker
    interface=org.gtk.vfs.MountTracker
    member=LookupMount,

# Snaps are unable to use the data in mimeinfo.cache (since they can't execute
# the returned desktop file themselves). unity messaging menu doesn't require
# mimeinfo.cache and xdg-mime will fallback to reading the desktop files
# directly to look for MimeType. Since reading the snap's own desktop files is
# allowed, we can safely deny access to this file (and xdg-mime will either
# return one of the snap's mimetypes, or none).
deny /var/lib/snapd/desktop/applications/mimeinfo.cache r,

# glib-networking's GLib proxy (different than the portal's proxy service
# org.freedesktop.portal.ProxyResolver). The Lookup API allows specifying
# various URLs (eg, file://, http:// and https://) which will be given to the
# unconfined glib-pacrunner.
dbus (send)
    bus=session
    path=/org/gtk/GLib/PACRunner
    interface=org.gtk.GLib.PACRunner
    member=Lookup
    peer=(label=unconfined),

# dbusmenu
dbus (send)
    bus=session
    path=/{MenuBar{,/[0-9A-F]*},com/canonical/{menu/[0-9A-F]*,dbusmenu}}
    interface=com.canonical.dbusmenu
    member="{LayoutUpdated,ItemsPropertiesUpdated}"
    peer=(label="{plasmashell,unconfined}"),

dbus (receive)
    bus=session
    path=/{MenuBar{,/[0-9A-F]*},com/canonical/{menu/[0-9A-F]*,dbusmenu}}
    interface="{com.canonical.dbusmenu,org.freedesktop.DBus.Properties}"
    member=Get*
    peer=(label="{plasmashell,unconfined}"),

dbus (receive)
    bus=session
    path=/{MenuBar{,/[0-9A-F]*},com/canonical/{menu/[0-9A-F]*,dbusmenu}}
    interface=com.canonical.dbusmenu
    member="{AboutTo*,Event*}"
    peer=(label="{plasmashell,unconfined}"),

dbus (receive)
    bus=session
    path=/{MenuBar{,/[0-9A-F]*},com/canonical/{menu/[0-9A-F]*,dbusmenu}}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label="{plasmashell,unconfined}"),

dbus (receive)
    bus=session
    path=/com/canonical/dbusmenu
    interface=org.freedesktop.DBus.Properties
    member=Get*
    peer=(label="{plasmashell,unconfined}"),

# app-indicators
dbus (send)
    bus=session
    path=/StatusNotifierWatcher
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(name=org.kde.StatusNotifierWatcher, label=unconfined),

dbus (send)
    bus=session
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="{GetConnectionUnixProcessID,RequestName,ReleaseName}"
    peer=(name=org.freedesktop.DBus, label=unconfined),

dbus (bind)
    bus=session
    name=org.kde.StatusNotifierItem-[0-9]*,

dbus (send)
    bus=session
    path=/StatusNotifierWatcher
    interface=org.freedesktop.DBus.Properties
    member=Get
    peer=(name=org.kde.StatusNotifierWatcher, label=unconfined),

dbus (send)
    bus=session
    path=/{StatusNotifierWatcher,org/ayatana/NotificationItem/*}
    interface=org.kde.StatusNotifierWatcher
    member=RegisterStatusNotifierItem
    peer=(label="{plasmashell,unconfined}"),

dbus (send)
    bus=session
    path=/{StatusNotifierItem,org/ayatana/NotificationItem/*}
    interface=org.kde.StatusNotifierItem
    member="New{AttentionIcon,Icon,IconThemePath,OverlayIcon,Status,Title,ToolTip}"
    peer=(name=org.freedesktop.DBus, label="{plasmashell,unconfined}"),

dbus (receive)
    bus=session
    path=/{StatusNotifierItem,org/ayatana/NotificationItem/*}
    interface=org.kde.StatusNotifierItem
    member={Activate,ContextMenu,Scroll,SecondaryActivate,ProvideXdgActivationToken,XAyatanaSecondaryActivate}
    peer=(label="{plasmashell,unconfined}"),

dbus (send)
    bus=session
    path=/{StatusNotifierItem/menu,org/ayatana/NotificationItem/*/Menu}
    interface=com.canonical.dbusmenu
    member="{LayoutUpdated,ItemsPropertiesUpdated}"
    peer=(name=org.freedesktop.DBus, label="{plasmashell,unconfined}"),

dbus (receive)
    bus=session
    path=/{StatusNotifierItem,StatusNotifierItem/menu,org/ayatana/NotificationItem/**}
    interface={org.freedesktop.DBus.Properties,com.canonical.dbusmenu}
    member={Get*,AboutTo*,Event*}
    peer=(label="{plasmashell,unconfined}"),

# notifications
dbus (send)
    bus=session
    path=/org/freedesktop/Notifications
    interface=org.freedesktop.Notifications
    member="{GetCapabilities,GetServerInformation,Notify,CloseNotification}"
    peer=(label=unconfined),

dbus (receive)
    bus=session
    path=/org/freedesktop/Notifications
    interface=org.freedesktop.Notifications
    member={ActionInvoked,NotificationClosed,NotificationReplied}
    peer=(label=unconfined),

# KDE Plasma's Inhibited property indicating "do not disturb" mode
# https://invent.kde.org/plasma/plasma-workspace/-/blob/master/libnotificationmanager/dbus/org.freedesktop.Notifications.xml#L42
dbus (send)
    bus=session
    path=/org/freedesktop/Notifications
    interface=org.freedesktop.DBus.Properties
    member="Get{,All}"
    peer=(label=unconfined),

dbus (receive)
    bus=session
    path=/org/freedesktop/Notifications
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=unconfined),

dbus (send)
    bus=session
    path=/org/ayatana/NotificationItem/*
    interface=org.kde.StatusNotifierItem
    member=XAyatanaNew*
    peer=(name=org.freedesktop.DBus, label="{plasmashell,unconfined}"),
`

const desktopLegacyConnectedPlugSecComp = `
# Description: Can access common desktop legacy methods. This gives privileged
# access to the user's input.

listen
accept
accept4
`

type desktopLegacyInterface struct {
	commonInterface
}

func (iface *desktopLegacyInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(desktopLegacyConnectedPlugAppArmor)

	// the DesktopFileRules can conflict with the rules in other, more privileged,
	// interfaces (like desktop-launch), so they are added here with the minimum
	// priority, while those other, more privileged, interfaces will add an empty
	// string with a bigger privilege value.
	desktopSnippet, err := getDesktopFileRules(plug.Snap())
	if err != nil {
		return err
	}
	spec.AddPrioritizedSnippet(desktopSnippet, prioritizedSnippetDesktopFileAccess, desktopLegacyAndUnity7Priority)

	return nil
}

func init() {
	registerIface(&desktopLegacyInterface{
		commonInterface: commonInterface{
			name:                 "desktop-legacy",
			summary:              desktopLegacySummary,
			implicitOnClassic:    true,
			implicitOnCore:       true,
			baseDeclarationSlots: desktopLegacyBaseDeclarationSlots,
			connectedPlugSecComp: desktopLegacyConnectedPlugSecComp,
		},
	})
}
