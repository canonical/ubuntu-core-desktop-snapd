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
	"strings"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
)

// The fprintd interface supports running fprintd (net.reactivated.Fprint)
// as a strictly-confined provider snap: the slot side is the daemon
// recipe (D-Bus receive rules, its fingerprint storage directory, and
// the reader device access libfprint enumerates through udev/sysfs), the
// plug side is the client recipe for fprintd consumers (the greeter and
// lock screen shell, the control-center enrollment UI, and the fprintd
// command-line clients).
//
// The daemon runs as root (the fat base never had an fprintd user; its
// unit and D-Bus service entry both run it as root) and authorizes
// privileged operations via polkit, for which the snap carries the
// built-in polkit plug.
const fprintdSummary = `allows operating as or interacting with the fprintd fingerprint service`

const fprintdBaseDeclarationSlots = `
  fprintd:
    allow-installation:
      slot-snap-type:
        - app
    deny-connection:
      on-classic: false
    deny-auto-connection: true
`

// The daemon (slot-side) recipe: peer-less D-Bus receive rules so
// confined clients (the session snap's shell and control-center) and
// unconfined callers (PAM modules, admin tools) can both call the API,
// the /var/lib/fprint print storage, and the reader device nodes and
// enumeration paths libfprint reads through libudev/libusb/libgudev.
const fprintdPermanentSlotAppArmor = `
# Description: Allow operating as the fprintd fingerprint daemon. This
# gives privileged access to fingerprint reader devices and to the
# enrolled fingerprint data store.

#include <abstractions/dbus-strict>

# Allow binding and owning the service's connection name
dbus (bind)
    bus=system
    name="net.reactivated.Fprint",
dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="{Request,Release}Name"
    peer=(name=org.freedesktop.DBus, label=unconfined),

# The daemon identifies callers (uid/pid) to authorize privileged
# operations via polkit
dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="GetConnectionUnix{ProcessID,User}"
    peer=(label=unconfined),

# The daemon watches the polkit authority so cached authorization
# decisions are dropped when it changes
dbus (receive)
    bus=system
    path=/org/freedesktop/PolicyKit1/Authority
    interface=org.freedesktop.PolicyKit1.Authority
    member=Changed
    peer=(label=unconfined),

# Receive API calls from any peer. The clients are confined snap apps
# (the session shell, control-center), the host PAM module (inside the
# gdm profile) and unconfined admin tools, so these rules must not
# constrain the peer label.
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=net.reactivated.Fprint{.Manager,.Device},
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Properties,
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.ObjectManager,
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Peer
    member=Ping,

# Replies and emitted signals (VerifyStatus, EnrollStatus,
# VerifyFingerSelected, PropertiesChanged) go to peers of any label,
# including confined snap clients
dbus (send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*},
dbus (send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus*,

# The daemon installs a sleep-delay inhibitor on logind so an
# enrollment is not interrupted by suspend
# (do not use peer=(label=unconfined) here since this is DBus activated)
dbus (send)
    bus=system
    path=/org/freedesktop/login1
    interface=org.freedesktop.login1.Manager
    member=Inhibit,

# The daemon's own state: the enrolled fingerprint data store. On this
# image the snap binds $SNAP_COMMON here with a layout, since
# snap-confine builds snap mount namespaces from the base rootfs (which
# has no /var/lib/fprint) plus a fixed whitelist of host mounts.
/var/lib/fprint/ r,
/var/lib/fprint/** rwkl,

# Fingerprint reader device nodes. libfprint talks to readers through
# usbfs (libusb/libgusb), HID raw devices, SPI devices and the ChromeOS
# EC fingerprint device (the same set the fprintd systemd unit's
# DeviceAllow entries cover).
/dev/bus/usb/ r,
/dev/bus/usb/** rw,
/dev/hidraw* rw,
/dev/spidev* rw,
/dev/cros_fp rw,

# Reader enumeration through udev and sysfs (libudev, libgusb)
/run/udev/ r,
/run/udev/data/ r,
/run/udev/data/** r,
/run/udev/control rw,
/sys/bus/ r,
/sys/bus/** r,
/sys/class/ r,
/sys/class/** r,
/sys/devices/ r,
/sys/devices/** r,

# libudev monitors udev events for reader hotplug
network netlink raw,
`

const fprintdConnectedSlotAppArmor = `
# Allow connected clients to interact with the fprintd service.

dbus (receive, send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=net.reactivated.Fprint{.Manager,.Device}
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive, send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive, send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.ObjectManager
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow clients to introspect the service
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label=###PLUG_SECURITY_TAGS###),
`

const fprintdConnectedPlugAppArmor = `
# Description: Allow using the fprintd fingerprint service. This gives
# access to fingerprint reader claiming, enrollment and verification
# (subject to polkit authorization on the service side).

#include <abstractions/dbus-strict>

dbus (send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive, send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###SLOT_SECURITY_TAGS###),
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Properties
    member="Get{,All}",
dbus (send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.ObjectManager
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow access to the fprintd Manager and Device APIs
dbus (send)
    bus=system
    path=/net/reactivated/Fprint/Manager
    interface=net.reactivated.Fprint.Manager
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (send)
    bus=system
    path=/net/reactivated/Fprint/Device/*
    interface=net.reactivated.Fprint.Device
    peer=(label=###SLOT_SECURITY_TAGS###),

# Receive status signals emitted by the daemon (VerifyStatus,
# EnrollStatus, VerifyFingerSelected)
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint/Device/*
    interface=net.reactivated.Fprint.Device
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow clients to introspect the service
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/net/reactivated/Fprint{,/Manager,/Device/*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
`

// libudev opens a netlink kobject-uevent socket to monitor reader
// hotplug events. The default seccomp template allows no socket() at
// all beyond its explicit list and does not include bind(), so both the
// socket() and bind() calls the udev monitor makes need explicit
// entries (the udisks2 slot snippet is the precedent).
const fprintdPermanentSlotSecComp = `
# libudev
bind
socket AF_NETLINK - NETLINK_KOBJECT_UEVENT
`

type fprintdInterface struct {
	commonInterface
}

func (iface *fprintdInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(fprintdPermanentSlotSecComp)
	return nil
}

func (iface *fprintdInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	if !implicitSystemPermanentSlot(slot) {
		spec.AddSnippet(fprintdPermanentSlotAppArmor)
	}
	return nil
}

func (iface *fprintdInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	if !implicitSystemConnectedSlot(slot) {
		old := "###PLUG_SECURITY_TAGS###"
		new := plug.LabelExpression()
		snippet := strings.Replace(fprintdConnectedSlotAppArmor, old, new, -1)
		spec.AddSnippet(snippet)
	}
	return nil
}

func (iface *fprintdInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	old := "###SLOT_SECURITY_TAGS###"
	var new string
	if implicitSystemConnectedSlot(slot) {
		new = "unconfined"
	} else {
		new = slot.LabelExpression()
	}
	snippet := strings.Replace(fprintdConnectedPlugAppArmor, old, new, -1)
	spec.AddSnippet(snippet)
	return nil
}

func (iface *fprintdInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// allow what declarations allowed
	return true
}

func init() {
	registerIface(&fprintdInterface{commonInterface: commonInterface{
		name:                 "fprintd",
		summary:              fprintdSummary,
		baseDeclarationSlots: fprintdBaseDeclarationSlots,
	}})
}
