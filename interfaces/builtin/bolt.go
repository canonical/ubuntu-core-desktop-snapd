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

// The bolt interface supports running boltd (org.freedesktop.bolt) as
// a strictly-confined provider snap: the slot side is the daemon
// recipe (D-Bus receive rules, the enrolled-device store, and the
// thunderbolt sysfs access through which the daemon enumerates,
// authorizes and manages devices), the plug side is the client recipe
// for bolt consumers (the shell's thunderbolt status agent and
// notifications, the control-center Thunderbolt panel, and boltctl).
//
// The daemon runs as root (the fat base never had a bolt user; its
// unit and D-Bus service entry both run it as root) and authorizes
// privileged operations via polkit, for which the snap carries the
// built-in polkit plug.
const boltSummary = `allows operating as or interacting with the bolt thunderbolt service`

const boltBaseDeclarationSlots = `
  bolt:
    allow-installation:
      slot-snap-type:
        - app
    deny-connection:
      on-classic: false
    deny-auto-connection: true
`

// The daemon (slot-side) recipe: peer-less D-Bus receive rules so
// confined clients (the session shell, control-center) and unconfined
// callers (admin tools) can both call the API, the /var/lib/boltd
// device store, and the sysfs paths the daemon reads (enumeration,
// DMI identification) and writes (device authorization, NVM firmware
// updates, force power).
const boltPermanentSlotAppArmor = `
# Description: Allow operating as the bolt thunderbolt daemon. This
# gives privileged access to thunderbolt device management, including
# device authorization and enrollment.

#include <abstractions/dbus-strict>

# Allow binding and owning the service's connection name
dbus (bind)
    bus=system
    name="org.freedesktop.bolt",
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
# (the session shell, control-center) and unconfined admin tools
# (boltctl outside the snap), so these rules must not constrain the
# peer label.
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.bolt1.{Manager,Domain,Device,Power},
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Properties,
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.ObjectManager,
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Peer
    member=Ping,

# Replies and emitted signals (DeviceAdded, DeviceRemoved, DomainAdded,
# DomainRemoved, PropertiesChanged) go to peers of any label, including
# confined snap clients
dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**},
dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus*,

# The daemon's own state: the enrolled-device store. On this image the
# snap binds $SNAP_COMMON here with a layout, since snap-confine
# builds snap mount namespaces from the base rootfs (which has no
# /var/lib/boltd) plus a fixed whitelist of host mounts.
/var/lib/boltd/ r,
/var/lib/boltd/** rwkl,

# The baked unit created /run/boltd via RuntimeDirectory; under snap
# confinement the daemon creates it itself (it runs as root). bolt
# keeps transient power-guard state there.
/run/boltd/ rwkl,
/run/boltd/** rwkl,

# Machine identification (bolt reads the DMI id for device records)
/sys/class/dmi/id/ r,
/sys/class/dmi/id/** r,

# Thunderbolt devices are pure sysfs: enumeration, device
# authorization (authorized attribute), NVM firmware update state and
# force power are all read/write attribute access under the thunderbolt
# bus. No device nodes are involved, so AppArmor path mediation (not a
# device cgroup) is what governs this.
#
# The entries under /sys/bus/thunderbolt/devices are symlinks into
# /sys/devices (e.g. /sys/bus/thunderbolt/devices/0-1 resolves to
# /sys/devices/pci…/…/domain0/0-1), and AppArmor mediates on the
# resolved path, so writes must be granted under /sys/devices below or
# authorizing a device is denied on real hardware.
/sys/bus/thunderbolt/ r,
/sys/bus/thunderbolt/** rwkl,

# Writes land on the resolved paths: the authorized, key, security and
# bootacl attributes of each thunderbolt domain and of the devices
# hanging off it. The ** prefix keeps PCI (hex) addressing schemes out
# of the rule.
/sys/devices/**/domain[0-9]*/** rw,

# The force-power attribute is exposed through the WMI bus, which
# resolves elsewhere under /sys/devices; bolt writes 1/0 there to
# power the controller up when nothing is connected.
/sys/devices/**/wmi_bus/**/force_power rw,

# Enumeration through sysfs and udev (libudev)
/sys/bus/ r,
/sys/bus/** r,
/sys/class/ r,
/sys/class/** r,
/sys/devices/ r,
/sys/devices/** r,
/run/udev/ r,
/run/udev/data/ r,
/run/udev/data/** r,
/run/udev/control rw,

# libudev monitors udev events for thunderbolt hotplug
network netlink raw,
`

const boltConnectedSlotAppArmor = `
# Allow connected clients to interact with the bolt service.

dbus (receive, send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.bolt1.{Manager,Domain,Device,Power}
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive, send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive, send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.ObjectManager
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow clients to introspect the service
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label=###PLUG_SECURITY_TAGS###),
`

const boltConnectedPlugAppArmor = `
# Description: Allow using the bolt thunderbolt service. This gives
# access to device enumeration and management (subject to polkit
# authorization on the service side).

#include <abstractions/dbus-strict>

dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive, send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###SLOT_SECURITY_TAGS###),
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Properties
    member="Get{,All}",
dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.ObjectManager
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow access to the bolt Manager, Domain, Device and Power APIs
dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.bolt1.{Manager,Domain,Device,Power}
    peer=(label=###SLOT_SECURITY_TAGS###),

# Receive signals emitted by the daemon (DeviceAdded, DeviceRemoved,
# DomainAdded, DomainRemoved) and the object manager interfaces
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.bolt1.{Manager,Domain,Device,Power}
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.ObjectManager
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow clients to introspect the service
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/org/freedesktop/bolt{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
`

// libudev opens a netlink kobject-uevent socket to monitor thunderbolt
// hotplug events. The default seccomp template allows no socket() at
// all beyond its explicit list and does not include bind(), so both the
// socket() and bind() calls the udev monitor makes need explicit
// entries (the udisks2 slot snippet is the precedent).
const boltPermanentSlotSecComp = `
# libudev
bind
socket AF_NETLINK - NETLINK_KOBJECT_UEVENT
`

type boltInterface struct {
	commonInterface
}

func (iface *boltInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(boltPermanentSlotSecComp)
	return nil
}

func (iface *boltInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	if !implicitSystemPermanentSlot(slot) {
		spec.AddSnippet(boltPermanentSlotAppArmor)
	}
	return nil
}

func (iface *boltInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	if !implicitSystemConnectedSlot(slot) {
		old := "###PLUG_SECURITY_TAGS###"
		new := plug.LabelExpression()
		snippet := strings.Replace(boltConnectedSlotAppArmor, old, new, -1)
		spec.AddSnippet(snippet)
	}
	return nil
}

func (iface *boltInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	old := "###SLOT_SECURITY_TAGS###"
	var new string
	if implicitSystemConnectedSlot(slot) {
		new = "unconfined"
	} else {
		new = slot.LabelExpression()
	}
	snippet := strings.Replace(boltConnectedPlugAppArmor, old, new, -1)
	spec.AddSnippet(snippet)
	return nil
}

func (iface *boltInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// allow what declarations allowed
	return true
}

func init() {
	registerIface(&boltInterface{commonInterface: commonInterface{
		name:                 "bolt",
		summary:              boltSummary,
		baseDeclarationSlots: boltBaseDeclarationSlots,
	}})
}
