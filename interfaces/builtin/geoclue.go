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

// The geoclue interface supports running geoclue (org.freedesktop.GeoClue2)
// as a strictly-confined provider snap: the slot side is the daemon
// recipe (D-Bus receive rules for the location API, sends into the
// session agents it authorizes location requests through, and the
// data-source access: wpa_supplicant for WiFi APs, ModemManager for
// modem GPS, Avahi for network NMEA, and the plain network sockets the
// NMEA listener and GeoIP lookups use), the plug side is the client
// recipe for geoclue consumers (the session shell, which is also the
// location agent, the settings-daemon timezone lookup, and libgeoclue
// apps in the content snap).
//
// The daemon runs as root under snap confinement (snapd's dbus
// activation entries hardcode User=root; the fat base ran it as the
// geoclue user, uid 203, which the desktop variant still bakes). All
// data-source access is mediated by this policy either way. geoclue
// has no polkit actions of its own, so the snap carries no polkit
// plug (ModemManager's own polkit actions would be the MM side's
// business).
const geoclueSummary = `allows operating as or interacting with the geoclue location service`

const geoclueBaseDeclarationSlots = `
  geoclue:
    allow-installation:
      slot-snap-type:
        - app
    deny-connection:
      on-classic: false
    deny-auto-connection: true
`

// The daemon (slot-side) recipe: peer-less D-Bus receive rules for the
// location API, peer-less sends into the session agents (confined snap
// apps) and the data sources, the shipped config, and the network
// access the sources use.
const geocluePermanentSlotAppArmor = `
# Description: Allow operating as the geoclue location daemon. This
# gives access to the location data sources (WiFi AP enumeration via
# wpa_supplicant, modem GPS via ModemManager, network NMEA via Avahi
# and a UDP listener, GeoIP lookups over HTTP) and to the agent API of
# the session's location agents.

#include <abstractions/dbus-strict>

# Allow binding and owning the service's connection name
dbus (bind)
    bus=system
    name="org.freedesktop.GeoClue2",
dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="{Request,Release}Name"
    peer=(name=org.freedesktop.DBus, label=unconfined),

# The daemon identifies callers (uid/pid and desktop id) to authorize
# location requests
dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="GetConnectionUnix{ProcessID,User}"
    peer=(label=unconfined),

# Receive API calls from any peer. The clients are confined snap apps
# (the session shell, the settings daemon) and libgeoclue apps, so
# these rules must not constrain the peer label.
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.GeoClue2.{Manager,Client,Location},
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Properties,
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Peer
    member=Ping,

# Replies and emitted signals (LocationUpdated, NotifyActiveChange,
# PropertiesChanged) go to peers of any label, including confined snap
# clients
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**},
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus*,

# Calls into the session's location agents (Authorize and the agent
# client API). The agents are confined snap apps (the shell exports
# /org/freedesktop/GeoClue2/Agent), so these rules must not constrain
# the peer label; the agents' own profiles carry the matching receive
# rules via the connected plug.
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2/Agent
    interface=org.freedesktop.GeoClue2.Agent,
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2/Agent
    interface=org.freedesktop.DBus.Properties,

# WiFi data source: enumerate APs and trigger scans through
# wpa_supplicant (the same sends the fat base's dbus policy granted
# the geoclue user). wpa_supplicant may live in another snap
# (network-manager), so these rules must not constrain the peer label.
dbus (send)
    bus=system
    path=/fi/w1/wpa_supplicant1{,/**}
    interface=org.freedesktop.DBus.Properties
    member="{Get,GetAll}",
dbus (send)
    bus=system
    path=/fi/w1/wpa_supplicant1{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
dbus (send)
    bus=system
    path=/fi/w1/wpa_supplicant1{,/**}
    interface=fi.w1.wpa_supplicant1.{Interface,BSS}
    member=Scan,

# Modem data sources (3g/cdma/modem-gps): enumerate modems and read
# their location through ModemManager (polkit on the ModemManager side
# governs the privileged bits). ModemManager may live in another snap,
# so these rules must not constrain the peer label.
dbus (send)
    bus=system
    path=/org/freedesktop/ModemManager1{,/**}
    interface=org.freedesktop.ModemManager1.*,
dbus (send)
    bus=system
    path=/org/freedesktop/ModemManager1{,/**}
    interface=org.freedesktop.DBus.Properties
    member="{Get,GetAll}",
# modem location updates arrive as signals
dbus (receive)
    bus=system
    path=/org/freedesktop/ModemManager1/Modem/*
    interface=org.freedesktop.ModemManager1.Modem.Location,
dbus (receive)
    bus=system
    path=/org/freedesktop/ModemManager1/Modem/*
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged,

# Network NMEA data source: service discovery through Avahi. The
# browser objects live on Avahi's unique connection, so these rules
# must not constrain the peer label either.
dbus (send)
    bus=system
    path=/**
    interface=org.freedesktop.Avahi.*,
dbus (receive)
    bus=system
    interface=org.freedesktop.Avahi.*,

# The daemon's config. The snap binds its own staged /etc/geoclue
# (geoclue.conf + conf.d/ drop-ins) over this path with a layout, since
# snap-confine builds snap mount namespaces from the base rootfs (which
# has no /etc/geoclue) plus a fixed whitelist of host mounts. The
# optional static-source file /etc/geolocation is granted but need not
# exist (absent on this image, as on the fat base).
/etc/geoclue/ r,
/etc/geoclue/** r,
/etc/geolocation r,

# Network access for the location sources: the NMEA UDP listener
# (bind + multicast membership), GeoIP lookups over HTTP(S) (libsoup)
# and DNS.
network inet stream,
network inet6 stream,
network inet dgram,
network inet6 dgram,
`

const geoclueConnectedSlotAppArmor = `
# Allow connected clients to interact with the geoclue service.

dbus (receive, send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.GeoClue2.{Manager,Client,Location}
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive, send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow clients to introspect the service
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label=###PLUG_SECURITY_TAGS###),
`

const geoclueConnectedPlugAppArmor = `
# Description: Allow using the geoclue location service and acting as
# its session agent. This gives access to location data (subject to
# the agent authorization on the service side) and lets the connected
# app receive the daemon's agent calls.

#include <abstractions/dbus-strict>

dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive, send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###SLOT_SECURITY_TAGS###),
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Properties
    member="Get{,All}",

# Allow access to the geoclue Manager, Client and Location APIs
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.GeoClue2.{Manager,Client,Location}
    peer=(label=###SLOT_SECURITY_TAGS###),

# Receive signals emitted by the daemon (LocationUpdated on the
# client's own object, NotifyActiveChange, PropertiesChanged)
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.GeoClue2.{Manager,Client,Location}
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=###SLOT_SECURITY_TAGS###),

# Acting as the location agent: the daemon calls Authorize (and the
# agent's properties) on /org/freedesktop/GeoClue2/Agent; the daemon's
# slot side carries the peer-less send for this.
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2/Agent
    interface=org.freedesktop.GeoClue2.Agent
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive)
    bus=system
    path=/org/freedesktop/GeoClue2/Agent
    interface=org.freedesktop.DBus.Properties
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow clients to introspect the service
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/org/freedesktop/GeoClue2{,/**}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
`

// The network-NMEA source binds a UDP listener. The default seccomp
// template allows socket() for AF_INET/AF_INET6 but not bind(), so the
// bind() call needs an explicit entry (the fprintd udev-monitor
// precedent).
const geocluePermanentSlotSecComp = `
# network NMEA UDP listener
bind
`

type geoclueInterface struct {
	commonInterface
}

func (iface *geoclueInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(geocluePermanentSlotSecComp)
	return nil
}

func (iface *geoclueInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	if !implicitSystemPermanentSlot(slot) {
		spec.AddSnippet(geocluePermanentSlotAppArmor)
	}
	return nil
}

func (iface *geoclueInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	if !implicitSystemConnectedSlot(slot) {
		old := "###PLUG_SECURITY_TAGS###"
		new := plug.LabelExpression()
		snippet := strings.Replace(geoclueConnectedSlotAppArmor, old, new, -1)
		spec.AddSnippet(snippet)
	}
	return nil
}

func (iface *geoclueInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	old := "###SLOT_SECURITY_TAGS###"
	var new string
	if implicitSystemConnectedSlot(slot) {
		new = "unconfined"
	} else {
		new = slot.LabelExpression()
	}
	snippet := strings.Replace(geoclueConnectedPlugAppArmor, old, new, -1)
	spec.AddSnippet(snippet)
	return nil
}

func (iface *geoclueInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// allow what declarations allowed
	return true
}

func init() {
	registerIface(&geoclueInterface{commonInterface: commonInterface{
		name:                 "geoclue",
		summary:              geoclueSummary,
		baseDeclarationSlots: geoclueBaseDeclarationSlots,
	}})
}
