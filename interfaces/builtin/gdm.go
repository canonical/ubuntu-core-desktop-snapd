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

const gdmSummary = `allows opening a session with the GDM display manager`

const gdmBaseDeclarationSlots = `
  gdm:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

// The first-boot wizard backend (provd) opens the user's desktop session
// through GDM at the end of the initial-setup run. It calls
// Manager.OpenSession on the system bus, which returns the address of a
// private per-session bus served by gdm itself (sockets under
// /run/gdm3/dbus, mode 0666, access filtered by GDM against the
// session's allowed user); the wizard then talks UserVerifier/Greeter on
// that private bus. The private bus is a plain GDBusServer inside the
// gdm process, so D-Bus mediation there is only the socket access
// itself - there is no bus daemon policing message flows on it. This is
// the same socket the desktop interface already grants for the
// reauthentication channel.
const gdmConnectedPlugAppArmor = `
#include <abstractions/dbus-strict>

# Open the session: returns the private per-session bus address
dbus (send)
    bus=system
    path=/org/gnome/DisplayManager/Manager
    interface=org.gnome.DisplayManager.Manager
    member=OpenSession
    peer=(label=gdm),

# Property and introspection traffic on the Manager object
dbus (send)
    bus=system
    path=/org/gnome/DisplayManager/Manager
    interface=org.freedesktop.DBus.Properties
    member={Get,GetAll}
    peer=(label=gdm),
dbus (send)
    bus=system
    path=/org/gnome/DisplayManager/Manager
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label=gdm),

# GDM's private per-session bus (address returned by OpenSession)
/run/gdm3/dbus/dbus-* rw,
`

func init() {
	registerIface(&commonInterface{
		name:                  "gdm",
		summary:               gdmSummary,
		implicitOnCore:        true,
		baseDeclarationSlots:  gdmBaseDeclarationSlots,
		connectedPlugAppArmor: gdmConnectedPlugAppArmor,
	})
}
