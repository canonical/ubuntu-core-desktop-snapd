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

const gdmSessionControlSummary = `allows GNOME Shell to open a greeter session with GDM`

const gdmSessionControlBaseDeclarationSlots = `
  gdm-session-control:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const gdmSessionControlConnectedPlugAppArmor = `
#include <abstractions/dbus-strict>

# Allow GNOME Shell to open its greeter session with the confined GDM service.
dbus (send)
    bus=system
    path=/org/gnome/DisplayManager/Manager
    interface=org.gnome.DisplayManager.Manager
    member=OpenSession
    peer=(label=gdm),
`

func init() {
	registerIface(&commonInterface{
		name:                  "gdm-session-control",
		summary:               gdmSessionControlSummary,
		implicitOnCore:        true,
		baseDeclarationSlots:  gdmSessionControlBaseDeclarationSlots,
		connectedPlugAppArmor: gdmSessionControlConnectedPlugAppArmor,
	})
}
