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

const systemdUserEnvironmentSummary = `allows a trusted session broker to update the user session environment`

const systemdUserEnvironmentBaseDeclarationPlugs = `
  systemd-user-environment:
    allow-installation: true
    deny-auto-connection: true
`

const systemdUserEnvironmentBaseDeclarationSlots = `
  systemd-user-environment:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const systemdUserEnvironmentConnectedPlugAppArmor = `
# Environment mutation is deliberately isolated from systemd-user-control:
# these methods affect every D-Bus-activated and systemd user service.
# Only the session-environment broker should connect this interface.
dbus (send)
    bus=session
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member={GetConnectionCredentials,UpdateActivationEnvironment}
    peer=(label=unconfined),

dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member=UnsetAndSetEnvironment
    peer=(label=unconfined),
`

func init() {
	registerIface(&commonInterface{
		name:                  "systemd-user-environment",
		summary:               systemdUserEnvironmentSummary,
		implicitOnCore:        true,
		implicitOnClassic:     false,
		baseDeclarationPlugs:  systemdUserEnvironmentBaseDeclarationPlugs,
		baseDeclarationSlots:  systemdUserEnvironmentBaseDeclarationSlots,
		connectedPlugAppArmor: systemdUserEnvironmentConnectedPlugAppArmor,
	})
}
