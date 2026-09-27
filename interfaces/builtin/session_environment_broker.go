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
)

const sessionEnvironmentBrokerSummary = `allows the GNOME session manager to request filtered environment updates`

const sessionEnvironmentBrokerBaseDeclarationPlugs = `
  session-environment-broker:
    allow-installation: true
    deny-auto-connection: true
`

const sessionEnvironmentBrokerBaseDeclarationSlots = `
  session-environment-broker:
    allow-installation:
      slot-snap-type:
        - app
    deny-auto-connection: true
`

const sessionEnvironmentBrokerConnectedPlugAppArmor = `
# The interface is intentionally bound to the first supported consumer
# and provider. It grants one operation, not general D-Bus or systemd access.
dbus (send)
    bus=session
    path=/org/ubuntu/SessionEnvironmentBroker
    interface=org.ubuntu.SessionEnvironmentBroker
    member=UpdateEnvironment
    peer=(label="snap.ubuntu-desktop-session.session-environment-broker"),

dbus (receive)
    bus=session
    path=/org/ubuntu/SessionEnvironmentBroker
    interface=org.ubuntu.SessionEnvironmentBroker
    member=UpdateEnvironment
    peer=(label="snap.ubuntu-desktop-session.session-environment-broker"),
`

const sessionEnvironmentBrokerConnectedSlotAppArmor = `
dbus (receive)
    bus=session
    path=/org/ubuntu/SessionEnvironmentBroker
    interface=org.ubuntu.SessionEnvironmentBroker
    member=UpdateEnvironment
    peer=(label="snap.ubuntu-desktop-session.gnome-session-service"),

dbus (send)
    bus=session
    path=/org/ubuntu/SessionEnvironmentBroker
    interface=org.ubuntu.SessionEnvironmentBroker
    member=UpdateEnvironment
    peer=(label="snap.ubuntu-desktop-session.gnome-session-service"),
`

type sessionEnvironmentBrokerInterface struct {
	commonInterface
}

func (iface *sessionEnvironmentBrokerInterface) AppArmorConnectedSlot(
	spec *apparmor.Specification,
	plug *interfaces.ConnectedPlug,
	slot *interfaces.ConnectedSlot,
) error {
	spec.AddSnippet(sessionEnvironmentBrokerConnectedSlotAppArmor)
	return nil
}

func init() {
	registerIface(&sessionEnvironmentBrokerInterface{commonInterface{
		name:                  "session-environment-broker",
		summary:               sessionEnvironmentBrokerSummary,
		implicitOnCore:        false,
		implicitOnClassic:     false,
		baseDeclarationPlugs:  sessionEnvironmentBrokerBaseDeclarationPlugs,
		baseDeclarationSlots:  sessionEnvironmentBrokerBaseDeclarationSlots,
		connectedPlugAppArmor: sessionEnvironmentBrokerConnectedPlugAppArmor,
	}})
}
