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

const kdeKauthSummary = `allows invoking KAuth helper actions on DBus-activated, unconfined KAuth helpers`

const kdeKauthBaseDeclarationSlots = `
  kde-kauth:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const kdeKauthConnectedPlugAppArmor = `
#include <abstractions/dbus-strict>

# Allow confined KDE applications to invoke privileged actions on KAuth
# helpers (eg org.kde.plasmasetup's CreateUser/SetHostname actions used by
# plasma-setup). KAuth's DBusHelperProxy always talks to the helper over the
# fixed "org.kde.kf6auth" interface/path regardless of the helper's own
# well-known bus name, so this is scoped by interface/member rather than by
# destination name.
#
# Do not use peer=(label=unconfined) on the outgoing calls: the helper is
# DBus-activated (see org.kde.plasmasetup.service), so it may not have a
# running peer label yet when the message is sent.
dbus (send)
    bus=system
    path=/
    interface=org.kde.kf6auth
    member={performAction,stopAction},

# Allow receiving the helper's progress/result signals once it is running.
dbus (receive)
    bus=system
    path=/
    interface=org.kde.kf6auth
    member=remoteSignal
    peer=(label=unconfined),
`

func init() {
	registerIface(&commonInterface{
		name:                  "kde-kauth",
		summary:               kdeKauthSummary,
		implicitOnCore:        true,
		baseDeclarationSlots:  kdeKauthBaseDeclarationSlots,
		connectedPlugAppArmor: kdeKauthConnectedPlugAppArmor,
	})
}
