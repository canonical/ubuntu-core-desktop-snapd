// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

const accountDaemonSummary = `allows to snap the accounts daemon`

const accountDaemonBaseDeclarationSlots = `
  account-daemon:
    allow-installation:
      slot-snap-type:
        - app
    deny-auto-connection: true
`

const accountDaemonConnectedPlugAppArmor = `
#include <abstractions/dbus-strict>
# Introspection of org.freedesktop.Accounts
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts
    interface=org.freedesktop.Accounts
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts/User[0-9]*
    interface=org.freedesktop.Accounts.User
    peer=(label=###SLOT_SECURITY_TAGS###),
# Read all properties from Accounts
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    member=Get{,All}
    peer=(label=###SLOT_SECURITY_TAGS###),
# Receive Accounts property changed events
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=###SLOT_SECURITY_TAGS###),
# Receive Users changed events
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.Accounts.User
    member=Changed
    peer=(label=###SLOT_SECURITY_TAGS###),
# Receive new user signal
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts
    interface=org.freedesktop.Accounts
    member=User{Added,Deleted}
    peer=(label=###SLOT_SECURITY_TAGS###),

/var/cache/cracklib/{,**} r,
/usr/sbin/usermod ixr,
/etc/login.defs r,
`

const accountDaemonPermanentSlotAppArmor = `
#include <abstractions/dbus-strict>
# Introspection of org.freedesktop.Accounts
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts
    interface=org.freedesktop.Accounts,
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts
    interface=org.freedesktop.Accounts,
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts/User[0-9]*
    interface=org.freedesktop.Accounts.User,
# Read all properties from Accounts
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    member=Get{,All},
# Send Accounts property changed events
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties,
# Send Users changed events
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts/User[0-9]*
    interface=org.freedesktop.Accounts.User,

dbus (send)
    bus=system
    path=/org/freedesktop/PolicyKit1/Authority
    interface=org.freedesktop.PolicyKit1.Authority
    member={,Cancel}CheckAuthorization
    peer=(label=unconfined),

dbus (receive)
    bus=system
    path=/org/freedesktop/PolicyKit1/Authority
    interface=org.freedesktop.PolicyKit1.Authority
    member=Changed
    peer=(label=unconfined),

# Allow binding the service to the requested connection name
dbus (bind)
    bus=system
    name="org.freedesktop.Accounts",

/home/{,**} rw,

/{,usr/}sbin/chpasswd ixr,
/{,usr/}bin/passwd ixr,
/{,usr/}bin/chage ixr,
/{,usr/}sbin/user{add,del,mod} ixr,
/usr/bin/lsattr ixr,

# Allow modifying the non-system extrausers NSS database. The extrausers
# database is used on Ubuntu Core devices to manage both privileged and
# unprivileged users (since /etc/passwd, /etc/group, etc are all read-only).
/var/lib/extrausers/ r,
/var/lib/extrausers/** rwkl,

# extra access required
/etc/writable/AccountsService/{,**} rw,
/etc/passwd r,
/etc/shadow r,
/etc/shells r,
/etc/gdm/{,**} rw,
/etc/writable/gdm/{,**} rw,
/etc/lightdm/{,**} rw,
/etc/writable/lightdm/{,**} rw,
/etc/locale.conf rw,
/etc/writable/locale.conf rw,
/etc/skel/{,**} r,
/run/user/** rwkl,
/run/user/ rw,
/var/cache/cracklib/{,**} r,

# Needed by useradd
/etc/login.defs r,
/etc/default/useradd r,
/etc/default/nss r,
/etc/pam.d/{,*} r,
/{,usr/}sbin/pam_tally2 ixr,

# Needed by chpasswd
/{,usr/}lib/@{multiarch}/security/* ixr,

# Useradd needs netlink
network netlink raw,

# Capabilities needed by useradd
capability audit_write,
capability chown,
capability fsetid,
capability fowner,

# useradd writes the result in the log
# faillog tracks failed events, lastlog maintain records of the last
# time a user successfully logged in, tallylog maintains records of
# failures.
#include <abstractions/wutmp>
/var/log/faillog rwk,
/var/log/lastlog rwk,
/var/log/tallylog rwk,
`

// Needed because useradd uses a netlink socket, {{group}} is used as a
// placeholder argument for the actual ID of a group owning /etc/shadow
const accountDaemonSlotSecComp = `
chown
chown32
chownat
fchown
fchown32
fchownat

# from libaudit1
bind
socket AF_NETLINK - NETLINK_AUDIT
`

type accountDaemonInterface struct {
	commonInterface
	secCompSnippet string
}

func (iface *accountDaemonInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(accountDaemonSlotSecComp)
	return nil
}

func (iface *accountDaemonInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(accountDaemonPermanentSlotAppArmor)
	return nil
}

func (iface *accountDaemonInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {

	old := "###SLOT_SECURITY_TAGS###"
	new := slot.LabelExpression()
	snippet := strings.Replace(accountDaemonConnectedPlugAppArmor, old, new, -1)
	spec.AddSnippet(snippet)

	return nil
}

func init() {
	registerIface(&accountDaemonInterface{commonInterface: commonInterface{
		name:                 "account-daemon",
		summary:              accountDaemonSummary,
		implicitOnCore:       false,
		baseDeclarationSlots: accountDaemonBaseDeclarationSlots,
	}})
}
