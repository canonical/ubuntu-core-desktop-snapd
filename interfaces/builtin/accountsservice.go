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
	"strconv"
	"strings"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
)

// The accountsservice interface supports running AccountsService
// (org.freedesktop.Accounts) as a strictly-confined provider snap: the
// slot side is the daemon recipe (file, capability, seccomp and D-Bus
// receive rules), the plug side is the client recipe. The slot-side
// policy is the account-control plug recipe re-emitted for a slot, with
// the additions a confined daemon needs that the account-control plug
// never had (the daemon was always the unconfined core daemon until
// now): /var/lib/AccountsService rw, the adduser/perl helper chain,
// peer-less D-Bus receive rules so confined clients with profiles of
// their own (the gdm greeter) and unconfined callers (provd, admin
// tools) can both call the API, and a layout-independent write to the
// home-directory tree the helpers create accounts in.
//
// The name deliberately differs from the existing "accounts-service"
// interface (the session-bus org.freedesktop.Accounts client plug).
const accountsserviceSummary = `allows operating as or interacting with the AccountsService user-account service`

const accountsserviceBaseDeclarationSlots = `
  accountsservice:
    allow-installation:
      slot-snap-type:
        - app
    deny-connection:
      on-classic: false
    deny-auto-connection: true
`

// The daemon (slot-side) recipe. This is the account-control PLUG recipe
// (the file/capability set useradd/userdel/chpasswd need on Ubuntu Core,
// where the account databases live in /var/lib/extrausers) re-emitted as
// slot policy, plus what the confined daemon itself needs: its own state
// directory, the helper binaries it execs (including the perl adduser
// the desktop variant bakes), and peer-less D-Bus receive rules.
const accountsservicePermanentSlotAppArmor = `
# Description: Allow operating as the AccountsService daemon. This gives
# privileged access to the system's user-account databases.

#include <abstractions/dbus-strict>

# Allow binding and owning the service's connection name
dbus (bind)
    bus=system
    name="org.freedesktop.Accounts",
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

# Receive API calls from any peer. The clients are the confined gdm
# profile (neither unconfined nor a plug security tag), confined snap
# clients and unconfined callers (provd, admin tools), so these rules
# must not constrain the peer label.
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.Accounts{,.User},
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties,
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Peer
    member=Ping,

# The daemon watches the polkit authority so cached authorization
# decisions are dropped when it changes
dbus (receive)
    bus=system
    path=/org/freedesktop/PolicyKit1/Authority
    interface=org.freedesktop.PolicyKit1.Authority
    member=Changed
    peer=(label=unconfined),

# Replies and emitted signals (PropertiesChanged, Changed) go to peers
# of any label, including confined snap clients
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*},
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus*,

# The daemon's own state: cached user metadata and face icons
/var/lib/AccountsService/ r,
/var/lib/AccountsService/** rwkl,

# Allow modifying the non-system extrausers NSS database. The extrausers
# database is used on Ubuntu Core devices to manage both privileged and
# unprivileged users (since /etc/passwd, /etc/group, etc are all
# read-only). The daemon edits these files directly (its user-creation
# and shell/account-type changes are compiled-in extrausers writes), and
# the helpers below also maintain them.
/var/lib/extrausers/ r,
/var/lib/extrausers/** rwkl,

# Helper binaries the daemon execs. All are host-path binaries from the
# base: adduser (perl, configured USE_EXTRAUSERS) creates accounts,
# userdel removes them, usermod edits GECOS and account type, chpasswd
# -e sets passwords into extrausers, passwd and chage cover the
# password-mode and expiry operations.
/{,usr/}sbin/adduser ixr,
/{,usr/}sbin/user{del,mod} ixr,
/{,usr/}sbin/chpasswd ixr,
/{,usr/}bin/passwd ixr,
/{,usr/}bin/chage ixr,

# adduser is a perl script; it needs the interpreter and its module tree
/{,usr/}bin/perl ixr,
/usr/share/perl{,5}/** r,
/etc/adduser.conf r,
# adduser takes a lock file here (a plain file, not a directory)
/run/adduser rwk,
/run/adduser/{,**} rwk,

# Needed by the shadow helpers
/etc/login.defs r,
/etc/default/useradd r,
/etc/default/nss r,
/etc/pam.d/{,*} r,
/{,usr/}lib/@{multiarch}/security/* ixr,

# Needed by useradd/usermod
network netlink raw,
capability audit_write,
capability chown,
capability fowner,
capability fsetid,

# The helpers write login accounting records
# faillog tracks failed events, lastlog maintains records of the last
# time a user successfully logged in, tallylog maintains records of
# failures.
#include <abstractions/wutmp>
/var/log/faillog rwk,
/var/log/lastlog rwk,
/var/log/tallylog rwk,

# Helper execed on SetLanguage to validate the requested locale
/usr/share/language-tools/language-validate ixr,
/usr/share/language-tools/{,*} r,

# Daemon reads
/etc/default/locale r,
/etc/shadow r,
/etc/shells r,
/etc/gdm3/custom.conf r,
/etc/systemd/system/display-manager.service r,
/etc/lightdm/lightdm.conf r,
/run/systemd/seats/ r,
/run/systemd/seats/* r,

# The helpers create account home directories under /home
/home/ r,
/home/** rwkl,
`

const accountsserviceConnectedSlotAppArmor = `
# Allow connected clients to interact with the AccountsService service.

dbus (receive, send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.Accounts{,.User}
    peer=(label=###PLUG_SECURITY_TAGS###),

dbus (receive, send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###PLUG_SECURITY_TAGS###),

# Allow clients to introspect the service
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect
    peer=(label=###PLUG_SECURITY_TAGS###),
`

const accountsserviceConnectedPlugAppArmor = `
# Description: Allow using the AccountsService service. This gives
# access to user-account management (subject to polkit authorization on
# the service side).

#include <abstractions/dbus-strict>

dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Peer
    member=Ping
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive, send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    peer=(label=###SLOT_SECURITY_TAGS###),
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    member="Get{,All}",

# Allow access to the Accounts API
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

# Receive Accounts property changed events
dbus (receive)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=###SLOT_SECURITY_TAGS###),

# Allow clients to introspect the service
# do not use peer=(label=unconfined) here since this is DBus activated
dbus (send)
    bus=system
    path=/org/freedesktop/Accounts{,/User[0-9]*}
    interface=org.freedesktop.DBus.Introspectable
    member=Introspect,
`

// The shadow helpers chown newly created files (account homes to their
// new uid:gid, spool files to the group owning /etc/shadow) and use the
// kernel audit netlink socket.
const accountsserviceSlotSecCompTemplate = `
# the account helpers chown homes/files to arbitrary uid:gid pairs
chown
chown32
fchown
fchown32
fchownat
lchown
lchown32

# the shadow helpers require chowning to 0:'{{group}}'
fchown - u:root {{group}}
fchown32 - u:root {{group}}

# from libaudit1
bind
socket AF_NETLINK - NETLINK_AUDIT
`

type accountsserviceInterface struct {
	commonInterface
	secCompSnippet string
}

func makeAccountsserviceSecCompSnippet() (string, error) {
	gid, err := osutil.FindGidOwning("/etc/shadow")
	if err != nil {
		return "", err
	}

	snippet := strings.Replace(accountsserviceSlotSecCompTemplate,
		"{{group}}", strconv.FormatUint(gid, 10), -1)

	return snippet, nil
}

func (iface *accountsserviceInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	if iface.secCompSnippet == "" {
		// Cache the snippet after it's successfully computed once
		snippet, err := makeAccountsserviceSecCompSnippet()
		if err != nil {
			return err
		}
		iface.secCompSnippet = snippet
	}
	spec.AddSnippet(iface.secCompSnippet)
	return nil
}

func (iface *accountsserviceInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	if !implicitSystemPermanentSlot(slot) {
		spec.AddSnippet(accountsservicePermanentSlotAppArmor)
	}
	return nil
}

func (iface *accountsserviceInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	if !implicitSystemConnectedSlot(slot) {
		old := "###PLUG_SECURITY_TAGS###"
		new := plug.LabelExpression()
		snippet := strings.Replace(accountsserviceConnectedSlotAppArmor, old, new, -1)
		spec.AddSnippet(snippet)
	}
	return nil
}

func (iface *accountsserviceInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	old := "###SLOT_SECURITY_TAGS###"
	var new string
	if implicitSystemConnectedSlot(slot) {
		new = "unconfined"
	} else {
		new = slot.LabelExpression()
	}
	snippet := strings.Replace(accountsserviceConnectedPlugAppArmor, old, new, -1)
	spec.AddSnippet(snippet)
	return nil
}

func (iface *accountsserviceInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// allow what declarations allowed
	return true
}

func init() {
	registerIface(&accountsserviceInterface{commonInterface: commonInterface{
		name:                 "accountsservice",
		summary:              accountsserviceSummary,
		baseDeclarationSlots: accountsserviceBaseDeclarationSlots,
	}})
}
