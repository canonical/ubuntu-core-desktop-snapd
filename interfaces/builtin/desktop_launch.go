// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"github.com/snapcore/snapd/snap"
)

// The desktop-legacy and unity7 interfaces denies access to the contents of the .desktop files
// located at /var/lib/snapd/desktop/applications; only the list of files is readable.
// The desktop-launch interface, instead, gives access to those files contents. But since, in
// AppArmor, a deny access is "stronger", if the desktop-legacy or the unity7 interfaces are
// connected, the access to those contents will be forbidden, no matter what the desktop-launch
// interface adds to the AppArmor configuration.
//
// To fix this, a prioritized block is defined with `prioritizedSnippetDesktopFileAccess`, where
// the AppArmor code inserted by desktop-legacy and unity7 to forbid access to those files is
// given a lower priority than the code inserted by desktop-launch to allow it. This way, if
// only the desktop-legacy or the unity7 interfaces are connected, everything will work as
// before (no access to the contents of the .desktop files), but if the desktop-launch interface
// is connected too (which, let's remind, it's a very privileged interface), then access to those
// .desktop files is granted, because the code from desktop-legacy and unity7 is removed.

const desktopLegacyAndUnity7Priority = 0
const desktopLaunchPriority = 100

var prioritizedSnippetDesktopFileAccess = apparmor.RegisterSnippetKey("desktop-file-access")

type desktopLaunchInterface struct{}

const desktopLaunchSummary = `allows snaps to identify and launch desktop applications in (or from) other snaps`

const desktopLaunchBaseDeclarationPlugs = `
  desktop-launch:
    allow-installation: false
    deny-auto-connection: true
`

const desktopLaunchBaseDeclarationSlots = `
  desktop-launch:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const desktopLaunchConnectedPlugAppArmor = `
# Description: Can identify and launch other snaps.

# Access to the desktop and icon files installed by snaps
/var/lib/snapd/desktop/applications/{,*} r,
/var/lib/snapd/desktop/icons/{,**} r,

# Allow access to all snap metadata
/snap/*/*/** r,

# Desktop files use the "snap" command, which may be symlinked
# to the snapd snap.
/usr/bin/snap ixr,
/snap/snapd/*/usr/bin/snap ixr,
/snap/snapd/*{,/usr}/lib/@{multiarch}/lib*.so* mr,

# "snap run" execs snap-confine (via syscall.Exec, replacing its own
# image) to actually enter the target snap's confinement. snap-confine
# has its own dedicated AppArmor profile, so this needs a discrete
# profile transition (not just "ix") from the caller's profile.
/usr/lib/snapd/snap-confine px,
/snap/snapd/*/usr/lib/snapd/snap-confine px,

# "snap run" computes a system-key before it execs snap-confine and
# transitions to the launched snap's own profile, so this still runs
# under the caller's (this plug's) profile. Without these, the caller
# gets EPERM computing the system key and the target snap never starts
# (e.g. "cannot determine seccomp compiler version in generateSystemKey").
/proc/sys/kernel/seccomp/actions_avail r,
/snap/snapd/*/usr/lib/snapd/snap-seccomp ixr,

# "snap run" also reads the target snap's sequence file (dir options,
# e.g. whether it's classic/using hidden snap dirs) before exec'ing
# snap-confine, again still under the caller's profile.
/var/lib/snapd/sequence/*.json r,

# "snap run" also creates (if missing) and enters the launched snap's
# own private XDG_RUNTIME_DIR subdirectory before exec'ing
# snap-confine, still under the caller's profile.
/run/user/[0-9]*/ w,
/run/user/[0-9]*/snap.*/ rw,

# "snap run" launches the target snap in its own transient scope via
# the user systemd manager (over the session bus), still under the
# caller's profile.
dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member=StartTransientUnit
    peer=(label=unconfined),

# Allow observing the JobRemoved signal which informs the caller of
# StartTransientUnit that the job has been dispatched and that the
# transient scope has finished starting.
dbus (receive)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member=JobRemoved
    peer=(label=unconfined),

# GTK4/libadwaita apps (e.g. gnome-terminal-server rendering any icon,
# such as its own window/tab icons) sandbox image decoding via glycin,
# which itself spawns a "bwrap" helper to run the actual decoder
# ("glycin-image-rs") isolated in its own user/mount namespace. Setting
# up that namespace requires reading the kernel's overflow uid/gid, and
# without it bwrap's child aborts immediately (exit status 1), which in
# turn makes glycin/gdk-pixbuf treat this as a fatal
# "ensure_surface_for_gicon" GTK assertion failure and abort the whole
# app (e.g. gnome-terminal-server core-dumps on its very first icon
# load after every (re)start).
@{PROC}/sys/kernel/overflowuid r,
@{PROC}/sys/kernel/overflowgid r,

#include <abstractions/dbus-session-strict>

dbus (send)
    bus=session
    path=/io/snapcraft/PrivilegedDesktopLauncher
    interface=io.snapcraft.PrivilegedDesktopLauncher
    member={OpenDesktopEntry,OpenDesktopEntry2}
    peer=(label=unconfined),

# Allow D-Bus traffic with other apps of this same snap (e.g. a
# desktop-session app confined per-unit via systemd's AppArmorProfile=,
# such as gnome-shell talking to this xdg-desktop-portal-gnome-style
# D-Bus-activated, daemon-scope=user app)
dbus (receive, send)
    peer=(label="snap.@{SNAP_INSTANCE_NAME}.**"),

# D-Bus-activated, daemon-scope=user apps (e.g. an xdg-desktop-portal
# implementation) started as a direct child of the unconfined
# systemd --user receive their activation socket/fd from it
unix (receive, send) type=stream peer=(label=unconfined),
`

func (iface *desktopLaunchInterface) Name() string {
	return "desktop-launch"
}

func (iface *desktopLaunchInterface) StaticInfo() interfaces.StaticInfo {
	return interfaces.StaticInfo{
		Summary:              desktopLaunchSummary,
		ImplicitOnClassic:    true,
		ImplicitOnCore:       true,
		BaseDeclarationPlugs: desktopLaunchBaseDeclarationPlugs,
		BaseDeclarationSlots: desktopLaunchBaseDeclarationSlots,
	}
}

func (iface *desktopLaunchInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(desktopLaunchConnectedPlugAppArmor)
	// the DesktopFileRules added by other, less privileged, interfaces (like unity7
	// or desktop-legacy) can conflict with the rules in this, more privileged,
	// interface, so they are added there with the minimum priority, while in this
	// one an empty string is added with a bigger privilege value, thus removing
	// those rules when desktop-launch plug is connected.
	spec.AddPrioritizedSnippet("", prioritizedSnippetDesktopFileAccess, desktopLaunchPriority)
	return nil
}

func (iface *desktopLaunchInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// allow what declarations allowed
	return true
}

// Only implicitOnClassic since userd isn't yet usable on core
func init() {
	registerIface(&desktopLaunchInterface{})
}
