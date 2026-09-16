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

const systemdUserControlSummary = `allows to control the user session service manager`

const systemdUserControlBaseDeclarationPlugs = `
  systemd-user-control:
    allow-installation: true
    deny-auto-connection: true
`

const systemdUserControlBaseDeclarationSlots = `
  systemd-user-control:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const systemdUserControlConnectedPlugAppArmor = `
# Description: Can control the user session service manager

#include <abstractions/dbus-session-strict>
#include <abstractions/dbus-strict>

# When AppArmorProfile= is used to confine the individual systemd --user
# units that make up this same desktop session (e.g.
# gnome-session-manager, org.gnome.Shell, the various
# org.gnome.SettingsDaemon.* components, and other apps belonging to this
# same snap such as xdg-desktop-portal-gnome), each ends up in its own
# process, but all sharing this same profile (or, for other apps in this
# snap, a per-app profile of the same snap instance). Without this rule,
# ordinary intra-session D-Bus traffic between these now-separately
# labelled processes (e.g. gnome-shell <-> gnome-session-manager,
# gnome-shell <-> org.gnome.SettingsDaemon.*, or gnome-shell <->
# xdg-desktop-portal-gnome) is denied by the dbus-session-strict
# abstraction above, even though they are all part of the same confined
# desktop session.
dbus (receive, send)
    peer=(label="snap.@{SNAP_INSTANCE_NAME}.**"),

# Supporting session boot fully driven by user session systemd
# and D-Bus activation

# Please note that UpdateActivationEnvironment can alter D-Bus activated services behavior
# (e.g. by setting LD_PRELOAD)
# It is thus intended to be restricted only to snaps acting as a desktop session on Ubuntu Core systems
#
# For such snaps, it allows the session to pass important variables to other processes in the session
# (e.g. DISPLAY, WAYLAND_DISPLAY)
dbus (send)
    bus=session
    path={/,/org/freedesktop/DBus}
    interface=org.freedesktop.DBus
    member=UpdateActivationEnvironment
    peer=(label=unconfined),

dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.DBus.Properties
    member={Set,Get,GetAll}
    peer=(label=unconfined),

# Allow reading properties (e.g. ActiveState) of individual units returned
# by GetUnit/GetUnitByPID/LoadUnit, needed by session-manager code (e.g.
# gnome-session-init-worker) that polls unit state before/while starting
# the graphical session
dbus (send)
    bus=session
    path=/org/freedesktop/systemd1/unit/**
    interface=org.freedesktop.DBus.Properties
    member={Get,GetAll}
    peer=(label=unconfined),

# systemd --user (unconfined) broadcasts PropertiesChanged for every unit
# it manages as they start/stop; session-manager/gnome-shell code that
# subscribes to systemd unit state (e.g. to know when a
# D-Bus/socket-activated unit becomes active) receives these regardless
# of whether it asked about that specific unit
dbus (receive)
    bus=session
    path=/org/freedesktop/systemd1/unit/**
    interface=org.freedesktop.DBus.Properties
    member=PropertiesChanged
    peer=(label=unconfined),

# Please note that SetEnvironment can alter existing units behavior (e.g. by setting LD_PRELOAD)
# It is thus intended to be restricted only to snaps acting as a desktop session on Ubuntu Core systems
#
# For such snaps, it allows the session to pass important variables to other processes in the session
# (e.g. DISPLAY, WAYLAND_DISPLAY)
dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member={SetEnvironment,UnsetEnvironment,UnsetAndSetEnvironment}
    peer=(label=unconfined),

# Allow to introspect the units available in the session
dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member={Reload,ListUnitFiles,ListUnitFilesByPatterns}
    peer=(label=unconfined),

# Allow to manage the units available in the session
# (e.g. to start the target describing the full session, phase parts of the startup)
dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member={ResetFailed,Reload,StartUnit,StopUnit,RestartUnit,Subscribe}
    peer=(label=unconfined),

# Allow common name-resolution calls on the session/system bus daemon
# itself, used pervasively by GLib/GDBus (e.g. GDBusProxy) when talking
# to any well-known D-Bus name
dbus (send)
    bus={session,system}
    path=/
    interface=org.freedesktop.DBus
    member=GetNameOwner
    peer=(label=unconfined),

# Allow looking up a unit's object path by name (e.g. to then read its
# ActiveState property via the Properties.Get rule above), needed by
# session-manager code (e.g. gnome-session-init-worker) to check whether
# graphical-session.target is already active before (re-)starting it
dbus (send)
    bus=session
    path=/org/freedesktop/systemd1
    interface=org.freedesktop.systemd1.Manager
    member=GetUnit
    peer=(label=unconfined),

# The following rules cover additional access needed by the session
# manager (gnome-session-service et al) and gnome-shell/SettingsDaemon
# units when they run confined (AppArmorProfile= drop-in) as direct
# children of the unconfined systemd --user, rather than being forked
# directly by this snap's own confined process tree. They were derived
# from a complain-mode run of the coordinated startup with those units
# labelled with this profile.

# Allow querying snapd for information during session startup (e.g.
# snap/session related status lookups performed early in
# gnome-session-service startup)
/run/snapd.socket rw,

# systemd --user (unconfined) hands off sockets/fds (e.g. for D-Bus or
# socket-activated units) to units it starts under this profile
unix (receive, send) type=stream peer=(label=unconfined),

# ibus dconf profile, read while setting up input method support
/etc/dconf/profile/ibus r,

# The user's login shell startup files, read by the session startup
# scripts (e.g. run-session.sh / gnome-session-service) when sourcing
# the user's environment
owner @{HOME}/.bashrc r,
owner @{HOME}/.profile r,

# Basic kernel/user-namespace identity information queried during
# session/service startup
@{PROC}/sys/kernel/overflowgid r,
@{PROC}/sys/kernel/overflowuid r,
@{PROC}/sys/user/max_user_namespaces r,

# CPU accounting limits for the user's systemd --user scope hierarchy,
# read by session-manager code that inspects its own resource
# constraints during startup
/sys/fs/cgroup/user.slice/cpu.max r,
/sys/fs/cgroup/user.slice/user-[0-9]*.slice/cpu.max r,
/sys/fs/cgroup/user.slice/user-[0-9]*.slice/user@[0-9]*.service/cpu.max r,
/sys/fs/cgroup/user.slice/user-[0-9]*.slice/user@[0-9]*.service/session.slice/cpu.max r,

# Allow the session manager (gnome-session-service) to notify systemd
# --user of its startup state via sd_notify, same as the system-level
# daemon-notify interface does for /run/systemd/notify
"/run/user/[0-9]*/systemd/notify" w,

# gnome-session-service's own dconf cache/state and session-save state,
# read/created on every session start; without these dconf silently
# stops working ("dconf will not work properly") and session state
# (like previously-running-app restore) can't be read back
owner /run/user/[0-9]*/dconf/user rw,
owner @{HOME}/.config/dconf/user r,
owner @{HOME}/.local/state/gnome-session@*.state rw,

# mutter (run as part of org.gnome.Shell@ubuntu.service under this
# profile) creates a per-session Xwayland Xauthority file via mknod();
# without write/create access here Xwayland fails to start at all and
# gnome-shell exits (fatal, not just degraded), taking the whole
# gnome-session@ubuntu.target down with it
owner /run/user/[0-9]*/.mutter-Xwaylandauth.* rw,

# mutter/mesa shader cache, created on first GL context creation
owner @{HOME}/.cache/mesa_shader_cache/{,**} rw,

# systemd --user runs "gnome-session-ctl --signal-init" (unconfined, as
# part of the gnome-session-manager@.service startup sequence) to tell
# the session manager it has finished the "Initialization" bring-up
# phase. Without this, gnome-session-service never transitions to its
# "Running" phase: it stays showing "Waiting for session to start" and
# every session-lifecycle call (Logout, Reboot, Shutdown, ...) fails
# with "org.gnome.SessionManager.NotInRunning: ... only available after
# the Running phase starts" -- i.e. the Logout/Restart UI buttons never
# work at all.
dbus (receive)
    bus=session
    path=/org/gnome/SessionManager
    interface=org.gnome.SessionManager
    member={Initialized,InitializationError}
    peer=(label=unconfined),

# Once actually in the Running phase, the session-lifecycle methods the
# Shell's own Logout/Restart/Power-off UI invokes on the session manager
# must also be receivable from gnome-shell's own D-Bus connection. This
# is normally covered by the same-label exemption for two processes that
# share the exact same "snap.@{SNAP_INSTANCE_NAME}.**" AppArmor label,
# but is listed explicitly here too since some of these are also called
# by other unconfined session-startup helpers (e.g. querying
# CanShutdown/CanReboot availability at various points).
dbus (receive)
    bus=session
    path=/org/gnome/SessionManager
    interface=org.gnome.SessionManager
    member={Logout,Shutdown,Reboot,Suspend,CanShutdown,CanReboot,CanSuspend,IsSessionRunning,RequestShutdown,RequestReboot}
    peer=(label=unconfined),
`

func init() {
	registerIface(&commonInterface{
		name:                  "systemd-user-control",
		summary:               systemdUserControlSummary,
		implicitOnCore:        true,
		implicitOnClassic:     false, // This is meant for use by session snaps on core, no use for apps in classic mode
		baseDeclarationPlugs:  systemdUserControlBaseDeclarationPlugs,
		baseDeclarationSlots:  systemdUserControlBaseDeclarationSlots,
		connectedPlugAppArmor: systemdUserControlConnectedPlugAppArmor,
	})
}
