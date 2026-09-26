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

const fuseDeviceSummary = `allows restricted access to the FUSE device without real CAP_SYS_ADMIN`

const fuseDeviceBaseDeclarationSlots = `
  fuse-device:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const fuseDeviceConnectedPlugAppArmor = `
# Description: Can open the FUSE kernel device and connect to a
# privileged mount broker to obtain a live FUSE session fd. Unlike
# fuse-support, this interface does NOT grant real CAP_SYS_ADMIN and
# does NOT allow the plugging snap to call mount(2) with a real chance
# of success; a scoped mount rule is included below only so that a
# mount(2) attempt fails with EPERM (from the kernel's capability check)
# rather than EACCES (from AppArmor's own default-deny mediation), which
# is required for libfuse's fusermount3 fallback path to be invoked at
# all. See notes/resume2.txt section 3 for the full rationale.

# Allow communicating with fuse kernel driver
# https://www.kernel.org/doc/Documentation/filesystems/fuse.txt
/dev/fuse rw,

# Allow connecting to the privileged FUSE mount broker's UNIX socket.
# The broker performs the actual mount(2)/umount(2) as real root and
# hands back a live FUSE communication fd via SCM_RIGHTS.
/run/xdg-fuse-broker.sock rw,

# Allow mounting the xdg-document-portal FUSE filesystem at the plain,
# global /run/user/<uid>/doc -- not the per-snap remapped runtime dir --
# because that's the one location snapd's own tooling (cmd_run.go's
# desktop-launch check, and the "desktop" interface's AppArmor
# bind-mount rule) hardcodes for every other snap to find the document
# portal. The plugging snap's own XDG_RUNTIME_DIR is overridden back to
# the real, unprivatized value for this reason (see
# ubuntu-desktop-session-snap's xdg-document-portal app "environment:").
#
# This rule intentionally is not paired with a grant of the sys_admin
# capability: the plugging snap's mount(2) call will still fail (no real
# CAP_SYS_ADMIN in its credentials), but it will fail with EPERM instead
# of EACCES, which is what causes libfuse to fall back to invoking
# fusermount3 (replaced, for this app, by a shim that talks to the
# broker instead of using a setuid helper).
mount fstype=fuse.* options=(rw,nosuid,nodev) ** -> /run/user/[0-9]*/doc/,
mount fstype=fuse.* options=(rw,nosuid,nodev) ** -> /run/user/[0-9]*/doc/**,

# libfuse creates the mountpoint directory itself before attempting the
# mount(2) call above, so it also needs plain create/write access to it
# (independent of the mount rule, which only governs the mount(2)
# syscall itself).
owner /run/user/[0-9]*/doc/ rw,

# Explicitly deny reads to /etc/fuse.conf. We do this to ensure that
# the safe defaults of fuse are used (which are enforced by our mount
# rules) and not system-specific options from /etc/fuse.conf that
# may conflict with our mount rules.
deny /etc/fuse.conf r,

# Allow read access to the fuse filesystem
/sys/fs/fuse/ r,
/sys/fs/fuse/** r,
`

var fuseDeviceConnectedPlugUDev = []string{`KERNEL=="fuse"`}

func init() {
	registerIface(&commonInterface{
		name:                  "fuse-device",
		summary:               fuseDeviceSummary,
		implicitOnCore:        true,
		implicitOnClassic:     false,
		baseDeclarationSlots:  fuseDeviceBaseDeclarationSlots,
		connectedPlugAppArmor: fuseDeviceConnectedPlugAppArmor,
		connectedPlugUDev:     fuseDeviceConnectedPlugUDev,
	})
}
