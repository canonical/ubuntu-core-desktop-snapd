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

const pamUnixChkpwdSummary = `allows verifying a user's password via the unix_chkpwd/pam_extrausers_chkpwd helpers, and the pam_faillock/pam_exec lockout-check helpers that run alongside them (eg for screen lock/unlock)`

const pamUnixChkpwdBaseDeclarationSlots = `
  pam-unix-chkpwd:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const pamUnixChkpwdConnectedPlugAppArmor = `
# Description: allow invoking the setuid/setgid helper binaries that PAM's
# pam_unix and pam_extrausers modules exec to verify a user's password from
# an unprivileged/confined caller (eg kscreenlocker_worker running inside
# the plasma-kwin-wayland snap app, which cannot read /etc/shadow or
# /var/lib/extrausers/shadow directly). Without this, PAM authentication
# silently fails with "authentication failure" whenever it is performed
# from inside a confined desktop session, eg when locking/unlocking the
# screen (login via the unconfined display manager greeter is unaffected).

# unix_chkpwd ships with its own dedicated AppArmor profile (see
# /etc/apparmor.d/unix-chkpwd) which mediates its access to /etc/shadow,
# so transition into that profile.
/usr/sbin/unix_chkpwd Px,

# pam_extrausers_chkpwd is specific to Ubuntu Core's extrausers scheme and
# has no shipped AppArmor profile of its own. It is setgid root purely to
# read /var/lib/extrausers/shadow, the same privilege level as other
# unconfined, narrowly-scoped system helpers used by this project (eg the
# KAuth helper connected via the kde-kauth interface), so let it run
# unconfined rather than inherit the caller's (possibly much broader)
# confinement.
/usr/sbin/pam_extrausers_chkpwd Ux,

# The rest of this project's common-auth PAM stack runs two more helpers
# alongside pam_unix/pam_extrausers on every auth attempt, both of which
# hit the same confinement gap: they work fine from the unconfined
# display-manager greeter (login) but are silently denied -- and, for
# pam_faillock, this is fatal to the whole auth attempt since it is
# configured "requisite" -- when the caller is a confined desktop-session
# process such as kscreenlocker_worker (screen lock/unlock).

# pam_faillock needs to create/update its tally-file state directory the
# first time anything calls into PAM after boot; grant that explicitly
# rather than relying on some other, unconfined caller having already
# created it.
/run/faillock/ rw,
/run/faillock/** rwk,

# pam_exec unconditionally runs this project's lockout-not-enabled.sh
# check as part of every auth attempt. It is a tiny, harmless script that
# only tests for the presence of a single marker file (see
# "snap set system users.lockout=true"), so let it run inline
# (inheriting this profile) rather than crafting a dedicated AppArmor
# profile for it, and allow it to read the marker file it checks for.
/usr/lib/core/lockout-not-enabled.sh ix,
/etc/writable/account-locked.enable r,
`

func init() {
	registerIface(&commonInterface{
		name:                  "pam-unix-chkpwd",
		summary:               pamUnixChkpwdSummary,
		implicitOnCore:        true,
		baseDeclarationSlots:  pamUnixChkpwdBaseDeclarationSlots,
		connectedPlugAppArmor: pamUnixChkpwdConnectedPlugAppArmor,
	})
}
