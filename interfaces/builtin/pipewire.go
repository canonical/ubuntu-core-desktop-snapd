// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2018 Canonical Ltd
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

const pipewireSummary = `allows access to the pipewire sockets, and offer them`

const pipewireBaseDeclarationSlots = `
  pipewire:
    allow-installation:
      slot-snap-type:
        - app
    deny-auto-connection: true
`

const pipewireConnectedPlugAppArmor = `
# Allow communicating with pipewire service
/{run,dev}/shm/pulse-shm-* mrwk,

owner /run/user/[0-9]*/ r,
owner /run/user/[0-9]*/pipewire-[0-9] rw,
`

const pipewireConnectedPlugAppArmorCore = `
owner /run/user/[0-9]*/###SLOT_SECURITY_TAGS###/pipewire-[0-9] rw,
`

const pipewireConnectedPlugSecComp = `
shmctl
`

const pipewirePermanentSlotAppArmor = `
capability sys_nice,
capability sys_resource,

owner @{PROC}/@{pid}/exe r,
/etc/machine-id r,

# For udev
network netlink raw,
/sys/devices/virtual/dmi/id/sys_vendor r,
/sys/devices/virtual/dmi/id/bios_vendor r,
/sys/**/sound/** r,

# Shared memory based communication with clients
/{run,dev}/shm/pulse-shm-* mrwk,

owner /run/user/[0-9]*/pipewire-[0-9] rwk,
owner /run/user/[0-9]*/pipewire-[0-9]-manager rwk,
`

const pipewirePermanentSlotSecComp = `
# The following are needed for UNIX sockets
personality
setpriority
bind
listen
accept
accept4
shmctl
# libudev
socket AF_NETLINK - NETLINK_KOBJECT_UEVENT
`

type pipewireInterface struct{}

func (iface *pipewireInterface) Name() string {
	return "pipewire"
}

func (iface *pipewireInterface) StaticInfo() interfaces.StaticInfo {
	return interfaces.StaticInfo{
		Summary:              pipewireSummary,
		ImplicitOnClassic:    false,
		ImplicitOnCore:       false,
		BaseDeclarationSlots: pipewireBaseDeclarationSlots,
	}
}

func (iface *pipewireInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(pipewireConnectedPlugAppArmor)
	if !implicitSystemConnectedSlot(slot) {
		old := "###SLOT_SECURITY_TAGS###"
		new := "snap." + slot.Snap().InstanceName() // forms the snap-instance-specific subdirectory name of /run/user/*/ used for XDG_RUNTIME_DIR
		snippet := strings.Replace(pipewireConnectedPlugAppArmorCore, old, new, -1)
		spec.AddSnippet(snippet)
	}
	return nil
}

func (iface *pipewireInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(pipewirePermanentSlotAppArmor)
	return nil
}

func (iface *pipewireInterface) SecCompConnectedPlug(spec *seccomp.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(pipewireConnectedPlugSecComp)
	return nil
}

func (iface *pipewireInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(pipewirePermanentSlotSecComp)
	return nil
}

func (iface *pipewireInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	return true
}

func init() {
	registerIface(&pipewireInterface{})
}