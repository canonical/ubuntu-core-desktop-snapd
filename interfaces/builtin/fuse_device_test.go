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

package builtin_test

import (
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type FuseDeviceInterfaceSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

const fuseDeviceConsumerYaml = `name: consumer
version: 0
apps:
 app:
  plugs: [fuse-device]
`

const fuseDeviceCoreYaml = `name: core
version: 0
type: os
slots:
  fuse-device:
`

var _ = Suite(&FuseDeviceInterfaceSuite{
	iface: builtin.MustInterface("fuse-device"),
})

func (s *FuseDeviceInterfaceSuite) SetUpTest(c *C) {
	s.plug, s.plugInfo = MockConnectedPlug(c, fuseDeviceConsumerYaml, nil, "fuse-device")
	s.slot, s.slotInfo = MockConnectedSlot(c, fuseDeviceCoreYaml, nil, "fuse-device")
}

func (s *FuseDeviceInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "fuse-device")
}

func (s *FuseDeviceInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *FuseDeviceInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *FuseDeviceInterfaceSuite) TestAppArmorSpec(c *C) {
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)
	spec := apparmor.NewSpecification(appSet)
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	snippet := spec.SnippetForTag("snap.consumer.app")
	c.Assert(snippet, testutil.Contains, `/dev/fuse rw,`)
	c.Assert(snippet, testutil.Contains, `/run/xdg-fuse-broker.sock rw,`)
	c.Assert(snippet, testutil.Contains,
		`mount fstype=fuse.* options=(rw,nosuid,nodev) ** -> /run/user/[0-9]*/doc/,`)
	c.Assert(snippet, testutil.Contains,
		`mount fstype=fuse.* options=(rw,nosuid,nodev) ** -> /run/user/[0-9]*/doc/**,`)
	c.Assert(snippet, testutil.Contains, `owner /run/user/[0-9]*/doc/ rw,`)
	// The whole point of this interface vs fuse-support: never grant the
	// real capability, only a scoped mount rule that still fails with
	// EPERM (not EACCES) so libfuse's fusermount3 fallback is reached.
	// Check for the actual AppArmor directive (not just the phrase, which
	// also appears in this snippet's explanatory comments).
	c.Assert(snippet, Not(testutil.Contains), "capability sys_admin,")
}

func (s *FuseDeviceInterfaceSuite) TestUDevSpec(c *C) {
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)
	spec := udev.NewSpecification(appSet)
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(spec.Snippets(), HasLen, 2)
	c.Assert(spec.Snippets(), testutil.Contains, `# fuse-device
KERNEL=="fuse", TAG+="snap_consumer_app"`)
	c.Assert(spec.Snippets(), testutil.Contains, fmt.Sprintf(`TAG=="snap_consumer_app", SUBSYSTEM!="module", SUBSYSTEM!="subsystem", RUN+="%v/snap-device-helper $env{ACTION} snap_consumer_app $devpath $major:$minor"`, dirs.DistroLibExecDir))
}

func (s *FuseDeviceInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, true)
	c.Assert(si.ImplicitOnClassic, Equals, false)
	c.Assert(si.Summary, Equals, `allows restricted access to the FUSE device without real CAP_SYS_ADMIN`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "fuse-device")
}

func (s *FuseDeviceInterfaceSuite) TestAutoConnect(c *C) {
	// deny-auto-connection in the base declaration is what actually blocks
	// implicit auto-connection; the Go-level AutoConnect() default (as with
	// fuse-support) still reports true here and relies on an explicit
	// gadget connection entry to be connected at all.
	c.Assert(s.iface.AutoConnect(s.plugInfo, s.slotInfo), Equals, true)
}

func (s *FuseDeviceInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
