// -*- Mode: Go; indent-tabs-mode: t -*-

package builtin_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/testutil"
)

type SystemdUserEnvironmentInterfaceSuite struct{}

var _ = Suite(&SystemdUserEnvironmentInterfaceSuite{})

func (s *SystemdUserEnvironmentInterfaceSuite) TestEnvironmentWritesAreBrokerOnly(c *C) {
	iface := builtin.MustInterface("systemd-user-environment")
	plug, _ := MockConnectedPlug(c, `name: other
version: 1.0
apps:
  app:
    command: foo
    plugs: [systemd-user-environment]
`, nil, "systemd-user-environment")
	slot, _ := MockConnectedSlot(c, `name: core
version: 0
type: os
slots:
  systemd-user-environment:
`, nil, "systemd-user-environment")

	appSet, err := interfaces.NewSnapAppSet(plug.Snap(), nil)
	c.Assert(err, IsNil)
	spec := apparmor.NewSpecification(appSet)
	c.Assert(spec.AddConnectedPlug(iface, plug, slot), IsNil)
	snippets := spec.Snippets()
	c.Assert(snippets["snap.other.app"], HasLen, 1)
	rules := string(snippets["snap.other.app"][0])
	c.Assert(rules, testutil.Contains, "GetConnectionCredentials")
	c.Assert(rules, testutil.Contains, "UpdateActivationEnvironment")
	c.Assert(rules, testutil.Contains, "UnsetAndSetEnvironment")
	c.Assert(rules, Not(testutil.Contains), "ShowEnvironment")
	c.Assert(rules, Not(testutil.Contains), "member=SetEnvironment")
	c.Assert(rules, Not(testutil.Contains), "member=UnsetEnvironment")
	c.Assert(builtin.Interfaces(), testutil.DeepContains, iface)
}
