// -*- Mode: Go; indent-tabs-mode: t -*-

package builtin_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/testutil"
)

type SessionEnvironmentBrokerInterfaceSuite struct{}

var _ = Suite(&SessionEnvironmentBrokerInterfaceSuite{})

func (s *SessionEnvironmentBrokerInterfaceSuite) TestOnlyNamedSessionManagerCanCallBroker(c *C) {
	iface := builtin.MustInterface("session-environment-broker")
	plugInfo := `name: ubuntu-desktop-session
version: 1.0
apps:
  gnome-session-service:
    command: foo
    plugs: [session-environment-broker]
`
	plug, _ := MockConnectedPlug(c, plugInfo, nil, "session-environment-broker")
	slotInfo := `name: ubuntu-desktop-session
version: 1.0
apps:
  session-environment-broker:
    command: foo
    slots: [session-environment-broker]
slots:
  session-environment-broker:
`
	slot, _ := MockConnectedSlot(c, slotInfo, nil, "session-environment-broker")

	plugSet, err := interfaces.NewSnapAppSet(plug.Snap(), nil)
	c.Assert(err, IsNil)
	plugSpec := apparmor.NewSpecification(plugSet)
	c.Assert(plugSpec.AddConnectedPlug(iface, plug, slot), IsNil)
	plugRules := string(plugSpec.Snippets()["snap.ubuntu-desktop-session.gnome-session-service"][0])
	c.Assert(plugRules, testutil.Contains, `peer=(label="snap.ubuntu-desktop-session.session-environment-broker")`)
	c.Assert(plugRules, testutil.Contains, "member=UpdateEnvironment")
	c.Assert(plugRules, Not(testutil.Contains), "SetEnvironment")

	slotSet, err := interfaces.NewSnapAppSet(slot.Snap(), nil)
	c.Assert(err, IsNil)
	slotSpec := apparmor.NewSpecification(slotSet)
	c.Assert(slotSpec.AddConnectedSlot(iface, plug, slot), IsNil)
	slotRules := string(slotSpec.Snippets()["snap.ubuntu-desktop-session.session-environment-broker"][0])
	c.Assert(slotRules, testutil.Contains, `peer=(label="snap.ubuntu-desktop-session.gnome-session-service")`)
	c.Assert(slotRules, testutil.Contains, "member=UpdateEnvironment")
	c.Assert(builtin.Interfaces(), testutil.DeepContains, iface)
}
