// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package main_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/godbus/dbus"
	. "gopkg.in/check.v1"

	snap "github.com/snapcore/snapd/cmd/snap"
	"github.com/snapcore/snapd/dbusutil"
	"github.com/snapcore/snapd/dbusutil/dbustest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/testutil"
)

type DesktopLaunchSuite struct {
	BaseSnapSuite

	desktopFile string
}

var _ = Suite(&DesktopLaunchSuite{})

const sampleDesktopFile = `
[Desktop Entry]
Version=1.0
Name=Test App
X-Snap-Exec=foo %U
Actions=action1;

[Desktop Action action1]
Name=Test action
X-Snap-Exec=foo --action
`

func (s *DesktopLaunchSuite) SetUpTest(c *C) {
	s.BaseSnapSuite.SetUpTest(c)

	s.AddCleanup(func() {
		dirs.SetRootDir("")
	})
	dirs.SetRootDir(c.MkDir())
	err := os.MkdirAll(dirs.SnapDesktopFilesDir, 0o755)
	c.Assert(err, IsNil)

	s.desktopFile = filepath.Join(dirs.SnapDesktopFilesDir, "foo_foo.desktop")
	err = os.WriteFile(s.desktopFile, []byte(sampleDesktopFile), 0o644)
	c.Assert(err, IsNil)

	oldSnap := os.Getenv("SNAP")
	s.AddCleanup(func() {
		os.Setenv("SNAP", oldSnap)
	})
	os.Unsetenv("SNAP")
	bamfDesktopFileHint := os.Getenv("BAMF_DESKTOP_FILE_HINT")
	s.AddCleanup(func() {
		os.Setenv("BAMF_DESKTOP_FILE_HINT", bamfDesktopFileHint)
	})
	os.Unsetenv("BAMF_DESKTOP_FILE_HINT")
	desktopStartupID := os.Getenv("DESKTOP_STARTUP_ID")
	s.AddCleanup(func() {
		os.Setenv("DESKTOP_STARTUP_ID", desktopStartupID)
	})
	os.Unsetenv("DESKTOP_STARTUP_ID")
	xdgActivationToken := os.Getenv("XDG_ACTIVATION_TOKEN")
	s.AddCleanup(func() {
		os.Setenv("XDG_ACTIVATION_TOKEN", xdgActivationToken)
	})
	os.Unsetenv("XDG_ACTIVATION_TOKEN")
}

func (s *DesktopLaunchSuite) TestLaunch(c *C) {
	restore := snap.MockSyscallExec(func(arg0 string, args []string, env []string) error {
		c.Check(args, DeepEquals, []string{"snap", "run", "foo"})
		c.Check(env, testutil.Contains, "BAMF_DESKTOP_FILE_HINT="+s.desktopFile)
		return nil
	})
	defer restore()

	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", s.desktopFile})
	c.Check(err, IsNil)
}

func (s *DesktopLaunchSuite) TestLaunchWithUris(c *C) {
	restore := snap.MockSyscallExec(func(arg0 string, args []string, env []string) error {
		c.Check(args, DeepEquals, []string{"snap", "run", "foo", "http://example.org", "/test.txt"})
		c.Check(env, testutil.Contains, "BAMF_DESKTOP_FILE_HINT="+s.desktopFile)
		return nil
	})
	defer restore()

	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", s.desktopFile, "--", "http://example.org", "/test.txt"})
	c.Check(err, IsNil)
}

func (s *DesktopLaunchSuite) TestLaunchAction(c *C) {
	restore := snap.MockSyscallExec(func(arg0 string, args []string, env []string) error {
		c.Check(args, DeepEquals, []string{"snap", "run", "foo", "--action"})
		c.Check(env, testutil.Contains, "BAMF_DESKTOP_FILE_HINT="+s.desktopFile)
		return nil
	})
	defer restore()

	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", s.desktopFile, "--action", "action1"})
	c.Check(err, IsNil)
}

func (s *DesktopLaunchSuite) TestBadDesktopFile(c *C) {
	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", dirs.SnapDesktopFilesDir + "/../foo.desktop"})
	c.Check(err, ErrorMatches, `desktop file has unclean path: .*`)

	_, err = snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", "/tmp/foo.desktop"})
	c.Check(err, ErrorMatches, `only launching snap applications from .* is supported`)

	// A missing desktop file will trigger an error from desktopentry.Read
	filename := filepath.Join(dirs.SnapDesktopFilesDir, "bar.desktop")
	_, err = snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", filename})
	c.Check(err, ErrorMatches, `open .*: no such file or directory`)
}

func (s *DesktopLaunchSuite) TestBadAction(c *C) {
	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", s.desktopFile, "--action", "bad-action"})
	c.Check(err, ErrorMatches, `desktop file .* does not have action "bad-action"`)
}

func (s *DesktopLaunchSuite) TestCmdlineArgsToUris(c *C) {
	// Use a fixed current working directory so relative paths
	// resolve consistently.
	origDir, err := os.Getwd()
	c.Assert(err, IsNil)
	defer os.Chdir(origDir)
	os.Chdir("/tmp")

	uris, err := snap.CmdlineArgsToUris([]string{
		"/test 1.txt",
		"file:///test2.txt",
		"http://example.org/test3.txt",
		"test 4.txt",
		"mailto:joe@example.org",
	})
	c.Assert(err, IsNil)
	c.Check(uris, DeepEquals, []string{
		"file:///test%201.txt",
		"file:///test2.txt",
		"http://example.org/test3.txt",
		"file:///tmp/test%204.txt",
		"mailto:joe@example.org",
	})
}

func (s *DesktopLaunchSuite) TestDBusLaunch(c *C) {
	conn, _, err := dbustest.InjectableConnection(func(msg *dbus.Message, n int) ([]*dbus.Message, error) {
		c.Check(msg.Type, Equals, dbus.TypeMethodCall)
		c.Check(msg.Headers, DeepEquals, map[dbus.HeaderField]dbus.Variant{
			dbus.FieldDestination: dbus.MakeVariant("io.snapcraft.Launcher"),
			dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/io/snapcraft/PrivilegedDesktopLauncher")),
			dbus.FieldInterface:   dbus.MakeVariant("io.snapcraft.PrivilegedDesktopLauncher"),
			dbus.FieldMember:      dbus.MakeVariant("OpenDesktopEntry2"),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.ParseSignatureMust("ssasa{ss}")),
		})

		c.Assert(msg.Body, HasLen, 4)
		c.Check(msg.Body[0], Equals, "foo_foo.desktop")
		c.Check(msg.Body[1], Equals, "action1")
		c.Check(msg.Body[2], DeepEquals, []string{"file:///test.txt"})
		c.Check(msg.Body[3], DeepEquals, map[string]string{
			"DESKTOP_STARTUP_ID":   "x11-startup-id",
			"XDG_ACTIVATION_TOKEN": "wayland-startup-id",
		})

		reply := &dbus.Message{
			Type: dbus.TypeMethodReply,
			Headers: map[dbus.HeaderField]dbus.Variant{
				dbus.FieldReplySerial: dbus.MakeVariant(msg.Serial()),
				dbus.FieldSender:      dbus.MakeVariant(":42"),
			},
		}
		return []*dbus.Message{reply}, nil
	})
	c.Assert(err, IsNil)
	restore := dbusutil.MockOnlySessionBusAvailable(conn)
	defer restore()

	restore = snap.MockSyscallExec(func(arg0 string, args []string, env []string) error {
		c.Fail()
		return fmt.Errorf("syscall.Exec unexpectedly called")
	})
	defer restore()

	os.Setenv("SNAP", "launcher-snap")
	os.Setenv("DESKTOP_STARTUP_ID", "x11-startup-id")
	os.Setenv("XDG_ACTIVATION_TOKEN", "wayland-startup-id")

	_, err = snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", s.desktopFile, "--action", "action1", "--", "/test.txt"})
	c.Check(err, IsNil)
}

func (s *DesktopLaunchSuite) TestDBusLaunchFailed(c *C) {
	conn, _, err := dbustest.InjectableConnection(func(msg *dbus.Message, n int) ([]*dbus.Message, error) {
		reply := &dbus.Message{
			Type: dbus.TypeError,
			Headers: map[dbus.HeaderField]dbus.Variant{
				dbus.FieldReplySerial: dbus.MakeVariant(msg.Serial()),
				dbus.FieldSender:      dbus.MakeVariant(":42"),
				dbus.FieldErrorName:   dbus.MakeVariant("org.freedesktop.DBus.Error.UnknownMethod"),
			},
		}
		return []*dbus.Message{reply}, nil
	})
	c.Assert(err, IsNil)
	restore := dbusutil.MockOnlySessionBusAvailable(conn)
	defer restore()

	restore = snap.MockSyscallExec(func(arg0 string, args []string, env []string) error {
		c.Fail()
		return fmt.Errorf("syscall.Exec unexpectedly called")
	})
	defer restore()

	os.Setenv("SNAP", "launcher-snap")

	_, err = snap.Parser(snap.Client()).ParseArgs([]string{"routine", "desktop-launch", "--desktop", s.desktopFile, "--action", "action1", "--", "/test.txt"})
	c.Check(err, ErrorMatches, `failed to launch foo_foo.desktop via the privileged desktop launcher: org.freedesktop.DBus.Error.UnknownMethod`)
}
