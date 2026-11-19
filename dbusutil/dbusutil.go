// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package dbusutil

import (
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"

	"github.com/snapcore/snapd/dirs"
)

// isSessionBusLikelyPresent checks for the apparent availability of DBus session bus.
//
// The code matches what go-dbus does when it tries to detect the session bus:
// - the presence of the environment variable DBUS_SESSION_BUS_ADDRESS
// - the presence of the bus socket address in the file /run/user/UID/dbus-session
// - the presence of the bus socket in /run/user/UID/bus
func isSessionBusLikelyPresent() bool {
	if address := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); address != "" {
		return true
	}
	uid := os.Getuid()
	if fi, err := os.Stat(fmt.Sprintf("%s/%d/dbus-session", dirs.XdgRuntimeDirBase, uid)); err == nil {
		if fi.Mode()&os.ModeType == 0 {
			return true
		}
	}
	if fi, err := os.Stat(fmt.Sprintf("%s/%d/bus", dirs.XdgRuntimeDirBase, uid)); err == nil {
		if fi.Mode()&os.ModeType == os.ModeSocket {
			return true
		}
	}
	return false
}

// MaybeExportSessionBusAddress makes the per-user bus socket
// discoverable when the launch environment carries no session bus
// address.
//
// snapd's own presence check (IsSessionBusLikelyPresent) already
// looks at dirs.XdgRuntimeDirBase/<uid>/bus, so the decision whether
// a bus is reachable does not depend on the environment. But go-dbus,
// given an empty DBUS_SESSION_BUS_ADDRESS, must discover the address
// itself, and its discovery path (tryDiscoverDbusSessionBusAddress)
// depends on user.Current(): without cgo that fails when the uid is
// not in passwd and $USER/$HOME are unset (e.g. a greeter with a
// dynamic uid), and it hard-codes /run/user rather than
// dirs.XdgRuntimeDirBase. Export the canonical address explicitly so
// go-dbus never needs its discovery path.
//
// Note the mutation is process-global and inherited by exec'd
// applications: snap run launched from ssh, cron or runuser contexts
// now injects DBUS_SESSION_BUS_ADDRESS into the application
// environment. go-dbus would do the same via Setenv on its own
// discovery success path.
//
// Exported for tests.
func MaybeExportSessionBusAddress() {
	if address := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); address != "" {
		return
	}
	uid := os.Getuid()
	socket := fmt.Sprintf("%s/%d/bus", dirs.XdgRuntimeDirBase, uid)
	if fi, err := os.Stat(socket); err == nil && fi.Mode()&os.ModeType == os.ModeSocket {
		os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+socket)
	}
}

// SessionBus is like dbus.SessionBus but it avoids auto-starting
// a new dbus-daemon when a bus is not already available.
//
// The go-dbus package will launch a session bus instance on demand when none
// is present, something we do not want to do. In all contexts where there is a
// need to use the session bus, we expect session bus daemon to have been started
// and managed by the corresponding user session manager.
//
// This function is mockable by either MockConnections or
// MockOnlySessionBusAvailable.
var SessionBus = func() (*dbus.Conn, error) {
	MaybeExportSessionBusAddress()
	if isSessionBusLikelyPresent() {
		return dbus.SessionBus()
	}
	return nil, fmt.Errorf("cannot find session bus")
}

// SystemBus is like dbus.SystemBus and is provided for completeness.
//
// This function is mockable by either MockConnections or
// MockOnlySystemBusAvailable.
var SystemBus = func() (*dbus.Conn, error) {
	return dbus.SystemBus()
}

// MockConnections mocks the connection functions system and session buses.
func MockConnections(system, session func() (*dbus.Conn, error)) (restore func()) {
	oldSystem := SystemBus
	oldSession := SessionBus
	SystemBus = system
	SessionBus = session
	return func() {
		SystemBus = oldSystem
		SessionBus = oldSession
	}
}

// MockOnlySystemBusAvailable makes SystemBus return the given connection.
//
// In addition calling SessionBus will panic.
func MockOnlySystemBusAvailable(conn *dbus.Conn) (restore func()) {
	systemBus := func() (*dbus.Conn, error) { return conn, nil }
	sessionBus := func() (*dbus.Conn, error) {
		panic("DBus session bus should not have been used")
	}
	return MockConnections(systemBus, sessionBus)
}

// MockOnlySessionBusAvailable makes SessionBus return the given connection.
//
// In addition calling SystemBus will panic.
func MockOnlySessionBusAvailable(conn *dbus.Conn) (restore func()) {
	systemBus := func() (*dbus.Conn, error) {
		panic("DBus system bus should not have been used")
	}
	sessionBus := func() (*dbus.Conn, error) { return conn, nil }
	return MockConnections(systemBus, sessionBus)
}

// SessionBusPrivate opens a connection to the D-Bus session bus
// independent of the default shared connection.
func SessionBusPrivate() (*dbus.Conn, error) {
	if !isSessionBusLikelyPresent() {
		return nil, fmt.Errorf("cannot find session bus")
	}
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, err
	}
	if err := conn.Auth(nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
