// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2016 Canonical Ltd
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

package wrappers

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/snapcore/snapd/desktop/desktopentry"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
)

// From the freedesktop Desktop Entry Specification¹,
//
//	Keys with type localestring may be postfixed by [LOCALE], where
//	LOCALE is the locale type of the entry. LOCALE must be of the form
//	lang_COUNTRY.ENCODING@MODIFIER, where _COUNTRY, .ENCODING, and
//	@MODIFIER may be omitted. If a postfixed key occurs, the same key
//	must be also present without the postfix.
//
//	When reading in the desktop entry file, the value of the key is
//	selected by matching the current POSIX locale for the LC_MESSAGES
//	category against the LOCALE postfixes of all occurrences of the
//	key, with the .ENCODING part stripped.
//
// sadly POSIX doesn't mention what values are valid for LC_MESSAGES,
// beyond mentioning² that it's implementation-defined (and can be of
// the form [language[_territory][.codeset][@modifier]])
//
// 1. https://specifications.freedesktop.org/desktop-entry-spec/latest/ar01s04.html
// 2. http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap08.html#tag_08_02
//
// So! The following is simplistic, and based on the contents of
// PROVIDED_LOCALES in locales.config, and does not cover all of
// "locales -m" (and ignores XSetLocaleModifiers(3), which may or may
// not be related). Patches welcome, as long as it's readable.
//
// REVIEWERS: this could also be left as `(?:\[[@_.A-Za-z-]\])?=` if even
// the following is hard to read:
const localizedSuffix = `(?:\[[a-z]+(?:_[A-Z]+)?(?:\.[0-9A-Z-]+)?(?:@[a-z]+)?\])?=`

var isValidDesktopFileLine = regexp.MustCompile(strings.Join([]string{
	// NOTE (mostly to self): as much as possible keep the
	// individual regexp simple, optimize for legibility
	//
	// empty lines and comments
	`^\s*$`,
	`^\s*#`,
	// headers
	`^\[Desktop Entry\]$`,
	`^\[Desktop Action [0-9A-Za-z-]+\]$`,
	`^\[[A-Za-z0-9-]+ Shortcut Group\]$`,
	// https://specifications.freedesktop.org/desktop-entry-spec/latest/ar01s05.html
	"^Type=",
	"^Version=",
	"^Name" + localizedSuffix,
	"^GenericName" + localizedSuffix,
	"^NoDisplay=",
	"^Comment" + localizedSuffix,
	"^Icon=",
	"^Hidden=",
	"^OnlyShowIn=",
	"^NotShowIn=",
	"^Exec=",
	// Note that we do not support TryExec, it does not make sense
	// in the snap context
	"^Terminal=",
	"^Actions=",
	"^MimeType=",
	"^Categories=",
	"^Keywords" + localizedSuffix,
	"^StartupNotify=",
	"^StartupWMClass=",
	"^PrefersNonDefaultGPU=",
	"^SingleMainWindow=",
	// unity extension
	"^X-Ayatana-Desktop-Shortcuts=",
	"^TargetEnvironment=",
}, "|")).Match

// fileOrUriMacro returns the Exec line macro used to expand files or URIs
func fileOrUriMacro(cmd string) rune {
	isMacro := false
	for _, r := range cmd {
		if isMacro {
			switch r {
			case 'f', 'F', 'u', 'U':
				return r
			}
			isMacro = false
		} else if r == '%' {
			isMacro = true
		}
	}
	// If no macros are found, default to accepting a single regular file
	return 'f'
}

// detectAppAndRewriteExecLine parses snap app name from passed "Exec=" line and rewrites it
// to use the wrapper path for snap application.
func detectAppAndRewriteExecLine(s *snap.Info, desktopFile, action, line string) (appName string, execLine string, err error) {
	if action != "" {
		action = " --action " + action
	}
	cmd := strings.SplitN(line, "=", 2)[1]
	exec := fmt.Sprintf("Exec=/usr/bin/snap routine desktop-launch --desktop %s%s -- %%%c\nX-Snap-Exec=", desktopFile, action, fileOrUriMacro(cmd))

	for _, app := range s.Apps {
		wrapper := filepath.Base(app.WrapperPath())
		validCmd := filepath.Base(wrapper)
		if s.InstanceKey != "" {
			// wrapper uses s.InstanceName(), with the instance key
			// set the command will be 'snap_foo.app' instead of
			// 'snap.app', need to account for that
			validCmd = snap.JoinSnapApp(s.SnapName(), app.Name)
		}
		// check the prefix to allow %flag style args
		// this is ok because desktop files are not run through sh
		// so we don't have to worry about the arguments too much
		if cmd == validCmd {
			return app.Name, exec + wrapper, nil
		} else if strings.HasPrefix(cmd, validCmd+" ") {
			return app.Name, exec + wrapper + cmd[len(validCmd):], nil
		}
	}

	logger.Noticef("cannot use line %q for desktop file %q (snap %s)", line, desktopFile, s.InstanceName())
	// The Exec= line in the desktop file is invalid. Instead of failing
	// hard we rewrite the Exec= line. The convention is that the desktop
	// file has the same name as the application we can use this fact here.
	df := filepath.Base(desktopFile)
	desktopFileApp := strings.TrimSuffix(df, filepath.Ext(df))
	app, ok := s.Apps[desktopFileApp]
	if ok {
		newExec := exec + filepath.Base(app.WrapperPath())
		logger.Noticef("rewriting desktop file %q to %q", desktopFile, newExec)
		return app.Name, newExec, nil
	}

	return "", "", fmt.Errorf("invalid exec command: %q", cmd)
}

func rewriteIconLine(s *snap.Info, line string) (string, error) {
	icon := strings.SplitN(line, "=", 2)[1]

	// If there is a path separator, assume the icon is a path name
	if strings.ContainsRune(icon, filepath.Separator) {
		if !strings.HasPrefix(icon, "${SNAP}/") {
			return "", fmt.Errorf("icon path %q is not part of the snap", icon)
		}
		if filepath.Clean(icon) != icon {
			return "", fmt.Errorf("icon path %q is not canonicalized, did you mean %q?", icon, filepath.Clean(icon))
		}
		return line, nil
	}

	// If the icon is prefixed with "snap.${SNAP_NAME}.", rewrite
	// to the instance name.
	snapIconPrefix := fmt.Sprintf("snap.%s.", s.SnapName())
	if strings.HasPrefix(icon, snapIconPrefix) {
		return fmt.Sprintf("Icon=snap.%s.%s", s.InstanceName(), icon[len(snapIconPrefix):]), nil
	}

	// If the icon has any other "snap." prefix, treat this as an error.
	if strings.HasPrefix(icon, "snap.") {
		return "", fmt.Errorf("invalid icon name: %q, must start with %q", icon, snapIconPrefix)
	}

	// Allow other icons names through unchanged.
	return line, nil
}

func sanitizeDesktopFile(s *snap.Info, desktopFile string, rawcontent []byte) []byte {
	var newContent bytes.Buffer
	mountDir := []byte(s.MountDir())
	scanner := bufio.NewScanner(bytes.NewReader(rawcontent))
	action := ""
	for i := 0; scanner.Scan(); i++ {
		bline := scanner.Bytes()

		if !isValidDesktopFileLine(bline) {
			logger.Debugf("ignoring line %d (%q) in source of desktop file %q", i, bline, filepath.Base(desktopFile))
			continue
		}
		// Record whether we are within a [Desktop Action $foo] group
		if len(bline) > 0 && bline[0] == '[' {
			action = ""
		}
		if bytes.HasPrefix(bline, []byte("[Desktop Action ")) {
			action = string(bline[len("[Desktop Action ") : len(bline)-1])
		}

		// rewrite exec lines to an absolute path for the binary
		if bytes.HasPrefix(bline, []byte("Exec=")) {
			var err error
			appName, line, err := detectAppAndRewriteExecLine(s, desktopFile, action, string(bline))
			if err != nil {
				// something went wrong, ignore the line
				continue
			}
			// Add metadata entry to associate the exec line with a snap app
			newContent.Write([]byte("X-SnapAppName=" + appName + "\n"))

			bline = []byte(line)
		}

		// rewrite icon line if it references an icon theme icon
		if bytes.HasPrefix(bline, []byte("Icon=")) {
			line, err := rewriteIconLine(s, string(bline))
			if err != nil {
				logger.Debugf("ignoring icon in source desktop file %q: %s", filepath.Base(desktopFile), err)
				continue
			}
			bline = []byte(line)
		}

		// do variable substitution
		bline = bytes.Replace(bline, []byte("${SNAP}"), mountDir, -1)

		newContent.Grow(len(bline) + 1)
		newContent.Write(bline)
		newContent.WriteByte('\n')

		// insert snap name
		if bytes.Equal(bline, []byte("[Desktop Entry]")) {
			newContent.Write([]byte("X-SnapInstanceName=" + s.InstanceName() + "\n"))
		}
	}

	return newContent.Bytes()
}

func updateDesktopDatabase(desktopFiles []string) error {
	if len(desktopFiles) == 0 {
		return nil
	}

	if _, err := exec.LookPath("update-desktop-database"); err == nil {
		if output, err := exec.Command("update-desktop-database", dirs.SnapDesktopFilesDir).CombinedOutput(); err != nil {
			return fmt.Errorf("cannot update-desktop-database %q: %s", output, err)
		}
		logger.Debugf("update-desktop-database successful")
	}
	return nil
}

func findDesktopFiles(rootDir string) ([]string, error) {
	if !osutil.IsDirectory(rootDir) {
		return nil, nil
	}
	desktopFiles, err := filepath.Glob(filepath.Join(rootDir, "*.desktop"))
	if err != nil {
		return nil, fmt.Errorf("cannot get desktop files from %v: %s", rootDir, err)
	}
	return desktopFiles, nil
}

func deriveDesktopFilesContent(s *snap.Info) (map[string]osutil.FileState, error) {
	desktopFiles, err := s.DesktopFilesFromInstalledSnap(snap.DesktopFilesFromInstalledSnapOptions{})
	if err != nil {
		return nil, err
	}

	content := make(map[string]osutil.FileState, len(desktopFiles))
	for _, df := range desktopFiles {
		base := filepath.Base(df)
		base, err := s.MangleDesktopFileName(base)
		if err != nil {
			return nil, err
		}
		if _, exists := content[base]; exists {
			logger.Noticef("error: identified %q as a duplicate file name %q after mangling in snap %q", filepath.Base(df), base, s.InstanceName())
			continue
		}
		fileContent, err := os.ReadFile(df)
		if err != nil {
			return nil, err
		}
		installedDesktopFileName := filepath.Join(dirs.SnapDesktopFilesDir, base)
		fileContent = sanitizeDesktopFile(s, installedDesktopFileName, fileContent)
		content[base] = &osutil.MemoryFileState{
			Content: fileContent,
			Mode:    0644,
		}
	}
	return content, nil
}

// forAllDesktopFiles loops over all installed desktop files under
// dirs.SnapDesktopFilesDir.
//
// Only the desktop file base and parsed instance name are passed to the
// callback function.
func forAllDesktopFiles(cb func(base, instanceName string) error) error {
	installedDesktopFiles, err := findDesktopFiles(dirs.SnapDesktopFilesDir)
	if err != nil {
		return err
	}

	for _, desktopFile := range installedDesktopFiles {
		base := filepath.Base(desktopFile)
		if isSnapdDesktopFile(base) {
			// skip snapd desktop files installed on core, they don't
			// have the usual X-SnapInstanceName entry.
			continue
		}

		de, err := desktopentry.Read(desktopFile)
		if err != nil || de.SnapInstanceName == "" {
			// cannot read instance name from desktop file, ignore
			logger.Noticef("cannot read instance name: %s", err)
			continue
		}

		if err := cb(base, de.SnapInstanceName); err != nil {
			return err
		}
	}

	return nil
}

func hasDesktopPrefix(s *snap.Info, desktopFile string) bool {
	base := filepath.Base(desktopFile)
	prefix := s.DesktopPrefix() + "_"
	return strings.HasPrefix(base, prefix) && strings.HasSuffix(base, ".desktop")
}

// EnsureSnapDesktopFiles puts in place the desktop files for the applications from the snap.
//
// It also removes desktop files from the applications of the old snap revision to ensure
// that only new snap desktop files exist.
func EnsureSnapDesktopFiles(snaps []*snap.Info) error {
	if err := os.MkdirAll(dirs.SnapDesktopFilesDir, 0755); err != nil {
		return err
	}

	var updated []string
	for _, info := range snaps {
		if info == nil {
			return fmt.Errorf("internal error: snap info cannot be nil")
		}

		desktopFileIDs, err := info.DesktopPlugFileIDs()
		if err != nil {
			return err
		}
		desktopFilesGlobs := []string{fmt.Sprintf("%s_*.desktop", info.DesktopPrefix())}
		for _, desktopFileID := range desktopFileIDs {
			desktopFilesGlobs = append(desktopFilesGlobs, desktopFileID+".desktop")
		}
		content, err := deriveDesktopFilesContent(info)
		if err != nil {
			return err
		}

		addGlobPatternAndConflictCheck := func(base, instanceName string) error {
			// Check if a target desktop file belongs to another snap
			_, hasTarget := content[base]
			if hasTarget && instanceName != info.InstanceName() {
				return fmt.Errorf("cannot install %q: %q already exists for another snap", base, filepath.Join(dirs.SnapDesktopFilesDir, base))
			}
			if instanceName == info.InstanceName() && !hasTarget && !hasDesktopPrefix(info, base) {
				// An unmangled desktop file exists for the snap, add to glob
				// patterns for removal
				desktopFilesGlobs = append(desktopFilesGlobs, base)
			}
			return nil
		}
		if err := forAllDesktopFiles(addGlobPatternAndConflictCheck); err != nil {
			return err
		}

		changed, removed, err := osutil.EnsureDirStateGlobs(dirs.SnapDesktopFilesDir, desktopFilesGlobs, content)
		if err != nil {
			return err
		}
		updated = append(updated, changed...)
		updated = append(updated, removed...)
	}

	// updates mime info etc
	if err := updateDesktopDatabase(updated); err != nil {
		return err
	}

	return nil
}

// RemoveSnapDesktopFiles removes the added desktop files for the applications in the snap.
func RemoveSnapDesktopFiles(s *snap.Info) error {
	if !osutil.IsDirectory(dirs.SnapDesktopFilesDir) {
		return nil
	}

	desktopFilesGlobs := []string{fmt.Sprintf("%s_*.desktop", s.DesktopPrefix())}

	addGlobPattern := func(base, instanceName string) error {
		if instanceName == s.InstanceName() && !hasDesktopPrefix(s, base) {
			// An unmangled desktop file exists for the snap, add to glob
			// patterns for removal
			desktopFilesGlobs = append(desktopFilesGlobs, base)
		}

		return nil
	}
	if err := forAllDesktopFiles(addGlobPattern); err != nil {
		return err
	}

	_, removed, err := osutil.EnsureDirStateGlobs(dirs.SnapDesktopFilesDir, desktopFilesGlobs, nil)
	if err != nil {
		return err
	}

	// updates mime info etc
	if err := updateDesktopDatabase(removed); err != nil {
		return err
	}

	return nil
}
