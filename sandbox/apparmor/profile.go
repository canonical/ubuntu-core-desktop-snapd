// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2022 Canonical Ltd
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

package apparmor

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/strutil"
)

type AaParserFlags int

const (
	// SkipReadCache causes apparmor_parser to be invoked with --skip-read-cache.
	// This allows us to essentially overwrite a cache that we know is stale regardless
	// of the time and date settings (apparmor_parser caching is based on mtime).
	// Note that writing of the cache relies on --write-cache but we pass that
	// command-line option unconditionally.
	SkipReadCache AaParserFlags = 1 << iota

	// ConserveCPU tells apparmor_parser to spare up to two CPUs on multi-core systems to
	// reduce load when processing many profiles at once.
	ConserveCPU AaParserFlags = 1 << iota

	// SkipKernelLoad tells apparmor_parser not to load profiles into the kernel. The use
	// case of this is when in pre-seeding mode.
	SkipKernelLoad AaParserFlags = 1 << iota
)

var (
	runtimeNumCPU = runtime.NumCPU

	osutilIsHomeUsingNFS        = osutil.IsHomeUsingNFS
	osutilIsRootWritableOverlay = osutil.IsRootWritableOverlay
)

// NfsSnippet contains extra permissions necessary for snaps and snap-confine
// to operate when NFS is used. This is an imperfect solution as this grants
// some network access to all the snaps on the system.
// For tracking see https://bugs.launchpad.net/apparmor/+bug/1724903
var NfsSnippet = `
  # snapd autogenerated workaround for systems using NFS, for details see:
  # https://bugs.launchpad.net/ubuntu/+source/snapd/+bug/1662552
  network inet,
  network inet6,
`

// OverlayRootSnippet contains the extra permissions necessary for snap and
// snap-confine to operate on systems where '/' is a writable overlay fs.
// AppArmor requires directory reads for upperdir (but these aren't otherwise
// visible to the snap). While we filter AppArmor regular expression (AARE)
// characters elsewhere, we double quote the path in case UPPERDIR has spaces.
var OverlayRootSnippet = `
  # snapd autogenerated workaround for systems using '/' on overlayfs. For
  # details see: https://bugs.launchpad.net/apparmor/+bug/1703674
  "###UPPERDIR###/{,**/}" r,
`

// capabilityBPFSnippet contains extra permissions for snap-confine to execute
// bpf() syscall and set up or modify cgroupv2 device access filtering
var capabilityBPFSnippet = `
capability bpf,
`

func numberOfJobsParam() string {
	cpus := runtimeNumCPU()
	// Do not use all CPUs as this may have negative impact when booting.
	if cpus > 2 {
		// otherwise spare 2
		cpus = cpus - 2
	} else {
		// Systems with only two CPUs, spare 1.
		//
		// When there is a a single CPU, pass -j1 to allow a single
		// compilation job only. Note, we could pass -j0 in such case
		// for further improvement, but that has incompatible meaning
		// between apparmor 2.x (automatic job count, equivalent to
		// -jauto) and 3.x (compile everything in the main process).
		cpus = 1
	}

	return fmt.Sprintf("-j%d", cpus)
}

// LoadProfiles loads apparmor profiles from the given files.
//
// If no such profiles were previously loaded then they are simply added to the kernel.
// If there were some profiles with the same name before, those profiles are replaced.
var LoadProfiles = func(fnames []string, cacheDir string, flags AaParserFlags) error {
	if len(fnames) == 0 {
		return nil
	}

	// Use no-expr-simplify since expr-simplify is actually slower on armhf (LP: #1383858)
	args := []string{"--replace", "--write-cache", "-O", "no-expr-simplify", fmt.Sprintf("--cache-loc=%s", cacheDir)}
	if flags&ConserveCPU != 0 {
		args = append(args, numberOfJobsParam())
	}

	if flags&SkipKernelLoad != 0 {
		args = append(args, "--skip-kernel-load")
	}

	if flags&SkipReadCache != 0 {
		args = append(args, "--skip-read-cache")
	}
	if !osutil.GetenvBool("SNAPD_DEBUG") {
		args = append(args, "--quiet")
	}

	cmd, _, err := AppArmorParser()
	if err != nil {
		return err
	}

	cmd.Args = append(cmd.Args, args...)
	cmd.Args = append(cmd.Args, fnames...)
	output, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(output), "parser error") {
		if err == nil {
			// ensure we have an error to report
			err = fmt.Errorf("exit status 0 with parser error")
		}
		return fmt.Errorf("cannot load apparmor profiles: %s\napparmor_parser output:\n%s", err, string(output))
	}
	return nil
}

// UnloadProfiles is meant to remove the named profiles from the running
// kernel and then remove any cache files. Importantly, we can only unload
// profiles when we are sure there are no lingering processes from the snap
// (ie, forcibly stop all running processes from the snap). Otherwise, any
// running processes will become unconfined. Since we don't have this guarantee
// yet, leave the profiles loaded in the kernel but remove the cache files from
// the system so the policy is gone on the next reboot. LP: #1818241
func UnloadProfiles(names []string, cacheDir string) error {
	if len(names) == 0 {
		return nil
	}

	/* TODO: uncomment when no lingering snap processes is guaranteed
	// By the time this function is called, all the profiles (names) have
	// been removed from dirs.SnapAppArmorDir, so to unload the profiles
	// from the running kernel we must instead use sysfs and write the
	// profile names one at a time to
	// /sys/kernel/security/apparmor/.remove (with no trailing \n).
	apparmorSysFsRemove := "/sys/kernel/security/apparmor/.remove"
	if !osutil.IsWritable(appArmorSysFsRemove) {
	        return fmt.Errorf("cannot unload apparmor profile: %s does not exist\n", appArmorSysFsRemove)
	}
	for _, n := range names {
	        // ignore errors since it is ok if the profile isn't removed
	        // from the kernel
	        ioutil.WriteFile(appArmorSysFsRemove, []byte(n), 0666)
	}
	*/

	// AppArmor 2.13 and higher has a cache forest while 2.12 and lower has
	// a flat directory (on 2.12 and earlier, .features and the snap
	// profiles are in the top-level directory instead of a subdirectory).
	// With 2.13+, snap profiles are not expected to be in every
	// subdirectory, so don't error on ENOENT but otherwise if we get an
	// error, something weird happened so stop processing.
	if li, err := filepath.Glob(filepath.Join(cacheDir, "*/.features")); err == nil && len(li) > 0 { // 2.13+
		for _, p := range li {
			dir := path.Dir(p)
			if err := osutil.UnlinkMany(dir, names); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot remove apparmor profile cache in %s: %s", dir, err)
			}
		}
	} else if err := osutil.UnlinkMany(cacheDir, names); err != nil && !os.IsNotExist(err) { // 2.12-
		return fmt.Errorf("cannot remove apparmor profile cache: %s", err)
	}
	return nil
}

// ReloadAllSnapProfiles reload the AppArmor profiles of all installed snaps,
// as well as that of snap-confine.
// This method is meant to be called when some rules have been changed in
// AppArmor include files (like in the tunable files for HOMEDIRS or other
// variables) which are bound to affect most snaps.
func ReloadAllSnapProfiles() error {
	profiles, err := filepath.Glob(filepath.Join(dirs.SnapAppArmorDir, "*"))
	if err != nil {
		// This only happens if the pattern is malformed
		return err
	}

	// We also need to reload the profile of snap-confine; it could come from
	// the core snap, in which case the glob above will already include it, or
	// from the distribution package, in which case it's under
	// /etc/apparmor.d/.
	if snapConfineProfile := SnapConfineDistroProfilePath(); snapConfineProfile != "" {
		profiles = append(profiles, snapConfineProfile)
	}

	// We want to reload the profiles no matter what, so don't even bother
	// checking if the cached profile is newer
	aaFlags := SkipReadCache
	if err := LoadProfiles(profiles, SystemCacheDir, aaFlags); err != nil {
		return err
	}

	return nil
}

// profilesPath contains information about the currently loaded apparmor profiles.
const realProfilesPath = "/sys/kernel/security/apparmor/profiles"

var profilesPath = realProfilesPath

// LoadedProfiles interrogates the kernel and returns a list of loaded apparmor profiles.
//
// Snappy manages apparmor profiles named "snap.*". Other profiles might exist on
// the system (via snappy dimension) and those are filtered-out.
func LoadedProfiles() ([]string, error) {
	file, err := os.Open(profilesPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var profiles []string
	for {
		var name, mode string
		n, err := fmt.Fscanf(file, "%s %s\n", &name, &mode)
		if n > 0 && n != 2 {
			return nil, fmt.Errorf("syntax error, expected: name (mode)")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, "snap.") {
			profiles = append(profiles, name)
		}
	}
	return profiles, nil
}

// SnapConfineDistroProfilePath returns the path to the AppArmor profile of the
// snap-confine binary shipped by the distribution package.
// If such a profile is not found (for instance, because we are running Ubuntu
// Core) return an empty string
var SnapConfineDistroProfilePath = func() string {
	// For historical reasons we may have a filename that ends with .real or
	// not.  If we do then we prefer the file ending with the name .real as
	// that is the more recent name we use.
	for _, profileName := range []string{
		"usr.lib.snapd.snap-confine.real",
		"usr.lib.snapd.snap-confine",
		"usr.libexec.snapd.snap-confine",
	} {
		maybeProfilePath := filepath.Join(ConfDir, profileName)
		if osutil.FileExists(maybeProfilePath) {
			return maybeProfilePath
		}
	}

	return ""
}

// SetupSnapConfineSnippets inspects the system and sets up local apparmor
// policy for snap-confine. Local policy is included by the system-wide policy.
// Returns whether any modifications was made to the snap-confine snippets.
func SetupSnapConfineSnippets() (wasChanged bool, err error) {
	// Create the local policy directory if it is not there.
	if err := os.MkdirAll(dirs.SnapConfineAppArmorDir, 0755); err != nil {
		return false, fmt.Errorf("cannot create snap-confine policy directory: %s", err)
	}

	policy := make(map[string]osutil.FileState)

	// Check if NFS is mounted at or under $HOME. Because NFS is not
	// transparent to apparmor we must alter our profile to counter that and
	// allow snap-confine to work.
	if nfs, err := osutilIsHomeUsingNFS(); err != nil {
		logger.Noticef("cannot determine if NFS is in use: %v", err)
	} else if nfs {
		policy["nfs-support"] = &osutil.MemoryFileState{
			Content: []byte(NfsSnippet),
			Mode:    0644,
		}
		logger.Noticef("snapd enabled NFS support, additional implicit network permissions granted")
	}

	// Check if '/' is on overlayfs. If so, add the necessary rules for
	// upperdir and allow snap-confine to work.
	if overlayRoot, err := osutilIsRootWritableOverlay(); err != nil {
		logger.Noticef("cannot determine if root filesystem on overlay: %v", err)
	} else if overlayRoot != "" {
		snippet := strings.Replace(OverlayRootSnippet, "###UPPERDIR###", overlayRoot, -1)
		policy["overlay-root"] = &osutil.MemoryFileState{
			Content: []byte(snippet),
			Mode:    0644,
		}
		logger.Noticef("snapd enabled root filesystem on overlay support, additional upperdir permissions granted")
	}

	// Check whether apparmor_parser supports bpf capability. Some older
	// versions do not, hence the capability cannot be part of the default
	// profile of snap-confine as loading it would fail.
	if features, err := ParserFeatures(); err != nil {
		logger.Noticef("cannot determine apparmor_parser features: %v", err)
	} else if strutil.ListContains(features, "cap-bpf") {
		policy["cap-bpf"] = &osutil.MemoryFileState{
			Content: []byte(capabilityBPFSnippet),
			Mode:    0644,
		}
	}

	// Ensure that generated policy is what we computed above.
	created, removed, err := osutil.EnsureDirState(dirs.SnapConfineAppArmorDir, "*", policy)
	if err != nil {
		return false, fmt.Errorf("cannot synchronize snap-confine policy: %s", err)
	}
	return len(created) > 0 || len(removed) > 0, nil
}

// RemoveSnapConfineSnippets clears out any previously written apparmor snippets
// for snap-confine.
func RemoveSnapConfineSnippets() error {
	_, _, err := osutil.EnsureDirState(dirs.SnapConfineAppArmorDir, "*", nil)
	return err
}
