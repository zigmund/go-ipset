/*
Copyright 2015 Jan Broer All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ipset is a library providing a wrapper to the IPtables ipset userspace utility
package ipset

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/go-semver/semver"
	log "github.com/sirupsen/logrus"
)

const (
	minIpsetVersion = "6.0.0"
	maxNameLen      = 31 // IPSET_MAXNAMELEN without trailing zero
	tempSuffix      = "-temp"
)

var (
	ipsetPath            string
	errIpsetNotFound     = errors.New("Ipset utility not found")
	errIpsetNotSupported = errors.New("Ipset utility version is not supported, requiring version >= 6.0")
)

// Params defines optional parameters for creating a new set.
type Params struct {
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
	// RecreateOnChange makes New replace existing set, if its maxelem or timeout
	// differ from params. Otherwise New fails on such set, because kernel does not
	// allow to change them. Existing set is hot swapped with a new empty set,
	// so iptables rules referencing it are kept, but all entries are lost.
	RecreateOnChange bool
}

// Header describes set properties reported by kernel.
type Header struct {
	Name       string
	HashType   string
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
	MemSize    int
	References int
	Entries    int
}

// IPSet implements an Interface to an set.
type IPSet struct {
	Name       string
	HashType   string
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
}

func initCheck() error {
	if ipsetPath == "" {
		path, err := exec.LookPath("ipset")
		if err != nil {
			return errIpsetNotFound
		}
		ipsetPath = path
		supportedVersion, err := getIpsetSupportedVersion()
		if err != nil {
			log.Warnf("Error checking ipset version, assuming version at least 6.0.0: %v", err)
			supportedVersion = true
		}
		if supportedVersion {
			return nil
		}
		return errIpsetNotSupported
	}
	return nil
}

func (s *IPSet) createHashSet(name string) error {
	/*	out, err := exec.Command("/usr/bin/sudo",
		ipsetPath, "create", name, s.HashType, "family", s.HashFamily, "hashsize", strconv.Itoa(s.HashSize),
		"maxelem", strconv.Itoa(s.MaxElem), "timeout", strconv.Itoa(s.Timeout), "-exist").CombinedOutput()*/
	out, err := exec.Command(ipsetPath, "create", name, s.HashType, "family", s.HashFamily, "hashsize", strconv.Itoa(s.HashSize),
		"maxelem", strconv.Itoa(s.MaxElem), "timeout", strconv.Itoa(s.Timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating ipset %s with type %s: %v (%s)", name, s.HashType, err, out)
	}

	return nil
}

// New creates a new set and returns an Interface to it.
// Example:
//
//	testIpset := ipset.New("test", "hash:ip", &ipset.Params{})
func New(name string, hashtype string, p *Params) (*IPSet, error) {
	// Using the ipset utilities default values here
	if p.HashSize == 0 {
		p.HashSize = 1024
	}

	if p.MaxElem == 0 {
		p.MaxElem = 65536
	}

	if p.HashFamily == "" {
		p.HashFamily = "inet"
	}

	// Check if hashtype is a type of hash
	if !strings.HasPrefix(hashtype, "hash:") {
		return nil, fmt.Errorf("not a hash type: %s", hashtype)
	}

	if err := initCheck(); err != nil {
		return nil, err
	}

	s := IPSet{name, hashtype, p.HashFamily, p.HashSize, p.MaxElem, p.Timeout}

	if p.RecreateOnChange {
		// Error means that set does not exist, or will be reported by create below
		if h, err := ListHeader(name); err == nil && (h.MaxElem != s.MaxElem || h.Timeout != s.Timeout) {
			log.Infof("Recreating set %s: maxelem %d -> %d, timeout %d -> %d", name, h.MaxElem, s.MaxElem, h.Timeout, s.Timeout)
			if err = s.swapIn(nil); err != nil {
				return nil, err
			}
		}
	}

	err := s.createHashSet(name)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Refresh is used to to overwrite the set with the specified entries.
// The ipset is updated on the fly by hot swapping it with a temporary set.
func (s *IPSet) Refresh(entries []string) error {
	return s.swapIn(entries)
}

// swapIn creates a temporary set with the set parameters, fills it with entries
// and hot swaps it with the set. Old set content is destroyed with the temporary set.
func (s *IPSet) swapIn(entries []string) error {
	tempName := tempSetName(s.Name)
	// Leftover from interrupted swap, if any
	_ = destroyIPSet(tempName)

	err := s.createHashSet(tempName)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		out, err := exec.Command(ipsetPath, "add", tempName, entry, "-exist").CombinedOutput()
		if err != nil {
			log.Errorf("error adding entry %s to set %s: %v (%s)", entry, tempName, err, out)
		}
	}
	err = Swap(tempName, s.Name)
	if err != nil {
		_ = destroyIPSet(tempName)
		return err
	}
	return destroyIPSet(tempName)
}

// tempSetName returns temporary set name, which fits the set name length limit.
func tempSetName(name string) string {
	if len(name) > maxNameLen-len(tempSuffix) {
		name = name[:maxNameLen-len(tempSuffix)]
	}
	return name + tempSuffix
}

// Test is used to check whether the specified entry is in the set or not.
func (s *IPSet) Test(entry string) (bool, error) {
	out, err := exec.Command(ipsetPath, "test", s.Name, entry).CombinedOutput()
	if err == nil {
		reg, e := regexp.Compile("NOT")
		if e == nil && reg.MatchString(string(out)) {
			return false, nil
		} else if e == nil {
			return true, nil
		} else {
			return false, fmt.Errorf("error testing entry %s: %v", entry, e)
		}
	} else {
		return false, fmt.Errorf("error testing entry %s: %v (%s)", entry, err, out)
	}
}

// Add is used to add the specified entry to the set.
// A timeout of 0 means that the entry will be stored permanently in the set.
func (s *IPSet) Add(entry string, timeout int) error {
	out, err := exec.Command(ipsetPath, "add", s.Name, entry, "timeout", strconv.Itoa(timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding entry %s: %v (%s)", entry, err, out)
	}
	return nil
}

// AddOption is used to add the specified entry to the set.
// A timeout of 0 means that the entry will be stored permanently in the set.
func (s *IPSet) AddOption(entry string, option string, timeout int) error {
	out, err := exec.Command(ipsetPath, "add", s.Name, entry, option, "timeout", strconv.Itoa(timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding entry %s with option %s : %v (%s)", entry, option, err, out)
	}
	return nil
}

// Del is used to delete the specified entry from the set.
func (s *IPSet) Del(entry string) error {
	out, err := exec.Command(ipsetPath, "del", s.Name, entry, "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting entry %s: %v (%s)", entry, err, out)
	}
	return nil
}

// Flush is used to flush all entries in the set.
func (s *IPSet) Flush() error {
	out, err := exec.Command(ipsetPath, "flush", s.Name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error flushing set %s: %v (%s)", s.Name, err, out)
	}
	return nil
}

// List is used to show the contents of a set
func (s *IPSet) List() ([]string, error) {
	out, err := exec.Command(ipsetPath, "list", s.Name).CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("error listing set %s: %v (%s)", s.Name, err, out)
	}
	r := regexp.MustCompile("(?m)^(.*\n)*Members:\n")
	list := strings.TrimSuffix(r.ReplaceAllString(string(out[:]), ""), "\n")
	if list == "" {
		return []string{}, nil
	}
	return strings.Split(list, "\n"), nil
}

// Header is used to show the set properties without its entries.
func (s *IPSet) Header() (*Header, error) {
	return ListHeader(s.Name)
}

// ListHeader is used to show properties of the set with the specified name without its entries.
func ListHeader(name string) (*Header, error) {
	if err := initCheck(); err != nil {
		return nil, err
	}
	out, err := exec.Command(ipsetPath, "list", "-t", name).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error listing set %s: %v (%s)", name, err, bytes.TrimSpace(out))
	}
	return parseHeader(out)
}

// parseHeader parses `ipset list -t` output:
//
//	Name: test
//	Type: hash:ip
//	Revision: 4
//	Header: family inet hashsize 1024 maxelem 65536 timeout 3600
//	Size in memory: 88
//	References: 1
//	Number of entries: 0
func parseHeader(out []byte) (*Header, error) {
	var (
		h                     Header
		hasHeader, hasEntries bool
	)

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)

		var err error
		switch key {
		case "Name":
			h.Name = value
		case "Type":
			h.HashType = value
		case "Header":
			hasHeader = true
			// Options may be flags without value (counters, comment, ...), so only known ones are parsed
			fields := strings.Fields(value)
			for i := 0; i+1 < len(fields) && err == nil; i++ {
				switch fields[i] {
				case "family":
					h.HashFamily = fields[i+1]
				case "hashsize":
					h.HashSize, err = strconv.Atoi(fields[i+1])
				case "maxelem":
					h.MaxElem, err = strconv.Atoi(fields[i+1])
				case "timeout":
					h.Timeout, err = strconv.Atoi(fields[i+1])
				}
			}
		case "Size in memory":
			h.MemSize, err = strconv.Atoi(value)
		case "References":
			h.References, err = strconv.Atoi(value)
		case "Number of entries":
			hasEntries = true
			h.Entries, err = strconv.Atoi(value)
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing set header line %q: %v", sc.Text(), err)
		}
	}

	if !hasHeader || !hasEntries {
		return nil, fmt.Errorf("unexpected ipset list output: %q", out)
	}
	return &h, nil
}

// Destroy is used to destroy the set.
func (s *IPSet) Destroy() error {
	out, err := exec.Command(ipsetPath, "destroy", s.Name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error destroying set %s: %v (%s)", s.Name, err, out)
	}
	return nil
}

// DestroyAll is used to destroy the set.
func DestroyAll() error {
	initCheck()
	out, err := exec.Command(ipsetPath, "destroy").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error destroying set %s (%s)", err, out)
	}
	return nil
}

// Swap is used to hot swap two sets on-the-fly. Use with names of existing sets of the same type.
func Swap(from, to string) error {
	if err := initCheck(); err != nil {
		return err
	}
	out, err := exec.Command(ipsetPath, "swap", from, to).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error swapping ipset %s to %s: %v (%s)", from, to, err, out)
	}
	return nil
}

func destroyIPSet(name string) error {
	out, err := exec.Command(ipsetPath, "destroy", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error destroying ipset %s: %v (%s)", name, err, out)
	}
	return nil
}

func destroyAll() error {
	out, err := exec.Command(ipsetPath, "destroy").Output()
	if err != nil {
		return fmt.Errorf("error destroying all ipsetz %s (%s)", err, out)
	}
	return nil
}

func getIpsetSupportedVersion() (bool, error) {
	minVersion, err := semver.NewVersion(minIpsetVersion)
	if err != nil {
		return false, err
	}
	// Returns "vX.Y".
	vstring, err := getIpsetVersionString()
	if err != nil {
		return false, err
	}
	// Make a dotted-tri format version string
	vstring = vstring + ".0"
	// Make a semver of the part after the v in "vX.X.X".
	version, err := semver.NewVersion(vstring[1:])
	if err != nil {
		return false, err
	}
	if version.LessThan(*minVersion) {
		return false, nil
	}
	return true, nil
}

func getIpsetVersionString() (string, error) {
	bytes, err := exec.Command(ipsetPath, "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	versionMatcher := regexp.MustCompile("v[0-9]+\\.[0-9]+")
	match := versionMatcher.FindStringSubmatch(string(bytes))
	if match == nil {
		return "", fmt.Errorf("no ipset version found in string: %s", bytes)
	}
	return match[0], nil
}
