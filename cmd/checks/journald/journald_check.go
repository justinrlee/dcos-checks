// Copyright © 2017 Mesosphere Inc. <http://mesosphere.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package journald

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/dcos/dcos-checks/common"
	"github.com/dcos/dcos-checks/constants"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	groupReadBit = 1 << 5
	groupExecBit = 1 << 3
	otherReadBit = 1 << 2
	otherExecBit = 1 << 0

	// systemdJournalGroup is a linux system group.
	systemdJournalGroup = "systemd-journal"
)

type (
	checkDirectoryFn func(string, uint32, map[string]uint32, map[string]uint32) error
)

// journalCheck validates that the journal folder has he correct permissions and owners.
type journalCheck struct {
	Path string

	lookupGroup grp
	checkGroupBits   map[string]uint32
	checkOtherBits   map[string]uint32

	checkDirFn checkDirectoryFn
}

// journaldCmd represents the journald command
var journaldCmd = &cobra.Command{
	Use:   "journald",
	Short: "Check journal folder ownership and permissions",
	Long: `Check if users in the systemd-journal group have r-x permissions on the journal folder.

If a user does not set the --path parameter, check will try to use default locations:
 - /var/log/journal
 - /run/log/journal
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if userJournalPath == "" {
			var err error
			userJournalPath, err = getJournalPath(systemJournalPaths)
			if err != nil {
				logrus.Fatal(err)
			}
		}

		common.RunCheck(context.TODO(), newJournalCheck(userJournalPath))
	},
}

var (
	// the default location for journal is /var/log/journal, however if the folder is there,
	// journald will write to /run/log/journal in a nonpersistent way.
	systemJournalPaths = []string{"/var/log/journal", "/run/log/journal"}

	userJournalPath string
)

// Add adds this command to the root command
func Add(root *cobra.Command) {
	root.AddCommand(journaldCmd)
	journaldCmd.Flags().StringVarP(&userJournalPath, "path", "p", "",
		"Set a path to systemd journal binary log directory.")
}

func (j *journalCheck) checkDirectory(path string, group uint32, groupBits map[string]uint32, 
		otherBits map[string]uint32) error {
	dirStat, err := os.Stat(path)
	if err != nil {
		return err
	}

	helpMsg := fmt.Sprintf("\nTry to run: systemd-tmpfiles --create --prefix %s", path)

	perm := dirStat.Mode().Perm()
	logrus.Debugf("folder %s full permissions: %s", path, perm)

	var otherError error = nil
	var groupError error = nil

	stat, ok := dirStat.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unable to type assert to syscall.Stat_t")
	}

	for description, bit := range otherBits {
		if uint32(perm)&bit == 0 {
			// otherValid = false
			otherError = errors.Errorf("directory %s has wrong permissions: %s bit must be set. \n%s",
				path, description, helpMsg)
		}
	}

	for description, bit := range groupBits {
		if uint32(perm)&bit == 0 {
			// groupValid = false
			groupError = errors.Errorf("directory %s has wrong permissions: %s bit must be set. \n%s",
				path, description, helpMsg)
		}
	}

	if stat.Gid != group {
		// groupValid = false
		groupError = errors.Errorf("directory %s must be in group with Gid %d.%s", path, group, helpMsg)
	} else {
		logrus.Debug("directory is in the right group")
	}

	if otherError != nil {
		return groupError
	}

	return otherError
}

// ID returns a unique check identifier.
func (j *journalCheck) ID() string {
	return "systemd journal check"
}

// Run the journal check.
func (j *journalCheck) Run(ctx context.Context, cfg *common.CLIConfigFlags) (string, int, error) {
	if j.Path == "" {
		return "", constants.StatusUnknown, errors.New("journald path is not set")
	}

	var err error
	gid, err := j.lookupGroup.gid()
	if err != nil {
		return "", 0, err
	}

	err = j.checkDirFn(j.Path, gid, j.checkGroupBits, j.checkOtherBits)
	if err != nil {
		return "", constants.StatusUnknown, err
	}

	return fmt.Sprintf("Users in group `systemd-journal` have r-x permissions on directory %s", j.Path),
		constants.StatusOK, nil
}

// newJournalCheck returns an initialized instance of journalCheck.
func newJournalCheck(p string) common.DCOSChecker {
	j := &journalCheck{
		Path: p,
		lookupGroup: grp{
			name: systemdJournalGroup,
		},

		checkGroupBits: map[string]uint32{
			"group r--": groupReadBit,
			"group --x": groupExecBit,
		},

		checkOtherBits: map[string]uint32{
			"group r--": otherReadBit,
			"group --x": otherExecBit,
		},
	}

	j.checkDirFn = j.checkDirectory

	return j
}

func getJournalPath(paths []string) (string, error) {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", errors.Errorf("journal paths %s do not exist", paths)
}
