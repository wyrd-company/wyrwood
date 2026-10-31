// ---
// relationships:
//
//	implements: agent-controller-protocol
//
// ---
package consumer

import (
	"os"
	"os/user"
	"sort"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// ProcessGroups reports effective and supplementary groups of this process.
// Names are display hints; account membership is never used as authority.
func ProcessGroups() *protocol.AssignableGroups {
	groups, err := os.Getgroups()
	if err != nil {
		return nil
	}
	any, err := canAssignAnyGroup()
	if err != nil {
		return nil
	}
	return processGroups(any, os.Getegid(), groups, user.LookupGroupId)
}

// canAssignAnyGroup reads the running thread's effective Linux capabilities.
// UID alone does not establish permission to change file ownership.
func canAssignAnyGroup() (bool, error) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return false, err
	}
	return data[unix.CAP_CHOWN/32].Effective&(1<<(unix.CAP_CHOWN%32)) != 0, nil
}

func processGroups(any bool, gid int, supplementary []int, lookup func(string) (*user.Group, error)) *protocol.AssignableGroups {
	result := &protocol.AssignableGroups{Any: any, Groups: []protocol.Group{}}
	seen := map[int]bool{}
	for _, id := range append(supplementary, gid) {
		if id < 0 || uint64(id) >= 4294967295 || seen[id] {
			continue
		}
		seen[id] = true
		group := protocol.Group{GID: uint32(id)}
		if entry, err := lookup(strconv.Itoa(id)); err == nil {
			group.Name = entry.Name
		}
		result.Groups = append(result.Groups, group)
	}
	sort.Slice(result.Groups, func(i, j int) bool { return result.Groups[i].GID < result.Groups[j].GID })
	return result
}
