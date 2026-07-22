//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package endpoints

import (
	"errors"
	"fmt"
	"os"

	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/sys/unix"
)

type fileMetadata struct {
	identity fileIdentity
	mode     uint32
	owner    uint32
	group    uint32
}

type metadataChange struct {
	path          string
	file          *endpointFile
	parentBefore  fileMetadata
	socketBefore  *fileMetadata
	directoryMode uint32
	socketMode    uint32
	group         *uint32
	postCommit    bool
}

// prepareActiveSocket validates the pinned endpoint inode. An access-group
// change only revokes group access during preparation; candidate access is
// granted by metadataChange.commit after the policy snapshot commits.
func prepareActiveSocket(consumer runtime.Consumer, file *endpointFile, groupChanged bool) (*metadataChange, error) {
	if err := validateConsumerFilesystemInputs(consumer); err != nil {
		return nil, err
	}
	parent, socket, err := inspectActiveFile(file)
	if err != nil {
		return nil, err
	}
	directoryMode, socketMode, group := desiredPermissions(consumer)
	change := &metadataChange{
		path:          consumer.Socket(),
		file:          file,
		parentBefore:  parent,
		socketBefore:  &socket,
		directoryMode: directoryMode,
		socketMode:    socketMode,
		group:         cloneGroup(group),
		postCommit:    groupChanged,
	}
	if groupChanged {
		if err := applyDirectoryPermissions(file.parent.fd, 0o700, nil); err != nil {
			return nil, errors.Join(err, change.rollback())
		}
		if err := applyAtPermissions(file.parent.fd, file.name, 0o600, nil); err != nil {
			return nil, errors.Join(err, change.rollback())
		}
		return change, nil
	}
	if err := change.applyDesired(); err != nil {
		return nil, errors.Join(err, change.rollback())
	}
	return change, nil
}

func validateConsumerFilesystemInputs(consumer runtime.Consumer) error {
	if len(consumer.Socket()) > maximumUnixSocketPathBytes {
		return errors.New("consumer socket path exceeds Linux AF_UNIX pathname limit")
	}
	_, _, group := desiredPermissions(consumer)
	return validateAccessGroup(group)
}

func desiredPermissions(consumer runtime.Consumer) (directoryMode uint32, socketMode uint32, group *uint32) {
	if accessGroup, exists := consumer.AccessGroup(); exists {
		return 0o710, 0o660, &accessGroup
	}
	return 0o700, 0o600, nil
}

func cloneGroup(group *uint32) *uint32 {
	if group == nil {
		return nil
	}
	value := *group
	return &value
}

func validateAccessGroup(group *uint32) error {
	if group == nil || *group == uint32(os.Getegid()) {
		return nil
	}
	groups, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("inspect daemon access groups: %w", err)
	}
	for _, candidate := range groups {
		if candidate >= 0 && uint32(candidate) == *group {
			return nil
		}
	}
	return errors.New("daemon user is not a member of the configured access group")
}

func inspectActiveFile(file *endpointFile) (fileMetadata, fileMetadata, error) {
	if file == nil || file.parent == nil {
		return fileMetadata{}, fileMetadata{}, errors.New("active consumer file handle is absent")
	}
	parent, err := statFD(file.parent.fd)
	if err != nil {
		return fileMetadata{}, fileMetadata{}, fmt.Errorf("inspect pinned consumer parent: %w", err)
	}
	if parent.identity != file.parent.identity || parent.mode&unix.S_IFMT != unix.S_IFDIR || parent.owner != uint32(os.Geteuid()) {
		return fileMetadata{}, fileMetadata{}, errors.New("pinned consumer parent identity or ownership changed")
	}
	socket, err := statAt(file.parent.fd, file.name)
	if err != nil {
		return fileMetadata{}, fileMetadata{}, fmt.Errorf("inspect active consumer socket: %w", err)
	}
	if socket.mode&unix.S_IFMT != unix.S_IFSOCK || socket.identity != file.identity || socket.owner != uint32(os.Geteuid()) {
		return fileMetadata{}, fileMetadata{}, errors.New("active consumer socket identity or ownership changed")
	}
	return parent, socket, nil
}

func applyDirectoryPermissions(fd int, mode uint32, group *uint32) error {
	if group != nil {
		if err := unix.Fchown(fd, -1, int(*group)); err != nil {
			return fmt.Errorf("assign consumer parent group: %w", err)
		}
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return fmt.Errorf("set consumer parent mode: %w", err)
	}
	metadata, err := statFD(fd)
	if err != nil {
		return fmt.Errorf("verify consumer parent permissions: %w", err)
	}
	if metadata.mode&0o7777 != mode || group != nil && metadata.group != *group {
		return errors.New("consumer parent permissions did not apply exactly")
	}
	return nil
}

func applyAtPermissions(directoryFD int, name string, mode uint32, group *uint32) error {
	if group != nil {
		if err := unix.Fchownat(directoryFD, name, -1, int(*group), unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("assign consumer socket group: %w", err)
		}
	}
	if err := unix.Fchmodat(directoryFD, name, mode, 0); err != nil {
		return fmt.Errorf("set consumer socket mode: %w", err)
	}
	metadata, err := statAt(directoryFD, name)
	if err != nil {
		return fmt.Errorf("verify consumer socket permissions: %w", err)
	}
	if metadata.mode&0o7777 != mode || group != nil && metadata.group != *group {
		return errors.New("consumer socket permissions did not apply exactly")
	}
	return nil
}

func (change *metadataChange) applyDesired() error {
	if err := applyDirectoryPermissions(change.file.parent.fd, change.directoryMode, change.group); err != nil {
		return err
	}
	return applyAtPermissions(change.file.parent.fd, change.file.name, change.socketMode, change.group)
}

func (change *metadataChange) filePath() string {
	return change.path
}

func (change *metadataChange) commit() error {
	if change == nil || !change.postCommit {
		return nil
	}
	return change.applyDesired()
}

func (change *metadataChange) rollback() error {
	if change == nil || change.file == nil || change.file.parent == nil {
		return nil
	}
	currentParent, err := statFD(change.file.parent.fd)
	if err != nil {
		return fmt.Errorf("inspect consumer parent for metadata rollback: %w", err)
	}
	if currentParent.identity != change.parentBefore.identity {
		return errors.New("consumer parent identity changed before metadata rollback")
	}
	var result error
	if change.socketBefore != nil {
		current, statErr := statAt(change.file.parent.fd, change.file.name)
		if statErr != nil {
			result = errors.Join(result, fmt.Errorf("inspect consumer socket for metadata rollback: %w", statErr))
		} else if current.identity != change.socketBefore.identity {
			result = errors.Join(result, errors.New("consumer socket identity changed before metadata rollback"))
		} else {
			result = errors.Join(result, restoreAtMetadata(change.file.parent.fd, change.file.name, current, *change.socketBefore))
		}
	}
	result = errors.Join(result, restoreFDMetadata(change.file.parent.fd, currentParent, change.parentBefore))
	return result
}

func restoreAtMetadata(fd int, name string, current, target fileMetadata) error {
	var result error
	if current.group != target.group {
		result = errors.Join(result, unix.Fchownat(fd, name, -1, int(target.group), unix.AT_SYMLINK_NOFOLLOW))
	}
	if current.mode&0o7777 != target.mode&0o7777 {
		result = errors.Join(result, unix.Fchmodat(fd, name, target.mode&0o7777, 0))
	}
	return result
}

func restoreFDMetadata(fd int, current, target fileMetadata) error {
	var result error
	if current.group != target.group {
		result = errors.Join(result, unix.Fchown(fd, -1, int(target.group)))
	}
	if current.mode&0o7777 != target.mode&0o7777 {
		result = errors.Join(result, unix.Fchmod(fd, target.mode&0o7777))
	}
	return result
}

func statFD(fd int) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(stat), nil
}

func statAt(directoryFD int, name string) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(stat), nil
}

func metadataFromStat(stat unix.Stat_t) fileMetadata {
	return fileMetadata{
		identity: fileIdentity{device: uint64(stat.Dev), inode: stat.Ino},
		mode:     stat.Mode,
		owner:    stat.Uid,
		group:    stat.Gid,
	}
}
