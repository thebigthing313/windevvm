// Package seed builds cloud-init NoCloud seed ISOs (volume label "cidata").
package seed

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

// Files is the seed content, e.g. "user-data", "meta-data", "network-config".
type Files map[string][]byte

// WriteISO writes files into a new ISO 9660 image at path, with Rock Ridge
// and Joliet names so cloud-init sees "user-data" rather than "USER_DAT".
func WriteISO(path string, files Files) error {
	var total int64
	for _, b := range files {
		total += int64(len(b))
	}
	size := total + 1<<20 // room for volume descriptors and directories
	size = (size + 2047) / 2048 * 2048

	work, err := os.MkdirTemp("", "wdvm-seed-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	os.Remove(path)
	d, err := diskfs.Create(path, size, diskfs.SectorSize(2048))
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer d.Close()
	fs, err := d.CreateFilesystem(disk.FilesystemSpec{Partition: 0, FSType: filesystem.TypeISO9660, VolumeLabel: "cidata", WorkDir: work})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := fs.OpenFile("/"+filepath.ToSlash(n), os.O_CREATE|os.O_RDWR)
		if err != nil {
			return fmt.Errorf("add %s: %w", n, err)
		}
		if _, err := f.Write(files[n]); err != nil {
			f.Close()
			return fmt.Errorf("write %s: %w", n, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	iso, ok := fs.(*iso9660.FileSystem)
	if !ok {
		return fmt.Errorf("unexpected filesystem type %T", fs)
	}
	return iso.Finalize(iso9660.FinalizeOptions{RockRidge: true, Joliet: true, VolumeIdentifier: "cidata"})
}
