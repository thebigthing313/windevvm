// Package diskimg converts Ubuntu's qcow2 cloud image into a VHD that
// Hyper-V can import, without external tools.
package diskimg

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const qcowMagic = 0x514649fb // "QFI\xfb"

// Incompatible feature bits we can't handle.
const (
	incompatExternalData = 1 << 2
	incompatCompression  = 1 << 3
	incompatExtendedL2   = 1 << 4
)

type qcowHeader struct {
	Magic                 uint32
	Version               uint32
	BackingFileOffset     uint64
	BackingFileSize       uint32
	ClusterBits           uint32
	Size                  uint64
	CryptMethod           uint32
	L1Size                uint32
	L1TableOffset         uint64
	RefcountTableOffset   uint64
	RefcountTableClusters uint32
	NbSnapshots           uint32
	SnapshotsOffset       uint64
}

type qcowV3 struct {
	IncompatibleFeatures uint64
	CompatibleFeatures   uint64
	AutoclearFeatures    uint64
	RefcountOrder        uint32
	HeaderLength         uint32
}

// QcowToRaw writes the guest contents of a qcow2 image to w (which must
// support seeking, so unallocated clusters can be skipped) and returns the
// virtual disk size. Supports v2 and v3 images with zlib-compressed and
// uncompressed clusters and no backing file, which is what Ubuntu publishes.
func QcowToRaw(src io.ReaderAt, w io.WriterAt) (int64, error) {
	var h qcowHeader
	if err := binary.Read(io.NewSectionReader(src, 0, 72), binary.BigEndian, &h); err != nil {
		return 0, fmt.Errorf("read qcow2 header: %w", err)
	}
	if h.Magic != qcowMagic {
		return 0, errors.New("not a qcow2 image")
	}
	if h.Version != 2 && h.Version != 3 {
		return 0, fmt.Errorf("unsupported qcow2 version %d", h.Version)
	}
	if h.BackingFileOffset != 0 {
		return 0, errors.New("qcow2 images with a backing file are not supported")
	}
	if h.CryptMethod != 0 {
		return 0, errors.New("encrypted qcow2 images are not supported")
	}
	if h.ClusterBits < 9 || h.ClusterBits > 21 {
		return 0, fmt.Errorf("bad cluster size 2^%d", h.ClusterBits)
	}
	if h.Version == 3 {
		var v3 qcowV3
		if err := binary.Read(io.NewSectionReader(src, 72, 32), binary.BigEndian, &v3); err != nil {
			return 0, err
		}
		if bad := v3.IncompatibleFeatures & (incompatExternalData | incompatCompression | incompatExtendedL2); bad != 0 {
			return 0, fmt.Errorf("unsupported qcow2 features %#x", bad)
		}
	}

	clusterSize := int64(1) << h.ClusterBits
	l2Entries := clusterSize / 8
	csizeShift := 62 - (h.ClusterBits - 8)
	csizeMask := uint64(1)<<(h.ClusterBits-8) - 1
	offsetMask := uint64(0x00fffffffffffe00)

	l1 := make([]uint64, h.L1Size)
	if err := binary.Read(io.NewSectionReader(src, int64(h.L1TableOffset), int64(h.L1Size)*8), binary.BigEndian, l1); err != nil {
		return 0, fmt.Errorf("read L1 table: %w", err)
	}

	l2 := make([]uint64, l2Entries)
	cluster := make([]byte, clusterSize)
	var comp []byte
	for i, l1e := range l1 {
		l2off := l1e & offsetMask
		if l2off == 0 {
			continue
		}
		if err := binary.Read(io.NewSectionReader(src, int64(l2off), clusterSize), binary.BigEndian, l2); err != nil {
			return 0, fmt.Errorf("read L2 table %d: %w", i, err)
		}
		for j, e := range l2 {
			guest := (int64(i)*l2Entries + int64(j)) * clusterSize
			if guest >= int64(h.Size) {
				break
			}
			n := min(clusterSize, int64(h.Size)-guest)
			switch {
			case e&(1<<62) != 0: // compressed
				hostOff := e & (uint64(1)<<csizeShift - 1)
				sectors := (e>>csizeShift)&csizeMask + 1
				clen := int64(sectors)*512 - int64(hostOff&511)
				if cap(comp) < int(clen) {
					comp = make([]byte, clen)
				}
				comp = comp[:clen]
				// The last compressed cluster may end before the sector count says.
				if _, err := src.ReadAt(comp, int64(hostOff)); err != nil && err != io.EOF {
					return 0, fmt.Errorf("read compressed cluster at %d: %w", hostOff, err)
				}
				fr := flate.NewReader(bytes.NewReader(comp))
				if _, err := io.ReadFull(fr, cluster[:n]); err != nil {
					return 0, fmt.Errorf("inflate cluster at guest offset %d: %w", guest, err)
				}
				fr.Close()
			case h.Version == 3 && e&1 != 0: // reads as zeros
				continue
			default:
				hostOff := e & offsetMask
				if hostOff == 0 { // unallocated, no backing file: zeros
					continue
				}
				if _, err := src.ReadAt(cluster[:n], int64(hostOff)); err != nil {
					return 0, fmt.Errorf("read cluster at %d: %w", hostOff, err)
				}
			}
			if allZero(cluster[:n]) {
				continue
			}
			if _, err := w.WriteAt(cluster[:n], guest); err != nil {
				return 0, err
			}
		}
	}
	return int64(h.Size), nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// QcowToVHD converts a qcow2 file to a fixed VHD (raw data plus a footer).
func QcowToVHD(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	size, err := QcowToRaw(src, dst)
	if err == nil {
		err = AppendVHDFooter(dst, size)
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dstPath)
	}
	return err
}
