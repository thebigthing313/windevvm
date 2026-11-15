package diskimg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// AppendVHDFooter turns a raw disk of the given size (a multiple of 512) into
// a fixed VHD by writing the 512-byte footer after the data.
func AppendVHDFooter(w io.WriterAt, size int64) error {
	if size%512 != 0 {
		return fmt.Errorf("disk size %d is not a multiple of 512", size)
	}
	f := vhdFooter(size)
	_, err := w.WriteAt(f, size)
	return err
}

func vhdFooter(size int64) []byte {
	f := make([]byte, 512)
	be := binary.BigEndian
	copy(f[0:8], "conectix")
	be.PutUint32(f[8:], 2)           // features: reserved bit must be set
	be.PutUint32(f[12:], 0x00010000) // format version 1.0
	be.PutUint64(f[16:], ^uint64(0)) // data offset: none for fixed disks
	vhdEpoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	be.PutUint32(f[24:], uint32(time.Since(vhdEpoch)/time.Second))
	copy(f[28:32], "wdvm")
	be.PutUint32(f[32:], 0x00010000)
	copy(f[36:40], "Wi2k")
	be.PutUint64(f[40:], uint64(size)) // original size
	be.PutUint64(f[48:], uint64(size)) // current size
	c, hd, s := chs(size / 512)
	be.PutUint16(f[56:], c)
	f[58], f[59] = hd, s
	be.PutUint32(f[60:], 2) // disk type: fixed
	rand.Read(f[68:84])     // unique id
	var sum uint32
	for _, b := range f {
		sum += uint32(b)
	}
	be.PutUint32(f[64:], ^sum)
	return f
}

// chs computes the CHS geometry for a sector count as the VHD spec describes.
func chs(total int64) (uint16, uint8, uint8) {
	if total > 65535*16*255 {
		total = 65535 * 16 * 255
	}
	var spt, heads, cth int64
	if total >= 65535*16*63 {
		spt, heads = 255, 16
		cth = total / spt
	} else {
		spt = 17
		cth = total / spt
		heads = (cth + 1023) / 1024
		if heads < 4 {
			heads = 4
		}
		if cth >= heads*1024 || heads > 16 {
			spt, heads = 31, 16
			cth = total / spt
		}
		if cth >= heads*1024 {
			spt, heads = 63, 16
			cth = total / spt
		}
	}
	return uint16(cth / heads), uint8(heads), uint8(spt)
}
