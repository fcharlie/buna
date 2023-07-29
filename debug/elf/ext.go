package elf

import (
	"errors"
	"fmt"
	"io"
)

// error
var (
	ErrNoOverlayFound = errors.New("elf: not have overlay data")
)

// Overlay returns the overlay of the ELF file (i.e. any optional bytes directly
// succeeding the image).
func (f *File) Overlay() ([]byte, error) {
	sr, ok := f.originalReader.(io.Seeker)
	if !ok {
		return nil, errors.New("elf: reader not a io.Seeker")
	}
	overlayEnd, err := sr.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("elf: seek %v", err)
	}
	overlayLen := overlayEnd - int64(f.OverlayOffset)
	overlay := make([]byte, overlayLen)
	ser := io.NewSectionReader(f.originalReader, int64(f.OverlayOffset), overlayLen)
	if _, err := io.ReadFull(ser, overlay); err != nil {
		return nil, err
	}
	return overlay, nil
}

// NewOverlayReader create a new ReaderAt for read ELF overlay data
func (f *File) NewOverlayReader() (io.ReaderAt, error) {
	if f.originalReader == nil {
		return nil, errors.New("elf: file reader is nil")
	}
	if f.OverlayOffset == 0 {
		return nil, ErrNoOverlayFound
	}
	return io.NewSectionReader(f.originalReader, int64(f.OverlayOffset), 1<<63-1), nil
}
