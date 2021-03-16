package pe

import (
	"errors"
	"fmt"
	"io"
)

// error
var (
	ErrNoOverlayFound = errors.New("pe: not have overlay data")
)

// NewOverlayReader create a new ReaderAt for read PE overlay data
func (f *File) NewOverlayReader() (io.ReaderAt, error) {
	if f.r == nil {
		return nil, errors.New("pe: file reader is nil")
	}
	return io.NewSectionReader(f.r, f.OverlayOffset, 1<<63-1), nil
}

// Overlay returns the overlay of the PE file (i.e. any optional bytes directly
// succeeding the image).
func (f *File) Overlay() ([]byte, error) {
	sr, ok := f.r.(io.Seeker)
	if !ok {
		return nil, errors.New("pe: reader not a io.Seeker")
	}
	overlayEnd, err := sr.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("pe: seek %v", err)
	}
	overlayLen := overlayEnd - f.OverlayOffset
	overlay := make([]byte, overlayLen)
	ser := io.NewSectionReader(f.r, f.OverlayOffset, overlayLen)
	if _, err := io.ReadFull(ser, overlay); err != nil {
		return nil, err
	}
	return overlay, nil
}
