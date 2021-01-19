package pe

import (
	"errors"
	"fmt"
	"io"
)

// error
var (
	ErrNoOverlayFound = errors.New("no overlay found")
)

// NewOverlayReader todo
func (file *File) NewOverlayReader() (io.ReaderAt, error) {
	if file.r == nil {
		return nil, errors.New("internal bug")
	}
	return io.NewSectionReader(file.r, file.OverlayOffset, 1<<63-1), nil
}

// Overlay returns the overlay of the PE fil (i.e. any optional bytes directly
// succeeding the image).
func (file *File) Overlay() ([]byte, error) {
	sr, ok := file.r.(io.Seeker)
	if !ok {
		return nil, errors.New("io.ReaderAt not  io.Seeker")
	}
	overlayEnd, err := sr.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("pe: seek %v", err)
	}
	overlayLen := overlayEnd - file.OverlayOffset
	overlay := make([]byte, overlayLen)
	ser := io.NewSectionReader(file.r, file.OverlayOffset, overlayLen)
	if _, err := io.ReadFull(ser, overlay); err != nil {
		return nil, err
	}
	return overlay, nil
}
