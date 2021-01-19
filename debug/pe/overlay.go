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

// Overlay returns the overlay of the PE fil (i.e. any optional bytes directly
// succeeding the image).
func (file *File) Overlay() ([]byte, error) {
	if file.overlay == nil {
		if err := file.parseOverlay(); err != nil {
			return nil, err
		}
	}
	return file.overlay, nil
}

// parseOverlay parses the overlay of the PE file.
func (file *File) parseOverlay() error {
	if file.r == nil {
		return errors.New("invalid reader")
	}
	// Locate start of overlay (i.e. end of image).
	var overlayStart int64
	for _, s := range file.Sections {
		if sectionStart := int64(s.Offset + s.Size); sectionStart > overlayStart {
			overlayStart = sectionStart
		}
	}
	sr, ok := file.r.(io.Seeker)
	if !ok {
		return errors.New("not seeker")
	}
	overlayEnd, err := sr.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("pe: seek %v", err)
	}
	overlayLen := overlayEnd - overlayStart
	if overlayLen == 0 {
		return ErrNoOverlayFound
	}
	overlay := make([]byte, overlayLen)
	ser := io.NewSectionReader(file.r, overlayStart, overlayLen)
	if _, err := io.ReadFull(ser, overlay); err != nil {
		return err
	}
	file.overlay = overlay
	return nil
}
