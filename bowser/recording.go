package bowser

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"
)

type FrameHeader struct {
	Offset int64
	Size   uint64
}

type Recording struct {
	Path string

	// TODO: lock
	recording bool
	start     time.Time
	buff      *bytes.Buffer
	file      *os.File
}

func NewRecording(path string) *Recording {
	return &Recording{
		Path: path,
		buff: new(bytes.Buffer),
	}
}

func (r *Recording) Open() (err error) {
	file, err := os.Create(r.Path)
	if err == nil {
		r.file = file
	}

	r.recording = true
	r.start = time.Now()
	go r.loop()

	return
}

func (r *Recording) loop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	for _ = range ticker.C {
		if !r.recording {
			return
		}
		r.writeFrame()
	}
}

func (r *Recording) Close() {
	r.writeFrame()
	r.file.Close()
}

func (r *Recording) Write(data []byte) {
	r.buff.Write(data)
}

func (r *Recording) writeFrame() {
	if r.buff.Len() == 0 {
		return
	}

	frame := FrameHeader{
		Offset: (time.Now().Sub(r.start)).Nanoseconds(),
		Size:   uint64(r.buff.Len()),
	}

	binary.Write(r.file, binary.BigEndian, &frame)
	r.buff.WriteTo(r.file)
	r.buff.Reset()
}
