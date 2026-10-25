package wire_test

import (
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

func oneFrame(t *testing.T, body int) []byte {
	t.Helper()
	prelude := wire.BuildHeader(0, wire.MsgCheckin, wire.SuiteAES256GCM, body)
	frame := make([]byte, 0, wire.FrameLen(body))
	frame = append(frame, prelude[:]...)
	frame = append(frame, make([]byte, wire.NonceLen+body+wire.TagLen)...)
	return frame
}

func TestSplitFramesHandlesConcatenatedFrames(t *testing.T) {
	a, b, c := oneFrame(t, 3), oneFrame(t, 0), oneFrame(t, 1024)
	joined := append(append(append([]byte{}, a...), b...), c...)

	frames, err := wire.SplitFrames(joined)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
	for i, want := range [][]byte{a, b, c} {
		if len(frames[i]) != len(want) {
			t.Fatalf("frame %d: got %d bytes, want %d", i, len(frames[i]), len(want))
		}
	}

	// An empty buffer is not an error (it means "no frames"), but a trailing
	// partial frame must be refused instead of dropped.
	if frames, err := wire.SplitFrames(nil); err != nil || len(frames) != 0 {
		t.Fatalf("empty buffer: %v %d", err, len(frames))
	}
	if _, err := wire.SplitFrames(joined[:len(joined)-1]); err == nil {
		t.Fatal("truncated frame accepted")
	}
	if _, err := wire.SplitFrames(append(append([]byte{}, a...), 0x00, 0x01)); err == nil {
		t.Fatal("garbage tail accepted")
	}
}
