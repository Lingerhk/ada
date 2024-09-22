package util

import (
	"bytes"
	"fmt"
	"io"
	"rsc.io/qr"
	"strings"
)

func writeSixel(w io.Writer, code *qr.Code) {
	// Sixel Support Control Sequence
	// Color 0: Black Color 1: White
	const SIXEL_BEGIN = "\x1bPq\n#0;2;0;0;0#1;2;100;100;100\n"
	const SIXEL_END = "\x1b\\"

	// Sixel Block Size, should be always greater than 6.
	const SIXEL_BLOCK_SIZE = 12

	size := SIXEL_BLOCK_SIZE
	if code.Size > 50 {
		size /= 2
	}
	line := size / 6
	// Frame the barcode in a 1 pixel border
	w.Write([]byte(SIXEL_BEGIN))
	w.Write([]byte(stringRepeat(fmt.Sprintf("#1!%d~-\n", size*(code.Size+2)), line))) // top border
	for i := 0; i <= code.Size; i++ {
		flag := -1
		repeat := 0
		content := bytes.NewBufferString("")
		content.WriteString(fmt.Sprintf("#1!%d~", size)) // left border

		for j := 0; j <= code.Size; j++ {
			if code.Black(j, i) {
				if flag == 1 {
					content.WriteString(fmt.Sprintf("#1!%d~", size*repeat))
					repeat = 0
				}
				flag = 0
				repeat++
			} else {
				if flag == 0 {
					content.WriteString(fmt.Sprintf("#0!%d~", size*repeat))
					repeat = 0
				}
				flag = 1
				repeat++
			}
		}
		if repeat > 0 {
			content.WriteString(fmt.Sprintf("#%d!%d~", flag, size*repeat))
		}
		content.WriteString("-\n")
		for i := 0; i < line; i++ {
			w.Write(content.Bytes())
		}
	}
	w.Write([]byte(stringRepeat(fmt.Sprintf("#1!%d~-\n", size*(code.Size+2)), 0))) // bottom border
	defer w.Write([]byte(SIXEL_END))
}

func stringRepeat(s string, count int) string {
	if count <= 0 {
		return ""
	}
	return strings.Repeat(s, count)
}

// GenerateQR expects a string to encode and a config
func GenerateQR(text string, buf io.Writer) {
	code, _ := qr.Encode(text, qr.M)
	writeSixel(buf, code)
}
