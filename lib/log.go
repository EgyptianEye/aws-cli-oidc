package lib

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

var IsTraceEnabled bool = false

func Write(format string, msg ...interface{}) {
	fmt.Fprintf(os.Stderr, format, msg...)
}

func Writeln(format string, msg ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, msg...))
}

func export(kv map[string]string) string {
	prefix := "export "
	suffix := []byte{0x0a}
	if runtime.GOOS == "windows" {
		prefix = "set "
		suffix = append([]byte{0xd}, suffix...)
	}
	var builder strings.Builder
	for k, v := range kv {
		builder.WriteString(prefix)
		builder.WriteString(k)
		builder.WriteByte(0x3d)
		builder.WriteString(v)
		builder.Write(suffix)
	}
	return builder.String()
}

func Traceln(format string, msg ...interface{}) {
	if IsTraceEnabled {
		fmt.Fprintln(os.Stderr, fmt.Sprintf(format, msg...))
	}
}

func Exit(err error) {
	if err != nil {
		Writeln(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
