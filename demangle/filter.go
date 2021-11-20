package demangle

import (
	"bytes"
	"strings"
)

func isRustEncoding(mangledName string) bool {
	return strings.HasPrefix(mangledName, "_R")
}

func isItaniumEncoding(mangledName string) bool {
	return strings.HasPrefix(mangledName, "_Z") || strings.HasPrefix(mangledName, "___Z")
}

// Demangle a string just as the GNU c++filt program does.
func doItaniumFilter(out *bytes.Buffer, name string) {
	skip := 0
	if name[0] == '.' || name[0] == '$' {
		skip++
	}
	if name[skip] == '_' {
		skip++
	}
	result := Filter(name[skip:])
	if result == name[skip:] {
		out.WriteString(name)
	} else {
		if name[0] == '.' {
			out.WriteByte('.')
		}
		out.WriteString(result)
	}
}

// Demangle demangle todo
func Demangle(name string) string {
	if isItaniumEncoding(name) || isRustEncoding(name) {
		// fmt.Fprintf(os.Stderr, "is Itanium\n")
		// var out bytes.Buffer
		// doItaniumFilter(&out, name)
		return Filter(name)
	}
	return MsvcFilter(name)
}
