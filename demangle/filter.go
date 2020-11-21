package demangle

import (
	"bytes"
	"strings"
)

func isItaniumEncoding(mangledName string) bool {
	pos := strings.IndexByte(mangledName, '_')
	return pos >= 0 && pos <= 4 && pos+1 < len(mangledName) && mangledName[pos+1] == 'Z'
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
	if isItaniumEncoding(name) {
		// fmt.Fprintf(os.Stderr, "is Itanium\n")
		// var out bytes.Buffer
		// doItaniumFilter(&out, name)
		return Filter(name)
	}
	return MsvcFilter(name)
}
