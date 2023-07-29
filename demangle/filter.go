package demangle

import (
	"strings"
)

func isRustEncoding(mangledName string) bool {
	return strings.HasPrefix(mangledName, "_R")
}

func isItaniumEncoding(mangledName string) (int, bool) {
	if strings.HasPrefix(mangledName, "_Z") || strings.HasPrefix(mangledName, "___Z") {
		return 0, true
	}
	// macOS
	if strings.HasPrefix(mangledName, "__Z") {
		return 1, true
	}
	return 0, false
}

// // Demangle a string just as the GNU c++filt program does.
// func doItaniumFilter(out *bytes.Buffer, name string) {
// 	skip := 0
// 	if name[0] == '.' || name[0] == '$' {
// 		skip++
// 	}
// 	if name[skip] == '_' {
// 		skip++
// 	}
// 	result := Filter(name[skip:])
// 	if result == name[skip:] {
// 		out.WriteString(name)
// 	} else {
// 		if name[0] == '.' {
// 			out.WriteByte('.')
// 		}
// 		out.WriteString(result)
// 	}
// }

// Demangle demangle function name. on windows support msvc abi and itanium abi, rust abi
func Demangle(name string) string {
	if skip, ok := isItaniumEncoding(name); ok {
		return Filter(name[skip:])
	}
	if isRustEncoding(name) {
		return Filter(name)
	}
	return MsvcFilter(name)
}
