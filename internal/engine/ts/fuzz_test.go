//go:build cgo

package ts

import (
	"sort"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

var fuzzExt = map[string]string{
	"python": "py", "javascript": "js", "typescript": "ts", "java": "java",
	"kotlin": "kt", "scala": "scala", "csharp": "cs", "ruby": "rb", "php": "php",
	"rust": "rs", "swift": "swift", "c": "c", "cpp": "cpp",
}

// FuzzAnalyze drives every Tree-sitter language with arbitrary source. The
// first byte picks the language so one corpus covers the whole registry.
func FuzzAnalyze(f *testing.F) {
	langs := make([]string, 0, len(specs))
	for l := range specs {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	seeds := []string{
		"import hashlib\nhashlib.md5(b'x')\n",
		"const c = require('crypto'); c.createHash('md5')\n",
		"MessageDigest.getInstance(\"MD5\");\n",
		"#include <openssl/md5.h>\nint main(){MD5(0,0,0);}\n",
		"srand(time(0)); rand();\n",
		"KeyPairGenerator g; g.initialize(512);\n",
		"\x00\xff{{{\"",
	}
	for i := range langs {
		for _, s := range seeds {
			f.Add(byte(i), []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, pick byte, src []byte) {
		lang := langs[int(pick)%len(langs)]
		path := "f." + fuzzExt[lang]
		fs, err := Analyze(lang, path, src)
		if err != nil {
			return
		}
		if err := finding.Validate(path, src, fs); err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
	})
}
