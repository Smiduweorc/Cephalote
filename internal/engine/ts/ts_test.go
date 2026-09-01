//go:build treesitter

package ts

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/lang"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

func ids(fs []finding.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}

// langCase is one language's fixture: `weak` must produce exactly the counts in
// `want`, and `clean` must produce nothing at all.
type langCase struct {
	lang  string
	path  string
	weak  string
	want  map[string]int
	clean string
}

var langCases = []langCase{
	{
		lang: "python", path: "app.py",
		weak: `import hashlib, ssl
from hashlib import md5 as digest
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
import random

a = hashlib.md5(b"x")
b = digest(b"y")
c = DES.new(key, DES.MODE_ECB)
weak = RSA.generate(1024)
strong = RSA.generate(4096)
p = ssl.PROTOCOL_TLSv1
tok = random.random()
n = hashlib.new("md5")
ok = hashlib.sha256(b"z")
`,
		want: map[string]int{
			rules.MD5:      3, // hashlib.md5, digest alias, hashlib.new("md5")
			rules.DES:      1,
			rules.RSASmall: 1, // 1024 only, not 4096
			rules.WeakTLS:  1,
			rules.WeakRand: 1,
		},
		clean: "import hashlib, secrets\nh = hashlib.sha256(b'x')\nt = secrets.token_bytes(32)\n",
	},
	{
		lang: "javascript", path: "app.js",
		weak: `const crypto = require('crypto');
const h = crypto.createHash('md5');
const s = crypto.createHash('sha1');
const c = crypto.createCipheriv('des-ede3-cbc', key, iv);
const e = crypto.createCipheriv('aes-128-ecb', key, iv);
const r = Math.random();
crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
`,
		want: map[string]int{
			rules.MD5:       1,
			rules.SHA1:      1,
			rules.TripleDES: 1,
			rules.ECB:       1,
			rules.WeakRand:  1,
			rules.RSASmall:  1,
		},
		clean: `const crypto = require('crypto');
const h = crypto.createHash('sha256');
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
const r = crypto.randomBytes(32);
`,
	},
	{
		lang: "typescript", path: "app.ts",
		weak: `import * as crypto from 'crypto';
const h: string = crypto.createHash('md5').digest('hex');
const c = crypto.createCipheriv('rc4', key, iv);
const r: number = Math.random();
`,
		want:  map[string]int{rules.MD5: 1, rules.RC4: 1, rules.WeakRand: 1},
		clean: "import * as crypto from 'crypto';\nconst h: string = crypto.createHash('sha512').digest('hex');\n",
	},
	{
		lang: "typescript", path: "app.tsx",
		weak: `const el = <div className="x" />;
const h = crypto.createHash('md5');
`,
		want:  map[string]int{rules.MD5: 1},
		clean: "const el = <div className=\"x\" />;\nconst h = crypto.createHash('sha256');\n",
	},
	{
		lang: "java", path: "A.java",
		weak: `class A {
  void f() throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    MessageDigest sd = java.security.MessageDigest.getInstance("SHA-1");
    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
    Signature sig = Signature.getInstance("SHA1withRSA");
    SSLContext ctx = SSLContext.getInstance("TLSv1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(1024);
    Random r = new Random();
    double d = Math.random();
  }
}
`,
		want: map[string]int{
			rules.MD5:      1,
			rules.SHA1:     2, // SHA-1 digest and SHA1withRSA signature
			rules.DES:      1,
			rules.ECB:      1,
			rules.WeakTLS:  1,
			rules.RSASmall: 1,
			rules.WeakRand: 2, // new Random(), Math.random()
		},
		clean: `class A {
  void f() throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(4096);
    SecureRandom r = new SecureRandom();
  }
}
`,
	},
	{
		lang: "kotlin", path: "A.kt",
		weak: `fun f() {
    val md = MessageDigest.getInstance("MD5")
    val c = Cipher.getInstance("DES/ECB/PKCS5Padding")
    val g = KeyPairGenerator.getInstance("RSA")
    g.initialize(1024)
    val x = java.security.MessageDigest.getInstance("SHA-1")
}
`,
		want: map[string]int{
			rules.MD5: 1, rules.SHA1: 1, rules.DES: 1, rules.ECB: 1, rules.RSASmall: 1,
		},
		clean: "fun f() {\n    val md = MessageDigest.getInstance(\"SHA-256\")\n    val c = Cipher.getInstance(\"AES/GCM/NoPadding\")\n}\n",
	},
	{
		lang: "scala", path: "A.scala",
		weak: `object A {
  def f(): Unit = {
    val md = MessageDigest.getInstance("MD5")
    val c = Cipher.getInstance("DES/ECB/PKCS5Padding")
    val r = scala.util.Random.nextInt()
  }
}
`,
		want:  map[string]int{rules.MD5: 1, rules.DES: 1, rules.ECB: 1, rules.WeakRand: 1},
		clean: "object A {\n  def f(): Unit = {\n    val md = MessageDigest.getInstance(\"SHA-256\")\n  }\n}\n",
	},
	{
		lang: "csharp", path: "A.cs",
		weak: `class P {
  void F() {
    var md = MD5.Create();
    var s = SHA1.Create();
    var h = System.Security.Cryptography.MD5.Create();
    var d = new DESCryptoServiceProvider();
    var t = new TripleDESCryptoServiceProvider();
    var r = new Random();
    var a = new RSACryptoServiceProvider(1024);
    aes.Mode = CipherMode.ECB;
    var x = HashAlgorithm.Create("MD5");
  }
}
`,
		want: map[string]int{
			rules.MD5:       3, // MD5.Create, the qualified one, HashAlgorithm.Create("MD5")
			rules.SHA1:      1,
			rules.DES:       1,
			rules.TripleDES: 1,
			rules.WeakRand:  1,
			rules.RSASmall:  1,
			rules.ECB:       1,
		},
		clean: `class P {
  void F() {
    var s = SHA256.Create();
    var a = new RSACryptoServiceProvider(4096);
    var r = RandomNumberGenerator.Create();
    aes.Mode = CipherMode.CBC;
  }
}
`,
	},
	{
		lang: "ruby", path: "a.rb",
		weak: `require 'openssl'
d = OpenSSL::Digest::MD5.new
e = OpenSSL::Digest.new('MD5')
c = OpenSSL::Cipher.new('des-ede3-cbc')
k = OpenSSL::PKey::RSA.new(1024)
r = rand(10)
h = Digest::SHA1.hexdigest("x")
`,
		want: map[string]int{
			rules.MD5:       2, // the constant and the string form
			rules.TripleDES: 1,
			rules.RSASmall:  1,
			rules.WeakRand:  1,
			rules.SHA1:      1,
		},
		clean: `require 'openssl'
d = OpenSSL::Digest::SHA256.new
c = OpenSSL::Cipher.new('aes-256-gcm')
k = OpenSSL::PKey::RSA.new(4096)
r = SecureRandom.hex(16)
`,
	},
	{
		lang: "php", path: "a.php",
		weak: `<?php
$h = md5($x);
$s = sha1($y);
$a = hash('md5', $z);
$c = openssl_encrypt($d, 'des-ede3-cbc', $k);
$r = rand();
$o = openssl_pkey_new(['private_key_bits' => 1024]);
`,
		want: map[string]int{
			rules.MD5:       2,
			rules.SHA1:      1,
			rules.TripleDES: 1,
			rules.WeakRand:  1,
			rules.RSASmall:  1,
		},
		clean: `<?php
$a = hash('sha256', $z);
$c = openssl_encrypt($d, 'aes-256-gcm', $k, 0, $iv, $tag);
$r = random_bytes(32);
$o = openssl_pkey_new(['private_key_bits' => 4096]);
`,
	},
	{
		lang: "rust", path: "a.rs",
		weak: `use md5::Md5;
fn main() {
    let mut h = Md5::new();
    let d = md5::compute(b"x");
    let s = sha1::Sha1::new();
    let c = Des::new_from_slice(&key);
    let k = RsaPrivateKey::new(&mut rng, 1024);
}
`,
		want: map[string]int{
			rules.MD5:      2,
			rules.SHA1:     1,
			rules.DES:      1,
			rules.RSASmall: 1,
		},
		clean: `use sha2::Sha256;
fn main() {
    let mut h = Sha256::new();
    let k = RsaPrivateKey::new(&mut rng, 4096);
    let r: u32 = rand::random();
}
`,
	},
	{
		lang: "swift", path: "a.swift",
		weak: `func f() {
    let d = Insecure.MD5.hash(data: x)
    let s = Insecure.SHA1.hash(data: y)
    let v = CC_MD5(p, n, out)
}
`,
		want:  map[string]int{rules.MD5: 2, rules.SHA1: 1},
		clean: "func f() {\n    let d = SHA256.hash(data: x)\n    let r = Int.random(in: 0..<10)\n}\n",
	},
	{
		lang: "c", path: "a.c",
		weak: `int main(void) {
  MD5_Init(&ctx);
  SHA1_Update(&c, d, n);
  const EVP_CIPHER *k = EVP_des_ede3_cbc();
  const EVP_CIPHER *e = EVP_aes_128_ecb();
  RSA_generate_key_ex(r, 1024, e, NULL);
  int x = rand();
  const EVP_MD *m = EVP_get_digestbyname("md5");
  const SSL_METHOD *t = TLSv1_method();
}
`,
		want: map[string]int{
			rules.MD5:       2,
			rules.SHA1:      1,
			rules.TripleDES: 1,
			rules.ECB:       1,
			rules.RSASmall:  1,
			rules.WeakRand:  1,
			rules.WeakTLS:   1,
		},
		clean: `int main(void) {
  SHA256_Init(&ctx);
  const EVP_CIPHER *k = EVP_aes_256_gcm();
  RSA_generate_key_ex(r, 4096, e, NULL);
  RAND_bytes(buf, 32);
}
`,
	},
	{
		lang: "cpp", path: "a.cpp",
		weak: `int main() {
  CryptoPP::Weak::MD5 h;
  auto d = QCryptographicHash::hash(x, QCryptographicHash::Md5);
  auto c = EVP_des_ede3_cbc();
  int r = std::rand();
}
`,
		want:  map[string]int{rules.MD5: 2, rules.TripleDES: 1, rules.WeakRand: 1},
		clean: "int main() {\n  auto c = EVP_aes_256_gcm();\n  auto d = QCryptographicHash::hash(x, QCryptographicHash::Sha256);\n}\n",
	},
}

func TestAnalyzeLanguages(t *testing.T) {
	for _, c := range langCases {
		t.Run(c.path, func(t *testing.T) {
			fs, err := Analyze(c.lang, c.path, []byte(c.weak))
			if err != nil {
				t.Fatal(err)
			}
			got := ids(fs)
			for id, n := range c.want {
				if got[id] != n {
					t.Errorf("rule %s = %d, want %d (all: %v)", id, got[id], n, got)
				}
			}
			for id, n := range got {
				if _, ok := c.want[id]; !ok {
					t.Errorf("unexpected rule %s x%d (all: %v)", id, n, got)
				}
			}
			for _, f := range fs {
				if f.Confidence != finding.High {
					t.Errorf("%s confidence = %s, want high", f.RuleID, f.Confidence)
				}
				if f.Line < 1 || f.Column < 1 {
					t.Errorf("%s has bad position %d:%d", f.RuleID, f.Line, f.Column)
				}
			}
		})
	}
}

func TestAnalyzeLanguages_NoFalsePositiveOnStrong(t *testing.T) {
	for _, c := range langCases {
		t.Run(c.path, func(t *testing.T) {
			fs, err := Analyze(c.lang, c.path, []byte(c.clean))
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) != 0 {
				t.Errorf("strong crypto should not flag: %v", ids(fs))
			}
		})
	}
}

func TestSupported(t *testing.T) {
	for _, c := range langCases {
		if !Supported(c.lang) {
			t.Errorf("Supported(%q) = false", c.lang)
		}
	}
	if Supported("brainfuck") {
		t.Error("Supported(brainfuck) = true")
	}
}

func TestAnalyzeUnsupportedLanguageIsNoOp(t *testing.T) {
	fs, err := Analyze("brainfuck", "a.bf", []byte("+++."))
	if err != nil || fs != nil {
		t.Errorf("Analyze(unsupported) = %v, %v; want nil, nil", fs, err)
	}
}

func TestClassifyAlgorithm(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"md5", []string{rules.MD5}},
		{"MD5", []string{rules.MD5}},
		{"SHA-1", []string{rules.SHA1}},
		{"sha1", []string{rules.SHA1}},
		{"sha", []string{rules.SHA1}},
		{"sha-256", nil},
		{"SHA-512", nil},
		{"DES/ECB/PKCS5Padding", []string{rules.DES, rules.ECB}},
		{"des-ede3-cbc", []string{rules.TripleDES}},
		{"DESede/CBC/PKCS5Padding", []string{rules.TripleDES}},
		{"AES/GCM/NoPadding", nil},
		{"aes-128-ecb", []string{rules.ECB}},
		{"aes-256-gcm", nil},
		{"rc4", []string{rules.RC4}},
		{"SHA1withRSA", []string{rules.SHA1}},
		{"PBKDF2WithHmacSHA1", nil},
		{"TLSv1", []string{rules.WeakTLS}},
		{"TLSv1.1", []string{rules.WeakTLS}},
		{"TLSv1.2", nil},
		{"TLSv1.3", nil},
		{"TLS", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := classifyAlgorithm(c.in)
		if len(got) != len(c.want) {
			t.Errorf("classifyAlgorithm(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("classifyAlgorithm(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestParseInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"1024", 1024, true},
		{"1_024", 1024, true},
		{"1024u32", 1024, true},
		{"2048L", 2048, true},
		{"0x10", 0, false},
		{"0b101", 0, false},
		{"abc", 0, false},
	}
	for _, c := range cases {
		got, err := parseInt(c.in)
		if (err == nil) != c.ok || (c.ok && got != c.want) {
			t.Errorf("parseInt(%q) = %d, %v; want %d, ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}

// TestEveryTierTwoLanguageIsRegistered keeps language detection and the
// analyzer registry from drifting apart: a file routed to tier 2 that the
// engine does not know would silently produce nothing instead of falling back.
func TestEveryTierTwoLanguageIsRegistered(t *testing.T) {
	for _, path := range []string{
		"a.py", "a.js", "a.mjs", "a.cjs", "a.jsx", "a.ts", "a.tsx", "a.java",
		"a.c", "a.h", "a.cc", "a.cpp", "a.cxx", "a.hpp", "a.rb", "a.php",
		"a.rs", "a.cs", "a.kt", "a.swift", "a.scala",
	} {
		l := lang.Detect(path, nil)
		if l.Tier != lang.TierTreeSitter {
			t.Fatalf("%s: tier = %d, want TierTreeSitter", path, l.Tier)
		}
		if !Supported(l.Name) {
			t.Errorf("%s: language %q routed to tier 2 but not registered", path, l.Name)
		}
	}
}

func TestAvailable(t *testing.T) {
	if !Available() {
		t.Error("Available() = false in the treesitter build")
	}
}

func TestResolveAlias(t *testing.T) {
	aliases := map[string]string{"digest": "hashlib.md5"}
	cases := []struct {
		name, in, want string
		aliases        map[string]string
	}{
		{"bare name is rewritten", "digest", "hashlib.md5", aliases},
		{"unknown bare name is left alone", "other", "other", aliases},
		// A qualified name is already canonical; rewriting it would let a
		// local alias shadow an unrelated member access.
		{"dotted name is never rewritten", "x.digest", "x.digest", aliases},
		{"no alias table", "digest", "digest", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveAlias(c.in, c.aliases); got != c.want {
				t.Errorf("resolveAlias(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// firstCall parses src and returns the first node of the given call type.
func firstCall(t *testing.T, sp spec, src, callType string) (*sitter.Node, []byte) {
	t.Helper()
	parser := sitter.NewParser()
	parser.SetLanguage(sp.syntax.language(""))
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tree.Close)
	var found *sitter.Node
	walk(tree.RootNode(), func(n *sitter.Node) {
		if found == nil && n.Type() == callType {
			found = n
		}
	})
	if found == nil {
		t.Fatalf("no %s node in %q", callType, src)
	}
	return found, []byte(src)
}

// stringArg's negative index means "the first string literal among the
// arguments", which the detection tables document but no entry uses yet.
func TestStringArgSelection(t *testing.T) {
	sp := specs["python"]
	call, src := firstCall(t, sp, `f(x, "algo", 7, "second")`, "call")
	args := sp.syntax.args(call)
	if len(args) != 4 {
		t.Fatalf("args = %d, want 4", len(args))
	}

	cases := []struct {
		name string
		idx  int
		want string
		ok   bool
	}{
		{"positional hit", 1, "algo", true},
		{"first string anywhere", -1, "algo", true},
		{"index past the end", 9, "", false},
		{"index at a non-literal argument", 0, "", false},
		{"index at an integer argument", 2, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := sp.syntax.stringArg(args, c.idx, src)
			if got != c.want || ok != c.ok {
				t.Errorf("stringArg(idx=%d) = %q, %v; want %q, %v", c.idx, got, ok, c.want, c.ok)
			}
		})
	}

	// With no string arguments at all, both modes must decline rather than
	// classify something that is not an algorithm name.
	noStrings, src2 := firstCall(t, sp, `f(x, 7)`, "call")
	for _, idx := range []int{-1, 0, 1} {
		if _, ok := sp.syntax.stringArg(sp.syntax.args(noStrings), idx, src2); ok {
			t.Errorf("stringArg(idx=%d) matched in a call with no string arguments", idx)
		}
	}
}

// A call with no arguments must yield an empty list, not the callee.
func TestArgsOfCallWithoutArguments(t *testing.T) {
	sp := specs["python"]
	call, _ := firstCall(t, sp, `hashlib.md5()`, "call")
	if got := sp.syntax.args(call); len(got) != 0 {
		t.Errorf("args() = %d nodes, want 0", len(got))
	}
}

func TestBitsRuleFlags(t *testing.T) {
	below := bitsRule{max: 2048}
	for _, c := range []struct {
		bits int
		want bool
	}{{512, true}, {2047, true}, {2048, false}, {4096, false}} {
		if got := below.flags(c.bits); got != c.want {
			t.Errorf("max-rule flags(%d) = %v, want %v", c.bits, got, c.want)
		}
	}

	// The `only` form exists for receivers that cannot be typed, so it must
	// ignore sizes outside its list even when they are below the threshold.
	only := bitsRule{only: []int{512, 1024}}
	for _, c := range []struct {
		bits int
		want bool
	}{{512, true}, {1024, true}, {1, false}, {2047, false}, {4096, false}} {
		if got := only.flags(c.bits); got != c.want {
			t.Errorf("only-rule flags(%d) = %v, want %v", c.bits, got, c.want)
		}
	}

	// A zero rule must never fire.
	if (bitsRule{}).flags(1) {
		t.Error("an empty bitsRule fired")
	}
}

// Every table entry must name a rule the catalog knows, or the finding would
// panic in MustGet at scan time rather than at test time.
func TestEveryTableEntryNamesAKnownRule(t *testing.T) {
	for lang, sp := range specs {
		for name, ids := range sp.targets {
			if len(ids) == 0 {
				t.Errorf("%s: target %q lists no rules", lang, name)
			}
			for _, id := range ids {
				if _, ok := rules.Get(id); !ok {
					t.Errorf("%s: target %q names unknown rule %q", lang, name, id)
				}
			}
		}
		for name, idx := range sp.algoCalls {
			if idx < -1 {
				t.Errorf("%s: algoCall %q has invalid index %d", lang, name, idx)
			}
		}
		for name, br := range sp.bitsCalls {
			if br.max == 0 && len(br.only) == 0 {
				t.Errorf("%s: bitsCall %q would never fire", lang, name)
			}
		}
	}
}

// A grammar shape that names a field the grammar does not have would silently
// stop matching, so every spec must at least produce findings on its own
// fixture - enforced by TestAnalyzeLanguages - and declare a usable syntax.
func TestEverySpecIsUsable(t *testing.T) {
	for lang, sp := range specs {
		if sp.syntax.language == nil {
			t.Errorf("%s: no grammar", lang)
			continue
		}
		if sp.syntax.language("") == nil {
			t.Errorf("%s: grammar is nil", lang)
		}
		if len(sp.syntax.call) == 0 {
			t.Errorf("%s: no call node types; nothing would ever match", lang)
		}
		if len(sp.targets)+len(sp.algoCalls)+len(sp.bitsCalls) == 0 {
			t.Errorf("%s: registered with no detections at all", lang)
		}
	}
}

func TestAnalyzeHandlesEmptyAndGarbageInput(t *testing.T) {
	for lang := range specs {
		for _, src := range []string{"", "\n\n", "\x01\x02 not source at all {{{"} {
			fs, err := Analyze(lang, "a", []byte(src))
			if err != nil {
				t.Errorf("Analyze(%s, %q) = %v", lang, src, err)
			}
			if len(fs) != 0 {
				t.Errorf("Analyze(%s, %q) = %+v, want no findings", lang, src, fs)
			}
		}
	}
}
