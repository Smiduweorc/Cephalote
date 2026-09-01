//go:build treesitter

package ts

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/scala"
	"github.com/smacker/go-tree-sitter/swift"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/Smiduweorc/Cephalote/internal/rules"
)

// Short aliases keep the detection tables below readable.
const (
	ruleMD5      = rules.MD5
	ruleMD4      = rules.MD4
	ruleSHA1     = rules.SHA1
	ruleDES      = rules.DES
	rule3DES     = rules.TripleDES
	ruleRC4      = rules.RC4
	ruleBlowfish = rules.Blowfish
	ruleECB      = rules.ECB
	ruleRSASmall = rules.RSASmall
	ruleWeakRand = rules.WeakRand
	ruleWeakTLS  = rules.WeakTLS
)

// bitsRule flags an undersized key from a call's integer argument.
type bitsRule struct {
	// max flags any size below it.
	max int
	// only, when set, restricts firing to these exact sizes. It is used where
	// the receiver cannot be typed (`generator.initialize(1024)` says nothing
	// about what `generator` is), so that only recognizable RSA modulus sizes
	// count and an unrelated `.initialize(n)` does not.
	only []int
}

// spec is everything the analyzer knows about one language.
type spec struct {
	syntax syntax

	// targets maps a dotted-name suffix to the rules its mere presence
	// triggers. Suffix matching on component boundaries means one entry covers
	// every way the name can be qualified: "Digest.MD5" matches both
	// `Digest::MD5` and `OpenSSL::Digest::MD5`.
	targets map[string][]string

	// algoCalls maps a callee suffix to the index of the argument naming the
	// algorithm, which classifyAlgorithm then interprets. -1 means "the first
	// string literal among the arguments".
	algoCalls map[string]int

	// bitsCalls maps a callee suffix to its key-size check.
	bitsCalls map[string]bitsRule

	// aliases, when set, resolves import-bound bare names to their canonical
	// dotted form before lookup (Python's `from hashlib import md5 as digest`).
	aliases func(root *sitter.Node, src []byte) map[string]string
}

// specs is the registry: a language is supported exactly when it appears here.
var specs = map[string]spec{
	"python":     pythonSpec,
	"javascript": jsSpec,
	"typescript": tsSpec,
	"java":       javaSpec,
	"kotlin":     kotlinSpec,
	"scala":      scalaSpec,
	"csharp":     csharpSpec,
	"ruby":       rubySpec,
	"php":        phpSpec,
	"rust":       rustSpec,
	"swift":      swiftSpec,
	"c":          cSpec,
	"cpp":        cppSpec,
}

// ---------------------------------------------------------------- Python ---

var pythonSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return python.GetLanguage() },
		member:   map[string]memberShape{"attribute": {left: "object", right: "attribute"}},
		call:     map[string]callShape{"call": {fn: "function", args: "arguments"}},
		argWrap:  map[string]bool{"keyword_argument": true},
		stringLit: map[string]bool{
			"string": true, "concatenated_string": true,
		},
		intLit: map[string]bool{"integer": true},
	},
	aliases: pythonImportAliases,
	targets: map[string][]string{
		// hashlib / pycryptodome / cryptography hashes
		"hashlib.md5":  {ruleMD5},
		"hashlib.sha1": {ruleSHA1},
		"hashes.MD5":   {ruleMD5},
		"hashes.SHA1":  {ruleSHA1},
		"MD5.new":      {ruleMD5},
		"MD4.new":      {ruleMD4},
		"SHA1.new":     {ruleSHA1},
		// symmetric ciphers (pycryptodome / cryptography)
		"DES.new":              {ruleDES},
		"DES3.new":             {rule3DES},
		"ARC4.new":             {ruleRC4},
		"Blowfish.new":         {ruleBlowfish},
		"algorithms.TripleDES": {rule3DES},
		"algorithms.ARC4":      {ruleRC4},
		"algorithms.Blowfish":  {ruleBlowfish},
		"modes.ECB":            {ruleECB},
		// insecure randomness for secrets
		"random.random":      {ruleWeakRand},
		"random.randint":     {ruleWeakRand},
		"random.randrange":   {ruleWeakRand},
		"random.getrandbits": {ruleWeakRand},
		"random.choice":      {ruleWeakRand},
		// deprecated transport
		"ssl.PROTOCOL_TLSv1":   {ruleWeakTLS},
		"ssl.PROTOCOL_TLSv1_1": {ruleWeakTLS},
		"ssl.PROTOCOL_SSLv3":   {ruleWeakTLS},
		"ssl.PROTOCOL_SSLv2":   {ruleWeakTLS},
		"ssl.PROTOCOL_SSLv23":  {ruleWeakTLS},
	},
	algoCalls: map[string]int{"hashlib.new": 0},
	bitsCalls: map[string]bitsRule{
		"RSA.generate":             {max: 2048},
		"rsa.generate_private_key": {max: 2048},
	},
}

// ------------------------------------------------ JavaScript/TypeScript ---

var ecmaSyntax = syntax{
	member: map[string]memberShape{
		"member_expression": {left: "object", right: "property"},
	},
	call: map[string]callShape{
		"call_expression": {fn: "function", args: "arguments"},
		"new_expression":  {fn: "constructor", args: "arguments"},
	},
	stringLit: map[string]bool{"string": true, "template_string": true},
	intLit:    map[string]bool{"number": true},
}

// Node's crypto module and the Web Crypto API both take the algorithm as a
// string, so almost everything here is an algoCall.
var ecmaTargets = map[string][]string{
	"Math.random":              {ruleWeakRand},
	"crypto.pseudoRandomBytes": {ruleWeakRand},
}

var ecmaAlgoCalls = map[string]int{
	"createHash":       0,
	"createCipheriv":   0,
	"createDecipheriv": 0,
	"createCipher":     0,
	"createDecipher":   0,
	"createSign":       0,
	"createVerify":     0,
}

var ecmaBitsCalls = map[string]bitsRule{
	"generateKeyPair":     {max: 2048},
	"generateKeyPairSync": {max: 2048},
}

func ecmaSpec(lang func(string) *sitter.Language) spec {
	s := ecmaSyntax
	s.language = lang
	return spec{
		syntax:    s,
		targets:   ecmaTargets,
		algoCalls: ecmaAlgoCalls,
		bitsCalls: ecmaBitsCalls,
	}
}

var jsSpec = ecmaSpec(func(string) *sitter.Language { return javascript.GetLanguage() })

// TypeScript needs the TSX grammar for .tsx: the two dialects disagree on
// angle-bracket syntax, so parsing one with the other's grammar loses nodes.
var tsSpec = ecmaSpec(func(path string) *sitter.Language {
	if strings.HasSuffix(strings.ToLower(path), ".tsx") {
		return tsx.GetLanguage()
	}
	return typescript.GetLanguage()
})

// ------------------------------------------------- JVM (Java/Kotlin/Scala) ---

// The JCA is one API across all three languages, so they share detections and
// differ only in grammar shape.
var jcaTargets = map[string][]string{
	"Math.random":       {ruleWeakRand},
	"Random":            {ruleWeakRand},
	"Random.nextInt":    {ruleWeakRand},
	"Random.nextLong":   {ruleWeakRand},
	"Random.nextDouble": {ruleWeakRand},
	"Random.nextFloat":  {ruleWeakRand},
	"Random.nextBytes":  {ruleWeakRand},
}

var jcaAlgoCalls = map[string]int{
	"MessageDigest.getInstance": 0,
	"Cipher.getInstance":        0,
	"KeyGenerator.getInstance":  0,
	"Signature.getInstance":     0,
	"SSLContext.getInstance":    0,
}

var jcaBitsCalls = map[string]bitsRule{
	"RSAKeyGenParameterSpec": {max: 2048},
	// The receiver of initialize() cannot be typed from syntax alone, so only
	// sizes that are unmistakably an RSA modulus count.
	"initialize": {only: []int{512, 768, 1024, 1536}},
}

var javaSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return java.GetLanguage() },
		member: map[string]memberShape{
			"field_access":      {left: "object", right: "field"},
			"scoped_identifier": {left: "scope", right: "name"},
			"method_invocation": {left: "object", right: "name"},
		},
		call: map[string]callShape{
			"method_invocation":          {fn: selfName, args: "arguments"},
			"object_creation_expression": {fn: "type", args: "arguments"},
		},
		stringLit: map[string]bool{"string_literal": true},
		intLit:    map[string]bool{"decimal_integer_literal": true},
	},
	targets:   jcaTargets,
	algoCalls: jcaAlgoCalls,
	bitsCalls: jcaBitsCalls,
}

// Kotlin's grammar names no fields, so every shape here is positional.
var kotlinSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return kotlin.GetLanguage() },
		member: map[string]memberShape{
			"navigation_expression": {},
		},
		call: map[string]callShape{
			"call_expression": {},
		},
		unwrap:     map[string]bool{"navigation_suffix": true},
		argsHolder: map[string]bool{"call_suffix": true},
		argWrap:    map[string]bool{"value_argument": true},
		stringLit:  map[string]bool{"string_literal": true},
		intLit:     map[string]bool{"integer_literal": true},
	},
	targets:   jcaTargets,
	algoCalls: jcaAlgoCalls,
	bitsCalls: jcaBitsCalls,
}

var scalaSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return scala.GetLanguage() },
		member: map[string]memberShape{
			"field_expression": {left: "value", right: "field"},
		},
		call: map[string]callShape{
			"call_expression":     {fn: "function", args: "arguments"},
			"instance_expression": {},
		},
		stringLit: map[string]bool{"string": true},
		intLit:    map[string]bool{"integer_literal": true, "number": true},
	},
	targets:   jcaTargets,
	algoCalls: jcaAlgoCalls,
	bitsCalls: jcaBitsCalls,
}

// ------------------------------------------------------------------ C# ---

var csharpSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return csharp.GetLanguage() },
		member: map[string]memberShape{
			"member_access_expression": {left: "expression", right: "name"},
			"qualified_name":           {left: "qualifier", right: "name"},
		},
		call: map[string]callShape{
			"invocation_expression":      {fn: "function", args: "arguments"},
			"object_creation_expression": {fn: "type", args: "arguments"},
		},
		argWrap:   map[string]bool{"argument": true},
		stringLit: map[string]bool{"string_literal": true, "verbatim_string_literal": true},
		intLit:    map[string]bool{"integer_literal": true},
	},
	targets: map[string][]string{
		"MD5.Create":                     {ruleMD5},
		"MD5CryptoServiceProvider":       {ruleMD5},
		"MD5Cng":                         {ruleMD5},
		"SHA1.Create":                    {ruleSHA1},
		"SHA1CryptoServiceProvider":      {ruleSHA1},
		"SHA1Managed":                    {ruleSHA1},
		"SHA1Cng":                        {ruleSHA1},
		"DES.Create":                     {ruleDES},
		"DESCryptoServiceProvider":       {ruleDES},
		"TripleDES.Create":               {rule3DES},
		"TripleDESCryptoServiceProvider": {rule3DES},
		"CipherMode.ECB":                 {ruleECB},
		"Random":                         {ruleWeakRand},
		"SslProtocols.Ssl2":              {ruleWeakTLS},
		"SslProtocols.Ssl3":              {ruleWeakTLS},
		"SslProtocols.Tls":               {ruleWeakTLS},
		"SslProtocols.Tls11":             {ruleWeakTLS},
		"SecurityProtocolType.Ssl3":      {ruleWeakTLS},
		"SecurityProtocolType.Tls":       {ruleWeakTLS},
		"SecurityProtocolType.Tls11":     {ruleWeakTLS},
	},
	algoCalls: map[string]int{
		"HashAlgorithm.Create":        0,
		"SymmetricAlgorithm.Create":   0,
		"CryptoConfig.CreateFromName": 0,
	},
	bitsCalls: map[string]bitsRule{
		"RSACryptoServiceProvider": {max: 2048},
		"RSA.Create":               {max: 2048},
	},
}

// ---------------------------------------------------------------- Ruby ---

var rubySpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return ruby.GetLanguage() },
		member: map[string]memberShape{
			"scope_resolution": {left: "scope", right: "name"},
			"call":             {left: "receiver", right: "method"},
		},
		call: map[string]callShape{
			"call": {fn: selfName, args: "arguments"},
		},
		argWrap:   map[string]bool{"pair": true},
		stringLit: map[string]bool{"string": true},
		intLit:    map[string]bool{"integer": true},
	},
	targets: map[string][]string{
		"Digest.MD5":  {ruleMD5},
		"Digest.SHA1": {ruleSHA1},
		"rand":        {ruleWeakRand},
		"srand":       {ruleWeakRand},
		"Random.rand": {ruleWeakRand},
		"Random.new":  {ruleWeakRand},
	},
	algoCalls: map[string]int{
		"Digest.new":    0,
		"Digest.digest": 0,
		"Cipher.new":    0,
	},
	bitsCalls: map[string]bitsRule{
		"RSA.new":      {max: 2048},
		"RSA.generate": {max: 2048},
	},
}

// ----------------------------------------------------------------- PHP ---

var phpSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return php.GetLanguage() },
		member: map[string]memberShape{
			"member_access_expression":         {left: "object", right: "name"},
			"scoped_call_expression":           {left: "scope", right: "name"},
			"member_call_expression":           {left: "object", right: "name"},
			"class_constant_access_expression": {},
		},
		call: map[string]callShape{
			"function_call_expression":   {fn: "function", args: "arguments"},
			"scoped_call_expression":     {fn: selfName, args: "arguments"},
			"member_call_expression":     {fn: selfName, args: "arguments"},
			"object_creation_expression": {args: "arguments"},
		},
		argWrap:   map[string]bool{"argument": true},
		stringLit: map[string]bool{"string": true, "encapsed_string": true},
		intLit:    map[string]bool{"integer": true},
	},
	targets: map[string][]string{
		"md5":       {ruleMD5},
		"md5_file":  {ruleMD5},
		"sha1":      {ruleSHA1},
		"sha1_file": {ruleSHA1},
		"rand":      {ruleWeakRand},
		"srand":     {ruleWeakRand},
		"mt_rand":   {ruleWeakRand},
		"mt_srand":  {ruleWeakRand},
		"uniqid":    {ruleWeakRand},
	},
	algoCalls: map[string]int{
		"hash":            0,
		"hash_file":       0,
		"hash_init":       0,
		"openssl_digest":  1,
		"openssl_encrypt": 1,
		"openssl_decrypt": 1,
	},
	bitsCalls: map[string]bitsRule{"openssl_pkey_new": {max: 2048}},
}

// ---------------------------------------------------------------- Rust ---

// Rust's `rand` crate is deliberately absent: `rand::random` and
// `rand::thread_rng` are CSPRNG-backed, so flagging them would be wrong. Only
// the explicitly non-cryptographic generator is listed.
var rustSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return rust.GetLanguage() },
		member: map[string]memberShape{
			"scoped_identifier":      {left: "path", right: "name"},
			"field_expression":       {left: "value", right: "field"},
			"scoped_type_identifier": {left: "path", right: "name"},
		},
		call: map[string]callShape{
			"call_expression": {fn: "function", args: "arguments"},
		},
		stringLit: map[string]bool{"string_literal": true, "raw_string_literal": true},
		intLit:    map[string]bool{"integer_literal": true},
	},
	targets: map[string][]string{
		"Md5.new":            {ruleMD5},
		"md5.compute":        {ruleMD5},
		"Md4.new":            {ruleMD4},
		"Sha1.new":           {ruleSHA1},
		"Des.new":            {ruleDES},
		"Des.new_from_slice": {ruleDES},
		"TdesEde3.new":       {rule3DES},
		"Rc4.new":            {ruleRC4},
		"Blowfish.new":       {ruleBlowfish},
		"ecb.Encryptor":      {ruleECB},
		"ecb.Decryptor":      {ruleECB},
		"rngs.SmallRng":      {ruleWeakRand},
	},
	bitsCalls: map[string]bitsRule{"RsaPrivateKey.new": {max: 2048}},
}

// --------------------------------------------------------------- Swift ---

// Apple's random APIs (arc4random, SystemRandomNumberGenerator) are
// CSPRNG-backed, so Swift has no insecure-randomness detections.
var swiftSpec = spec{
	syntax: syntax{
		language: func(string) *sitter.Language { return swift.GetLanguage() },
		member: map[string]memberShape{
			"navigation_expression": {left: "target", right: "suffix"},
		},
		call: map[string]callShape{
			"call_expression": {},
		},
		unwrap:     map[string]bool{"navigation_suffix": true},
		argsHolder: map[string]bool{"call_suffix": true},
		argWrap:    map[string]bool{"value_argument": true},
		stringLit:  map[string]bool{"line_string_literal": true},
		intLit:     map[string]bool{"integer_literal": true},
	},
	targets: map[string][]string{
		"Insecure.MD5":  {ruleMD5},
		"Insecure.SHA1": {ruleSHA1},
		"CC_MD5":        {ruleMD5},
		"CC_MD4":        {ruleMD4},
		"CC_SHA1":       {ruleSHA1},
	},
}

// ------------------------------------------------------------- C / C++ ---

// OpenSSL, libcrypto and the C standard library name the algorithm in the
// symbol itself, so C detections are almost all plain function names.
var cTargets = map[string][]string{
	"MD5":         {ruleMD5},
	"MD5_Init":    {ruleMD5},
	"MD5_Update":  {ruleMD5},
	"MD5_Final":   {ruleMD5},
	"EVP_md5":     {ruleMD5},
	"MD4":         {ruleMD4},
	"MD4_Init":    {ruleMD4},
	"EVP_md4":     {ruleMD4},
	"SHA1":        {ruleSHA1},
	"SHA1_Init":   {ruleSHA1},
	"SHA1_Update": {ruleSHA1},
	"SHA1_Final":  {ruleSHA1},
	"EVP_sha1":    {ruleSHA1},

	"DES_set_key":           {ruleDES},
	"DES_set_key_unchecked": {ruleDES},
	"DES_ncbc_encrypt":      {ruleDES},
	"EVP_des_cbc":           {ruleDES},
	"DES_ecb_encrypt":       {ruleDES, ruleECB},
	"EVP_des_ecb":           {ruleDES, ruleECB},

	"EVP_des_ede3":         {rule3DES},
	"EVP_des_ede3_cbc":     {rule3DES},
	"DES_ede3_cbc_encrypt": {rule3DES},
	"EVP_des_ede3_ecb":     {rule3DES, ruleECB},

	"RC4":         {ruleRC4},
	"RC4_set_key": {ruleRC4},
	"EVP_rc4":     {ruleRC4},

	"BF_set_key": {ruleBlowfish},
	"EVP_bf_cbc": {ruleBlowfish},
	"EVP_bf_ecb": {ruleBlowfish, ruleECB},

	"EVP_aes_128_ecb": {ruleECB},
	"EVP_aes_192_ecb": {ruleECB},
	"EVP_aes_256_ecb": {ruleECB},

	"rand":    {ruleWeakRand},
	"srand":   {ruleWeakRand},
	"drand48": {ruleWeakRand},
	"lrand48": {ruleWeakRand},
	"random":  {ruleWeakRand},
	"srandom": {ruleWeakRand},

	"SSLv2_method":        {ruleWeakTLS},
	"SSLv3_method":        {ruleWeakTLS},
	"TLSv1_method":        {ruleWeakTLS},
	"TLSv1_client_method": {ruleWeakTLS},
	"TLSv1_server_method": {ruleWeakTLS},
	"TLSv1_1_method":      {ruleWeakTLS},
}

var cAlgoCalls = map[string]int{
	"EVP_get_digestbyname": 0,
	"EVP_get_cipherbyname": 0,
}

var cBitsCalls = map[string]bitsRule{
	"RSA_generate_key":                 {max: 2048},
	"RSA_generate_key_ex":              {max: 2048},
	"EVP_PKEY_CTX_set_rsa_keygen_bits": {max: 2048},
}

var cSyntax = syntax{
	language: func(string) *sitter.Language { return c.GetLanguage() },
	member: map[string]memberShape{
		"field_expression": {left: "argument", right: "field"},
	},
	call: map[string]callShape{
		"call_expression": {fn: "function", args: "arguments"},
	},
	stringLit: map[string]bool{"string_literal": true},
	intLit:    map[string]bool{"number_literal": true},
}

var cSpec = spec{
	syntax:    cSyntax,
	targets:   cTargets,
	algoCalls: cAlgoCalls,
	bitsCalls: cBitsCalls,
}

var cppSpec = func() spec {
	s := cSyntax
	s.language = func(string) *sitter.Language { return cpp.GetLanguage() }
	s.member = map[string]memberShape{
		"field_expression":     {left: "argument", right: "field"},
		"qualified_identifier": {left: "scope", right: "name"},
	}
	t := map[string][]string{
		"QCryptographicHash.Md5":  {ruleMD5},
		"QCryptographicHash.Md4":  {ruleMD4},
		"QCryptographicHash.Sha1": {ruleSHA1},
	}
	for k, v := range cTargets {
		t[k] = v
	}
	return spec{syntax: s, targets: t, algoCalls: cAlgoCalls, bitsCalls: cBitsCalls}
}()
