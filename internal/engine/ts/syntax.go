//go:build treesitter

package ts

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// A syntax describes the small part of a grammar the analyzer actually needs:
// how to read a dotted name (`Crypto.Cipher.DES.new`, `OpenSSL::Cipher.new`,
// `CryptoPP::Weak::MD5`) out of a chain of nodes, and how to reach a call's
// arguments. Everything above that (walking, matching, deduping, building
// findings) is shared, so adding a language is a table entry, not an
// analyzer.
type syntax struct {
	// language returns the grammar. It takes the path because one language
	// name can map to two grammars (.ts vs .tsx).
	language func(path string) *sitter.Language

	// member are the node types that join two halves of a dotted name, mapped
	// to the fields holding the left (receiver) and right (member) halves. An
	// empty field name means the half is positional: left is named child 0,
	// right is named child 1.
	member map[string]memberShape

	// call are the node types that invoke something, including object
	// construction, mapped to the fields naming the callee and the arguments.
	call map[string]callShape

	// unwrap are nodes that wrap a name but contribute nothing to it, such as
	// Kotlin's and Swift's `navigation_suffix`.
	unwrap map[string]bool

	// argsHolder are nodes that stand between a call and its argument list
	// (Kotlin's and Swift's `call_suffix`); argWrap are per-argument wrappers
	// (`argument`, `value_argument`).
	argsHolder map[string]bool
	argWrap    map[string]bool

	// stringLit and intLit are the literal node types carrying an algorithm
	// name and a key size respectively.
	stringLit map[string]bool
	intLit    map[string]bool
}

type memberShape struct{ left, right string }

// selfName marks a call node that spells its own callee out of its fields
// (Java's `method_invocation`, Ruby's `call`) rather than holding it in one
// child node. Such a type also has a memberShape entry.
const selfName = "@self"

type callShape struct {
	// fn names the field holding the callee; "" means named child 0, and
	// selfName means the call node renders its own name.
	fn string
	// args names the field holding the argument list; "" means the call's last
	// named child.
	args string
}

// dotted renders a name chain as "a.b.c", using "." for every language's
// separator so one target table spelling works everywhere.
func (s syntax) dotted(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	t := n.Type()
	if s.unwrap[t] {
		if c := lastNamed(n); c != nil {
			return s.dotted(c, src)
		}
		return strings.TrimLeft(n.Content(src), ".")
	}
	if m, ok := s.member[t]; ok {
		left := s.dotted(s.part(n, m.left, 0), src)
		right := s.dotted(s.part(n, m.right, 1), src)
		switch {
		case left == "":
			return right
		case right == "":
			return left
		}
		return left + "." + right
	}
	if c, ok := s.call[t]; ok && c.fn != selfName {
		return s.dotted(s.callee(n), src)
	}
	return n.Content(src)
}

// calleeName is the dotted name of what a call invokes.
func (s syntax) calleeName(call *sitter.Node, src []byte) string {
	if s.call[call.Type()].fn == selfName {
		// The member shape for this node type renders the name.
		return s.dotted(call, src)
	}
	return s.dotted(s.callee(call), src)
}

func (s syntax) callee(call *sitter.Node) *sitter.Node {
	c := s.call[call.Type()]
	switch c.fn {
	case selfName:
		return nil
	case "":
		return call.NamedChild(0)
	}
	return call.ChildByFieldName(c.fn)
}

// args returns a call's argument expressions, unwrapping the holder and
// per-argument nodes that some grammars insert.
func (s syntax) args(call *sitter.Node) []*sitter.Node {
	c := s.call[call.Type()]
	var list *sitter.Node
	if c.args != "" {
		list = call.ChildByFieldName(c.args)
	} else {
		list = lastNamed(call)
	}
	// A call with no argument node at all (Ruby's parenthesis-free `Foo.new`)
	// leaves the callee as the last named child; it holds no arguments.
	if list == nil || list == s.callee(call) {
		return nil
	}
	for s.argsHolder[list.Type()] {
		next := lastNamed(list)
		if next == nil {
			return nil
		}
		list = next
	}
	out := make([]*sitter.Node, 0, list.NamedChildCount())
	for i := 0; i < int(list.NamedChildCount()); i++ {
		a := list.NamedChild(i)
		if s.argWrap[a.Type()] {
			if inner := lastNamed(a); inner != nil {
				a = inner
			}
		}
		out = append(out, a)
	}
	return out
}

// stringArg returns the literal string at position idx, or, when idx is
// negative, the first literal string among the arguments. Non-literal
// arguments (a variable holding the plaintext, say) simply do not match.
func (s syntax) stringArg(args []*sitter.Node, idx int, src []byte) (string, bool) {
	if idx >= 0 {
		if idx >= len(args) || !s.stringLit[args[idx].Type()] {
			return "", false
		}
		return unquote(args[idx].Content(src)), true
	}
	for _, a := range args {
		if s.stringLit[a.Type()] {
			return unquote(a.Content(src)), true
		}
	}
	return "", false
}

// minIntArg returns the smallest integer literal anywhere in the arguments.
// Key sizes are passed in many shapes (positionally, as a named argument, or
// inside an options object), and taking the minimum finds the modulus length
// without having to model each of them, because the other numbers in these
// calls (public exponents, buffer lengths) are larger than any key size we
// would flag.
func (s syntax) minIntArg(args []*sitter.Node, src []byte) (int, bool) {
	best, found := 0, false
	for _, a := range args {
		walk(a, func(n *sitter.Node) {
			if !s.intLit[n.Type()] {
				return
			}
			v, err := parseInt(n.Content(src))
			if err != nil {
				return
			}
			if !found || v < best {
				best, found = v, true
			}
		})
	}
	return best, found
}

func lastNamed(n *sitter.Node) *sitter.Node {
	if n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(int(n.NamedChildCount()) - 1)
}

func (s syntax) part(n *sitter.Node, field string, pos int) *sitter.Node {
	if field != "" {
		return n.ChildByFieldName(field)
	}
	if pos < int(n.NamedChildCount()) {
		return n.NamedChild(pos)
	}
	return nil
}

// unquote strips the delimiters a string literal node carries. Grammars differ
// on whether the quotes are part of the node, so this handles both.
func unquote(s string) string {
	s = strings.TrimPrefix(s, "@") // C# verbatim strings
	return strings.Trim(s, "\"'`")
}

func walk(n *sitter.Node, fn func(*sitter.Node)) {
	fn(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), fn)
	}
}
