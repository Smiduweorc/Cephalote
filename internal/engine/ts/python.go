//go:build treesitter

package ts

import sitter "github.com/smacker/go-tree-sitter"

// pythonImportAliases builds name -> "module.name" for `from M import a, b as c`
// so that a later bare `a(...)` resolves to the same table entry as `M.a`.
func pythonImportAliases(root *sitter.Node, src []byte) map[string]string {
	m := map[string]string{}
	walk(root, func(n *sitter.Node) {
		if n.Type() != "import_from_statement" {
			return
		}
		modNode := n.ChildByFieldName("module_name")
		if modNode == nil {
			return
		}
		module := modNode.Content(src)
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.StartByte() <= modNode.EndByte() {
				continue // this is the module_name itself (or before it)
			}
			switch c.Type() {
			case "dotted_name", "identifier":
				name := c.Content(src)
				m[name] = module + "." + name
			case "aliased_import":
				orig := c.ChildByFieldName("name")
				alias := c.ChildByFieldName("alias")
				if orig != nil && alias != nil {
					m[alias.Content(src)] = module + "." + orig.Content(src)
				}
			}
		}
	})
	return m
}
