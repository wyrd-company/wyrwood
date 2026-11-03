// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package policy

import (
	"regexp"
	"sort"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	hclstrconv "github.com/hashicorp/hcl/hcl/strconv"
	"github.com/hashicorp/hcl/hcl/token"
)

const (
	maximumBindingValues         = 16
	maximumBindingValueBytes     = 128
	maximumBindingValueNameBytes = 64
	// bindingValueMetadataPrefix keeps a value's alias metadata key away from
	// the role_name key that AppRole writes at login.
	bindingValueMetadataPrefix = "binding_"
)

var (
	bindingPlaceholder      = regexp.MustCompile(`\{\{binding\.([a-z][a-z0-9_]*)\}\}`)
	bindingMention          = regexp.MustCompile(`\{\{\s*binding\b`)
	bindingValueNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	bindingValuePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// decodedToken is the string OpenBao reads from a token, with escapes applied.
func decodedToken(item token.Token) string {
	if item.Type == token.STRING {
		if decoded, err := hclstrconv.Unquote(item.Text); err == nil {
			return decoded
		}
	}
	return item.Text
}

// mentionsBinding reads a token both as written and as decoded, so that an
// escape cannot hide a placeholder.
func mentionsBinding(item token.Token) bool {
	return bindingMention.MatchString(item.Text) || bindingMention.MatchString(decodedToken(item))
}

// bindingValueUse reads the placeholders of an HCL document. Comments are not
// read. Names are those in path stanza names. Stray reports a placeholder that
// is malformed, escaped, or outside a path stanza name, which OpenBao would
// accept and never resolve. A document that does not parse reports nothing,
// because OpenBao remains the validity authority.
func bindingValueUse(source string) (names []string, stray bool) {
	parsed, err := hcl.Parse(source)
	if err != nil {
		return nil, false
	}
	list, ok := parsed.Node.(*ast.ObjectList)
	if !ok {
		return nil, false
	}
	found := map[string]bool{}
	for _, item := range list.Items {
		isPath := len(item.Keys) >= 2 && item.Keys[0].Token.Value() == "path"
		for index, key := range item.Keys {
			if !isPath || index != 1 {
				stray = stray || mentionsBinding(key.Token)
				continue
			}
			// Publication compiles the text as written, so a placeholder counts
			// only when it is the same as written and as decoded.
			decoded := decodedToken(key.Token)
			written := bindingPlaceholder.FindAllStringSubmatch(key.Token.Text, -1)
			if len(written) != len(bindingPlaceholder.FindAllString(decoded, -1)) {
				stray = true
			}
			for _, match := range written {
				found[match[1]] = true
			}
			stray = stray || bindingMention.MatchString(bindingPlaceholder.ReplaceAllString(decoded, ""))
		}
		ast.Walk(item.Val, func(node ast.Node) (ast.Node, bool) {
			switch inner := node.(type) {
			case *ast.ObjectKey:
				stray = stray || mentionsBinding(inner.Token)
			case *ast.LiteralType:
				stray = stray || mentionsBinding(inner.Token)
			}
			return node, true
		})
	}
	return namesOf(found), stray
}

func validateBindingPlaceholders(source string) error {
	names, stray := bindingValueUse(source)
	if stray {
		return partError(PartOpenBao, "a binding value is written {{binding.name}} with a lower-case name and no escapes, and only in a path stanza name")
	}
	if len(names) > maximumBindingValues {
		return partError(PartOpenBao, "a policy can use at most %d binding values", maximumBindingValues)
	}
	for _, name := range names {
		if len(name) > maximumBindingValueNameBytes {
			return partError(PartOpenBao, "a binding value name exceeds %d bytes", maximumBindingValueNameBytes)
		}
	}
	return nil
}

// ValueNames returns the binding values the policy's path stanzas use.
func (p Policy) ValueNames() []string {
	names, _ := bindingValueUse(p.OpenBao.Policy)
	return names
}

// expandBindingValues shows the result for one binding. Validated values hold
// no character that HCL or an ACL path treats as special.
func expandBindingValues(source string, values map[string]string) string {
	return bindingPlaceholder.ReplaceAllStringFunc(source, func(placeholder string) string {
		name := bindingPlaceholder.FindStringSubmatch(placeholder)[1]
		if value, ok := values[name]; ok {
			return value
		}
		return placeholder
	})
}

// HasBindingValues reports whether source holds a placeholder to compile.
func HasBindingValues(source string) bool { return bindingPlaceholder.MatchString(source) }

// IdentityTemplates compiles each placeholder to the OpenBao identity template
// that reads the value from the binding's AppRole alias metadata.
func IdentityTemplates(source, appRoleAccessor string) string {
	return bindingPlaceholder.ReplaceAllString(source, "{{identity.entity.aliases."+appRoleAccessor+".metadata."+bindingValueMetadataPrefix+"$1}}")
}

// IdentityMetadata is the AppRole SecretID metadata that carries the values to
// the alias metadata at login. It is nil when the binding has no values.
func (s Settings) IdentityMetadata() map[string]string {
	if len(s.Values) == 0 {
		return nil
	}
	metadata := make(map[string]string, len(s.Values))
	for name, value := range s.Values {
		metadata[bindingValueMetadataPrefix+name] = value
	}
	return metadata
}

func validateBindingValues(values map[string]string) error {
	if len(values) > maximumBindingValues {
		return partError(PartSelection, "a binding can hold at most %d values", maximumBindingValues)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(name) > maximumBindingValueNameBytes || !bindingValueNamePattern.MatchString(name) {
			return partError(PartSelection, "a binding value name must be lower-case letters, digits, and underscores, and start with a letter")
		}
		if value := values[name]; len(value) > maximumBindingValueBytes || !bindingValuePattern.MatchString(value) {
			return partError(PartSelection, "the value of %s must be 1 to %d letters, digits, underscores, or hyphens", name, maximumBindingValueBytes)
		}
	}
	return nil
}
