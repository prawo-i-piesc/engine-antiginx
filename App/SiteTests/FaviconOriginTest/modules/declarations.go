package modules

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

// MarkupPatterns are the compiled expressions icon declarations are extracted with.
type MarkupPatterns struct {
	Comment   *regexp.Regexp
	LinkTag   *regexp.Regexp
	BaseTag   *regexp.Regexp
	Attribute *regexp.Regexp
}

// IconDeclaration is one <link> element that declares a page icon, as written in the markup.
type IconDeclaration struct {
	Rel  string
	Href string
}

// Extractor finds icon declarations and the document base URL in a page.
type Extractor struct {
	Patterns      MarkupPatterns
	IconRelations map[string]bool
}

// Declarations returns every icon declaration in the page, in document order. Commented out
// markup is ignored because the browser ignores it.
func (e Extractor) Declarations(body string) []IconDeclaration {
	body = e.Patterns.Comment.ReplaceAllString(body, "")

	declarations := []IconDeclaration{}
	for _, tag := range e.Patterns.LinkTag.FindAllString(body, -1) {
		attributes := e.attributes(tag)
		rel := strings.ToLower(strings.Join(strings.Fields(attributes["rel"]), " "))
		href := strings.TrimSpace(attributes["href"])
		if href == "" || !e.declaresIcon(rel) {
			continue
		}
		declarations = append(declarations, IconDeclaration{Rel: rel, Href: href})
	}
	return declarations
}

// BaseURL returns the URL relative icon references resolve against: the document's <base>
// element when it declares one, the page's own address otherwise.
func (e Extractor) BaseURL(body string, page *url.URL) *url.URL {
	body = e.Patterns.Comment.ReplaceAllString(body, "")

	tag := e.Patterns.BaseTag.FindString(body)
	if tag == "" {
		return page
	}
	href := strings.TrimSpace(e.attributes(tag)["href"])
	if href == "" {
		return page
	}
	base, err := url.Parse(href)
	if err != nil {
		return page
	}
	return page.ResolveReference(base)
}

// declaresIcon reports whether any token of a rel attribute names an icon.
func (e Extractor) declaresIcon(rel string) bool {
	for _, token := range strings.Fields(rel) {
		if e.IconRelations[token] {
			return true
		}
	}
	return false
}

// attributes parses the attributes of one tag into lowercased names mapped to unescaped values.
// The first occurrence of a repeated attribute wins, which is how browsers resolve one.
func (e Extractor) attributes(tag string) map[string]string {
	attributes := map[string]string{}
	for _, match := range e.Patterns.Attribute.FindAllStringSubmatch(tag, -1) {
		name := strings.ToLower(match[1])
		if _, seen := attributes[name]; seen {
			continue
		}
		attributes[name] = html.UnescapeString(match[2] + match[3] + match[4])
	}
	return attributes
}
