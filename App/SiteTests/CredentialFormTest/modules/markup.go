package modules

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Kinds of secret a field collects.
const (
	FieldPassword = "password"
	FieldCard     = "card"
	FieldOTP      = "otp"
)

// MarkupPatterns are the compiled expressions forms, fields and scripts are extracted with.
type MarkupPatterns struct {
	Comment   *regexp.Regexp
	Script    *regexp.Regexp
	FormOpen  *regexp.Regexp
	FormClose *regexp.Regexp
	Control   *regexp.Regexp
	BaseTag   *regexp.Regexp
	Attribute *regexp.Regexp
}

// FieldPattern recognises one kind of sensitive field by its identifiers.
type FieldPattern struct {
	Kind    string
	Pattern *regexp.Regexp
}

// SensitiveField is one control that collects a password, card details or a one-time code.
type SensitiveField struct {
	Kind string `json:"Kind"`
	Tag  string `json:"Tag"`
	Type string `json:"Type,omitempty"`
	Name string `json:"Name,omitempty"`
}

// FormDeclaration is one <form> element as written in the markup.
type FormDeclaration struct {
	Action        string
	Method        string
	OnSubmit      string
	ButtonActions []string // formaction overrides on the form's submit controls
	Fields        []SensitiveField
}

// Page is the parts of a document the test inspects.
type Page struct {
	Forms       []FormDeclaration
	LooseFields []SensitiveField // Sensitive fields outside any form, left for a script to read
	Scripts     []string         // Inline script bodies and form submit handlers
	Base        *url.URL
}

// Extractor finds forms, their sensitive fields and the inline scripts in a page.
type Extractor struct {
	Patterns          MarkupPatterns
	FieldPatterns     []FieldPattern
	AutocompleteKinds map[string]string
	IgnoredInputTypes map[string]bool
	ScriptTypes       map[string]bool
}

// Parse extracts everything the test inspects from a page. Scripts are taken out first, so
// markup quoted inside them is not mistaken for the page's own, and commented out markup is
// ignored because the browser ignores it.
func (e Extractor) Parse(body string, address *url.URL) Page {
	page := Page{Forms: []FormDeclaration{}, LooseFields: []SensitiveField{}, Scripts: []string{}}

	for _, match := range e.Patterns.Script.FindAllStringSubmatch(body, -1) {
		attributes := e.attributes("<script " + match[1] + ">")
		if _, external := attributes["src"]; external {
			continue
		}
		if !e.ScriptTypes[strings.ToLower(strings.TrimSpace(attributes["type"]))] {
			continue
		}
		if script := strings.TrimSpace(match[2]); script != "" {
			page.Scripts = append(page.Scripts, script)
		}
	}

	markup := e.Patterns.Script.ReplaceAllString(body, "")
	markup = e.Patterns.Comment.ReplaceAllString(markup, "")
	page.Base = e.baseURL(markup, address)

	outside := strings.Builder{}
	cursor := 0
	for _, segment := range e.formSegments(markup) {
		outside.WriteString(markup[cursor:segment.start])
		cursor = segment.end
		form := e.form(segment.tag, markup[segment.contentStart:segment.end])
		if form.OnSubmit != "" {
			page.Scripts = append(page.Scripts, form.OnSubmit)
		}
		page.Forms = append(page.Forms, form)
	}
	outside.WriteString(markup[cursor:])

	for _, control := range e.Patterns.Control.FindAllStringSubmatch(outside.String(), -1) {
		if field, sensitive := e.sensitiveField(strings.ToLower(control[1]), e.attributes(control[0])); sensitive {
			page.LooseFields = append(page.LooseFields, field)
		}
	}
	return page
}

// formSegment is where one form starts, where its content starts and where it ends.
type formSegment struct {
	tag          string
	start        int
	contentStart int
	end          int
}

// formSegments splits the markup into forms. A form ends at its closing tag, or where the
// next form starts, since forms cannot nest and browsers close an unterminated one there.
func (e Extractor) formSegments(markup string) []formSegment {
	opens := e.Patterns.FormOpen.FindAllStringIndex(markup, -1)
	segments := make([]formSegment, 0, len(opens))
	for index, open := range opens {
		end := len(markup)
		if index+1 < len(opens) {
			end = opens[index+1][0]
		}
		if close := e.Patterns.FormClose.FindStringIndex(markup[open[1]:end]); close != nil {
			end = open[1] + close[1]
		}
		segments = append(segments, formSegment{tag: markup[open[0]:open[1]], start: open[0], contentStart: open[1], end: end})
	}
	return segments
}

// form reads one form's destination and its sensitive fields.
func (e Extractor) form(tag string, content string) FormDeclaration {
	attributes := e.attributes(tag)
	form := FormDeclaration{
		Action:        strings.TrimSpace(attributes["action"]),
		Method:        strings.ToLower(strings.TrimSpace(attributes["method"])),
		OnSubmit:      strings.TrimSpace(attributes["onsubmit"]),
		ButtonActions: []string{},
		Fields:        []SensitiveField{},
	}
	if form.Method == "" {
		form.Method = "get"
	}

	for _, control := range e.Patterns.Control.FindAllStringSubmatch(content, -1) {
		controlAttributes := e.attributes(control[0])
		if action, overrides := controlAttributes["formaction"]; overrides && strings.TrimSpace(action) != "" {
			form.ButtonActions = append(form.ButtonActions, strings.TrimSpace(action))
		}
		if field, sensitive := e.sensitiveField(strings.ToLower(control[1]), controlAttributes); sensitive {
			form.Fields = append(form.Fields, field)
		}
	}
	return form
}

// sensitiveField decides whether a control collects a secret: by its type, then by the
// autocomplete token a browser would fill it with, then by what it is named and labelled.
func (e Extractor) sensitiveField(tag string, attributes map[string]string) (SensitiveField, bool) {
	if tag == "button" {
		return SensitiveField{}, false
	}
	inputType := strings.ToLower(strings.TrimSpace(attributes["type"]))
	if tag == "input" && inputType == "" {
		inputType = "text"
	}
	if tag == "input" && e.IgnoredInputTypes[inputType] {
		return SensitiveField{}, false
	}

	field := SensitiveField{Tag: tag, Type: inputType, Name: attributes["name"]}
	if field.Name == "" {
		field.Name = attributes["id"]
	}

	if inputType == "password" {
		field.Kind = FieldPassword
		return field, true
	}
	for _, token := range strings.Fields(strings.ToLower(attributes["autocomplete"])) {
		if kind := e.AutocompleteKinds[token]; kind != "" {
			field.Kind = kind
			return field, true
		}
	}

	identifiers := splitIdentifier(strings.Join([]string{
		attributes["name"], attributes["id"], attributes["placeholder"], attributes["aria-label"],
	}, " "))
	for _, pattern := range e.FieldPatterns {
		if pattern.Pattern.MatchString(identifiers) {
			field.Kind = pattern.Kind
			return field, true
		}
	}
	return SensitiveField{}, false
}

// baseURL returns the URL relative form actions resolve against: the document's <base>
// element when it declares one, the page's own address otherwise.
func (e Extractor) baseURL(markup string, address *url.URL) *url.URL {
	tag := e.Patterns.BaseTag.FindString(markup)
	if tag == "" {
		return address
	}
	href := strings.TrimSpace(e.attributes(tag)["href"])
	if href == "" {
		return address
	}
	base, err := url.Parse(href)
	if err != nil {
		return address
	}
	return address.ResolveReference(base)
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

// splitIdentifier turns identifiers into lowercase words separated by single spaces, so
// cardNumber, card_number, OTPCode and "Card number" read "card number" and "otp code".
func splitIdentifier(identifier string) string {
	runes := []rune(identifier)
	words := strings.Builder{}
	separated := true
	for index, current := range runes {
		if !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			if !separated {
				words.WriteRune(' ')
				separated = true
			}
			continue
		}
		if !separated && unicode.IsUpper(current) {
			previous := runes[index-1]
			nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			if unicode.IsLower(previous) || unicode.IsUpper(previous) && nextIsLower {
				words.WriteRune(' ')
			}
		}
		words.WriteRune(unicode.ToLower(current))
		separated = false
	}
	return strings.TrimSpace(words.String())
}
