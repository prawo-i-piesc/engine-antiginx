package modules

import (
	"encoding/json"
	"strings"
	"time"
)

// rdapDomainRecord is the subset of an RDAP domain response the test reads.
type rdapDomainRecord struct {
	LdhName     string           `json:"ldhName"`
	Handle      string           `json:"handle"`
	Status      []string         `json:"status"`
	Events      []rdapEvent      `json:"events"`
	Entities    []rdapEntity     `json:"entities"`
	Nameservers []rdapNameserver `json:"nameservers"`
	SecureDNS   *rdapSecureDNS   `json:"secureDNS"`
}

// rdapIPRecord is the subset of an RDAP address response the test reads.
type rdapIPRecord struct {
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Entities     []rdapEntity `json:"entities"`
}

// rdapEvent is one dated entry in an object's lifecycle.
type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

// rdapEntity is a party attached to an RDAP object, tagged with the roles it plays.
type rdapEntity struct {
	Handle     string            `json:"handle"`
	Roles      []string          `json:"roles"`
	VCardArray []json.RawMessage `json:"vcardArray"`
	PublicIds  []rdapPublicID    `json:"publicIds"`
	Entities   []rdapEntity      `json:"entities"`
}

// rdapPublicID is an identifier assigned to a party by an authority outside the registry.
type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// rdapNameserver is one nameserver recorded for a domain at its registry.
type rdapNameserver struct {
	LdhName string `json:"ldhName"`
}

// rdapSecureDNS is the DNSSEC section of a domain record.
type rdapSecureDNS struct {
	DelegationSigned bool `json:"delegationSigned"`
	ZoneSigned       bool `json:"zoneSigned"`
}

// eventDate returns the date of the first event with the given action, comparing action names
// case insensitively because registries disagree about capitalisation.
func (r rdapDomainRecord) eventDate(action string) *time.Time {
	for _, event := range r.Events {
		if !strings.EqualFold(strings.TrimSpace(event.Action), action) {
			continue
		}
		if parsed := parseRDAPTime(event.Date); parsed != nil {
			return parsed
		}
	}
	return nil
}

// entityByRole returns the first entity playing the given role for this address block.
func (r rdapIPRecord) entityByRole(role string) *rdapEntity {
	return findEntityByRole(r.Entities, role)
}

// nameserverNames returns the registry's nameservers as lowercase hostnames.
func (r rdapDomainRecord) nameserverNames() []string {
	names := []string{}
	for _, nameserver := range r.Nameservers {
		if nameserver.LdhName == "" {
			continue
		}
		names = append(names, strings.ToLower(strings.TrimSuffix(nameserver.LdhName, ".")))
	}
	return names
}

// networkName returns the operator's name for the address block, falling back to the registry
// handle when the block is unnamed.
func (r rdapIPRecord) networkName() string {
	if r.Name != "" {
		return r.Name
	}
	return r.Handle
}

// organization returns the best available name for the party, preferring the explicit
// organisation over the display name, which for a company card is usually the same value and
// for a person's card is the individual rather than the company.
func (c vCard) organization() string {
	if c.Organization != "" {
		return c.Organization
	}
	return c.FullName
}

// entityCountry returns the country of the first contact that publishes one.
func (r rdapIPRecord) entityCountry() string {
	for _, entity := range r.Entities {
		if country := parseVCard(entity.VCardArray).Country; country != "" {
			return country
		}
	}
	return ""
}

// publicID returns the identifier assigned to the entity by a given authority.
func (e rdapEntity) publicID(idType string) string {
	for _, id := range e.PublicIds {
		if strings.EqualFold(strings.TrimSpace(id.Type), idType) {
			return id.Identifier
		}
	}
	return ""
}

// findEntityByRole walks a list of entities and their nested entities, returning the first one
// that plays the given role.
func findEntityByRole(entities []rdapEntity, role string) *rdapEntity {
	for index := range entities {
		for _, candidate := range entities[index].Roles {
			if strings.EqualFold(strings.TrimSpace(candidate), role) {
				return &entities[index]
			}
		}
	}

	for index := range entities {
		if nested := findEntityByRole(entities[index].Entities, role); nested != nil {
			return nested
		}
	}
	return nil
}

// vCard holds the three contact card fields the report uses.
type vCard struct {
	FullName     string
	Organization string
	Country      string
}

// parseVCard extracts the used fields from a jCard array.
func parseVCard(raw []json.RawMessage) vCard {
	card := vCard{}
	if len(raw) < 2 {
		return card
	}

	properties := [][]json.RawMessage{}
	if err := json.Unmarshal(raw[1], &properties); err != nil {
		return card
	}

	for _, property := range properties {
		if len(property) < 4 {
			continue
		}

		name := ""
		if err := json.Unmarshal(property[0], &name); err != nil {
			continue
		}

		switch strings.ToLower(name) {
		case "fn":
			card.FullName = vCardStringValue(property[3])
		case "org":
			card.Organization = vCardStringValue(property[3])
		case "adr":
			if country := vCardParameter(property[1], "cc"); country != "" {
				card.Country = strings.ToUpper(country)
				continue
			}
			if card.Country == "" {
				card.Country = strings.ToUpper(vCardAddressCountry(property[3]))
			}
		}
	}
	return card
}

// vCardStringValue reads a property value that is either a plain string or a list whose first
// element is the meaningful one, which is how multi valued properties are encoded.
func vCardStringValue(raw json.RawMessage) string {
	value := ""
	if err := json.Unmarshal(raw, &value); err == nil {
		return strings.TrimSpace(value)
	}

	values := []string{}
	if err := json.Unmarshal(raw, &values); err == nil && len(values) > 0 {
		return strings.TrimSpace(values[0])
	}
	return ""
}

// vCardParameter reads one entry from a property's parameter object.
func vCardParameter(raw json.RawMessage, name string) string {
	parameters := map[string]any{}
	if err := json.Unmarshal(raw, &parameters); err != nil {
		return ""
	}

	value, present := parameters[name]
	if !present {
		return ""
	}
	if text, isText := value.(string); isText {
		return strings.TrimSpace(text)
	}
	return ""
}

// vCardAddressCountry reads the country out of a structured address value, which is a seven
// element array whose last element is the country.
func vCardAddressCountry(raw json.RawMessage) string {
	components := []string{}
	if err := json.Unmarshal(raw, &components); err != nil {
		return ""
	}
	if len(components) < 7 {
		return ""
	}
	return strings.TrimSpace(components[6])
}

// parseRDAPTime parses an RDAP date, accepting the variations registries emit in place of the
// RFC 3339 timestamp the specification calls for.
func parseRDAPTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		utc := parsed.UTC()
		return &utc
	}
	return nil
}

// normalizeStatuses lowercases and trims the EPP status codes of a domain so the evaluation
// can match them without repeating the registries' formatting differences.
func normalizeStatuses(statuses []string) []string {
	normalized := []string{}
	for _, status := range statuses {
		trimmed := strings.ToLower(strings.TrimSpace(status))
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

// --------------------------------------------------------------------------
// Reference datasets and name classification
// --------------------------------------------------------------------------
//
// This file holds the reference datasets the DNS reputation test recognises names and
// addresses against, together with the pure functions that do the recognising. Nothing
// here performs a lookup, so every classification the verdict rests on can be tested
// directly.
//
// The datasets describe categories of infrastructure rather than named offenders. A
// platform appearing here is not accused of anything: free hosting, dynamic DNS and
// tunnelling services are ordinary tools with large legitimate populations. They earn a
// place in the analysis because they share one property phishing depends on — anyone can
// publish a page on them within minutes, under a hostname whose registration data
// describes the platform rather than the person, and abandon it just as quickly. The same
// reasoning applies to the top level domains listed here: they are the ones whose
// registration terms make bulk disposable registration cheapest, which is visible in
// every published abuse ranking, and which says nothing about any individual site.

// entityByRole returns the first entity playing the given role, searching nested entities as
// well so a contact reported inside the registrar is still found.
func (r rdapDomainRecord) entityByRole(role string) *rdapEntity {
	return findEntityByRole(r.Entities, role)
}

// organization returns the organisation the address block is allocated to.
func (r rdapIPRecord) organization() string {
	for _, role := range []string{"registrant", "administrative", "technical", "abuse"} {
		entity := findEntityByRole(r.Entities, role)
		if entity == nil {
			continue
		}
		if name := parseVCard(entity.VCardArray).organization(); name != "" {
			return name
		}
	}
	return ""
}
