// Package CredentialFormTest implements the Credential Form Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package CredentialFormTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CredentialFormTest/modules"
	"fmt"
	"io"
	"sort"
	"strings"
)

// SensitiveField is one control that collects a password, card details or a one-time code.
type SensitiveField = modules.SensitiveField

// Submission is one place a form submits to.
type Submission = modules.Submission

// ScriptSubmission is one inline script that sends data to a data-collection service.
type ScriptSubmission = modules.ScriptSubmission

// CredentialForm is one form that collects a secret, and everywhere it submits to.
type CredentialForm struct {
	Fields      []SensitiveField `json:"Fields"`
	Submissions []Submission     `json:"Submissions"`
}

// CredentialFormAnalysis is the evidence behind the credential form verdict.
type CredentialFormAnalysis struct {
	PageURL           string             `json:"PageURL"`
	PageDomain        string             `json:"PageDomain"`
	FormsScanned      int                `json:"FormsScanned"`
	CredentialForms   []CredentialForm   `json:"CredentialForms"`
	LooseFields       []SensitiveField   `json:"LooseFields"`
	ScriptSubmissions []ScriptSubmission `json:"ScriptSubmissions"`
}

// The stages own no data: the patterns and datasets in data.go are wired into them here.
var (
	extractor = modules.Extractor{
		Patterns:          markupPatterns,
		FieldPatterns:     fieldPatterns,
		AutocompleteKinds: autocompleteKinds,
		IgnoredInputTypes: ignoredInputTypes,
		ScriptTypes:       executableScriptTypes,
	}

	classifier = modules.Classifier{
		Collectors: collectors,
		Processors: processors,
	}

	inspector = modules.ScriptInspector{
		Patterns:   scriptPatterns,
		Collectors: collectors,
	}
)

// destinationSeverity is how much each destination of a form collecting a secret says about
// the page. Collectors are graded by collectorSeverity instead.
var destinationSeverity = map[string]SiteTests.ThreatLevel{
	modules.DestinationSameHost:     SiteTests.None,
	modules.DestinationSameSite:     SiteTests.None,
	modules.DestinationUnresolvable: SiteTests.None,
	modules.DestinationScripted:     SiteTests.Info,
	modules.DestinationProcessor:    SiteTests.Info,
	modules.DestinationForeign:      SiteTests.Medium,
	modules.DestinationIPAddress:    SiteTests.High,
	modules.DestinationInsecure:     SiteTests.High,
	modules.DestinationMailto:       SiteTests.High,
}

// collectorSeverity is how much handing a secret to each kind of collector says about the
// page. A chat bot receiving passwords is how phishing kits are built; a legitimate site has
// its own backend.
var collectorSeverity = map[string]SiteTests.ThreatLevel{
	modules.CollectorMessenger:      SiteTests.Critical,
	modules.CollectorFormBackend:    SiteTests.High,
	modules.CollectorRequestCatcher: SiteTests.High,
}

// scriptSeverityWithoutSecrets grades a script sending to a collector on a page with no
// sensitive field: contact forms legitimately post to form backends, far less often to bots.
var scriptSeverityWithoutSecrets = map[string]SiteTests.ThreatLevel{
	modules.CollectorMessenger:      SiteTests.Medium,
	modules.CollectorFormBackend:    SiteTests.None,
	modules.CollectorRequestCatcher: SiteTests.Low,
}

// fieldKindLabels name each kind of secret in the operator's terms.
var fieldKindLabels = map[string]string{
	modules.FieldPassword: "passwords",
	modules.FieldCard:     "card details",
	modules.FieldOTP:      "one-time codes",
}

// finding is one graded observation, carried until the verdict and description are assembled.
type finding struct {
	level     SiteTests.ThreatLevel
	certainty int
	sentence  string
}

// New creates a new ResponseTest that checks where a page sends the secrets its forms collect.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			response := params.Response
			if response == nil || response.Request == nil || response.Request.URL == nil || response.Body == nil {
				return unreadableResult("The page address or content is unavailable, so its forms could not be inspected.")
			}

			body, err := io.ReadAll(io.LimitReader(response.Body, maxScannedBody))
			if err != nil {
				return unreadableResult("The page content could not be read, so its forms could not be inspected.")
			}

			address := response.Request.URL
			page := extractor.Parse(string(body), address)
			analysis := CredentialFormAnalysis{
				PageURL:           address.String(),
				PageDomain:        SiteTests.RegistrableDomain(address.Hostname()),
				FormsScanned:      len(page.Forms),
				CredentialForms:   []CredentialForm{},
				LooseFields:       page.LooseFields,
				ScriptSubmissions: []ScriptSubmission{},
			}

			for _, form := range page.Forms {
				if len(form.Fields) == 0 {
					continue
				}
				credentialForm := CredentialForm{Fields: form.Fields, Submissions: []Submission{}}
				submission := classifier.Classify(address, page.Base, form.Action)
				submission.Via, submission.Method = "form", form.Method
				credentialForm.Submissions = append(credentialForm.Submissions, submission)
				for _, action := range form.ButtonActions {
					override := classifier.Classify(address, page.Base, action)
					override.Via, override.Method = "button", form.Method
					credentialForm.Submissions = append(credentialForm.Submissions, override)
				}
				analysis.CredentialForms = append(analysis.CredentialForms, credentialForm)
			}

			for index, script := range page.Scripts {
				analysis.ScriptSubmissions = append(analysis.ScriptSubmissions, inspector.Inspect(index, script)...)
			}

			findings := evaluateFindings(analysis)
			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   verdictCertainty(findings),
				ThreatLevel: verdictThreatLevel(findings),
				Metadata:    analysis,
				Description: buildCredentialFormDescription(analysis, findings),
			}
		},
	}
}

// unreadableResult reports a page whose forms could not be inspected.
func unreadableResult(description string) SiteTests.TestResult {
	return SiteTests.TestResult{
		Name:        TestName,
		Certainty:   credentialUnreadable,
		ThreatLevel: SiteTests.Info,
		Metadata:    nil,
		Description: description,
	}
}

// evaluateFindings grades every form destination and script submission, most severe first.
func evaluateFindings(analysis CredentialFormAnalysis) []finding {
	findings := []finding{}

	for _, form := range analysis.CredentialForms {
		secrets := describeSecrets(form.Fields)
		for _, submission := range form.Submissions {
			if found, graded := gradeSubmission(analysis, secrets, submission); graded {
				findings = append(findings, found)
			}
		}
	}

	pageCollectsSecrets := len(analysis.CredentialForms) > 0 || len(analysis.LooseFields) > 0
	for _, submission := range analysis.ScriptSubmissions {
		findings = append(findings, gradeScript(submission, pageCollectsSecrets))
	}

	sort.SliceStable(findings, func(first int, second int) bool {
		return findings[first].level > findings[second].level
	})
	return findings
}

// gradeSubmission grades where one form collecting a secret submits to. A form submitting to
// the page's own site is not a finding.
func gradeSubmission(analysis CredentialFormAnalysis, secrets string, submission Submission) (finding, bool) {
	target := submission.Host
	if submission.Via == "button" {
		secrets += " (through a submit button's formaction)"
	}

	switch submission.Destination {
	case modules.DestinationCollector:
		return finding{collectorSeverity[submission.CollectorKind], credentialFactCertainty, fmt.Sprintf(
			"A form collecting %s submits to %s (%s), a service that hands submitted data to whoever owns the endpoint. A site collecting its own users' secrets has its own backend; phishing kits send what victims type to Telegram bots, Discord webhooks and hosted form services.",
			secrets, submission.Provider, target)}, true
	case modules.DestinationMailto:
		return finding{destinationSeverity[submission.Destination], credentialFactCertainty, fmt.Sprintf(
			"A form collecting %s submits to %s, which e-mails what was typed in plain text instead of sending it to a server.",
			secrets, submission.Action)}, true
	case modules.DestinationInsecure:
		return finding{destinationSeverity[submission.Destination], credentialFactCertainty, fmt.Sprintf(
			"A form collecting %s submits over plain http: to %s, so the secrets travel unencrypted and can be read or altered by anyone on the network path.",
			secrets, target)}, true
	case modules.DestinationIPAddress:
		return finding{destinationSeverity[submission.Destination], credentialFactCertainty, fmt.Sprintf(
			"A form collecting %s submits to the bare address %s rather than to a named site, which is how throwaway phishing infrastructure is reached.",
			secrets, target)}, true
	case modules.DestinationForeign:
		return finding{destinationSeverity[submission.Destination], credentialForeignCertainty, fmt.Sprintf(
			"A form collecting %s submits to %s, a domain unrelated to %s. Single sign-on and payment pages do this legitimately, but it is also how a phishing page delivers what it collects to its operator.",
			secrets, target, analysis.PageDomain)}, true
	case modules.DestinationProcessor:
		return finding{destinationSeverity[submission.Destination], credentialFactCertainty, fmt.Sprintf(
			"A form collecting %s submits to %s (%s), an identity provider or payment gateway.",
			secrets, submission.Provider, target)}, true
	case modules.DestinationScripted:
		return finding{destinationSeverity[submission.Destination], credentialFactCertainty, fmt.Sprintf(
			"A form collecting %s has a javascript: action, so a script decides where its data goes.",
			secrets)}, true
	}
	return finding{}, false
}

// gradeScript grades one inline script sending data to a collector. It weighs more on a page
// that collects secrets, and is less certain when no read of field values was recognised.
func gradeScript(submission ScriptSubmission, pageCollectsSecrets bool) finding {
	certainty := credentialScriptCertainty
	if !submission.ReadsFieldValues {
		certainty = credentialScriptUncertain
	}

	if !pageCollectsSecrets {
		return finding{scriptSeverityWithoutSecrets[submission.CollectorKind], certainty, fmt.Sprintf(
			"An inline script sends data to %s (%s), although the page has no field collecting a secret.",
			submission.Provider, submission.Endpoint)}
	}

	reads := "sends data"
	if submission.ReadsFieldValues {
		reads = "reads the values typed into the page and sends them"
	}
	return finding{collectorSeverity[submission.CollectorKind], certainty, fmt.Sprintf(
		"An inline script %s to %s (%s) on a page that collects secrets, which is how phishing kits deliver stolen credentials without a visible form action.",
		reads, submission.Provider, submission.Endpoint)}
}

// verdictThreatLevel is the most severe finding.
func verdictThreatLevel(findings []finding) SiteTests.ThreatLevel {
	levels := make([]SiteTests.ThreatLevel, 0, len(findings))
	for _, found := range findings {
		levels = append(levels, found.level)
	}
	return SiteTests.HighestThreatLevel(levels...)
}

// verdictCertainty is the confidence in the most severe finding, or full confidence when the
// page's forms all submit to its own site.
func verdictCertainty(findings []finding) int {
	level := verdictThreatLevel(findings)
	if level == SiteTests.None {
		return credentialFactCertainty
	}
	certainty := 0
	for _, found := range findings {
		if found.level == level && found.certainty > certainty {
			certainty = found.certainty
		}
	}
	return certainty
}

// describeSecrets names the kinds of secret a form collects, in the operator's terms.
func describeSecrets(fields []SensitiveField) string {
	kinds := []string{}
	for _, field := range fields {
		kinds = append(kinds, fieldKindLabels[field.Kind])
	}
	kinds = SiteTests.UniqueStrings(kinds)
	if len(kinds) == 1 {
		return kinds[0]
	}
	return strings.Join(kinds[:len(kinds)-1], ", ") + " and " + kinds[len(kinds)-1]
}

// buildCredentialFormDescription renders the findings in the operator's terms, most severe first.
func buildCredentialFormDescription(analysis CredentialFormAnalysis, findings []finding) string {
	sentences := []string{}
	for _, found := range findings {
		if found.level > SiteTests.None {
			sentences = append(sentences, found.sentence)
		}
	}
	if len(sentences) > 0 {
		return strings.Join(SiteTests.UniqueStrings(sentences), " ")
	}

	if len(analysis.CredentialForms) > 0 {
		return fmt.Sprintf("All %d form(s) collecting passwords, card details or one-time codes submit to the page's own site.", len(analysis.CredentialForms))
	}
	if len(analysis.LooseFields) > 0 {
		return fmt.Sprintf("The page has %d field(s) collecting passwords, card details or one-time codes outside any form, and no inline script sending them to a known data-collection service.", len(analysis.LooseFields))
	}
	if analysis.FormsScanned == 0 {
		return "The page has no form and no field collecting a password, card details or a one-time code."
	}
	return fmt.Sprintf("None of the %d form(s) on the page collects a password, card details or a one-time code.", analysis.FormsScanned)
}
