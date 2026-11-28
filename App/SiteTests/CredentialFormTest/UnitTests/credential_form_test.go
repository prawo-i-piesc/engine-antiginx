package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CredentialFormTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"net/url"
	"testing"
)

// fixtureCase is one response fixture and the verdict the test must reach on it.
type fixtureCase struct {
	fixture   string
	level     SiteTests.ThreatLevel
	certainty int
	fragments []string
}

func runCases(t *testing.T, cases []fixtureCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, CredentialFormTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
			if result.Certainty != c.certainty {
				t.Errorf("certainty %d, want %d", result.Certainty, c.certainty)
			}
		})
	}
}

// Pages that collect no secret, and forms that keep secrets on the page's own site, are not
// findings.
func TestPagesWithoutFindings(t *testing.T) {
	runCases(t, []fixtureCase{
		{"no_forms.http", SiteTests.None, 100, []string{"The page has no form and no field collecting"}},
		{"search_form.http", SiteTests.None, 100, []string{"None of the 1 form(s) on the page collects"}},
		{"login_same_host.http", SiteTests.None, 100, []string{"All 1 form(s) collecting passwords"}},
		// An empty action submits to the page's own address
		{"login_empty_action.http", SiteTests.None, 100, []string{"submit to the page's own site"}},
		// Another host under the same registered domain is the same site
		{"login_same_site.http", SiteTests.None, 100, []string{"submit to the page's own site"}},
		// Not a URL a browser would submit to, so there is no destination to grade
		{"login_unresolvable.http", SiteTests.None, 100, nil},
	})
}

// Each kind of destination a form collecting a secret can submit to, graded by what it says
// about the page.
func TestFormDestinations(t *testing.T) {
	runCases(t, []fixtureCase{
		{"login_javascript_action.http", SiteTests.Info, 100, []string{"has a javascript: action"}},
		{"card_processor.http", SiteTests.Info, 100, []string{"collecting card details submits to PayPal", "identity provider or payment gateway"}},
		// SSO and payment pages do this legitimately, hence the lower certainty
		{"login_foreign.http", SiteTests.Medium, 70, []string{"collect.unrelated-site.net, a domain unrelated to example.com"}},
		{"login_ip_address.http", SiteTests.High, 100, []string{"submits to the bare address 203.0.113.7"}},
		{"login_insecure_http.http", SiteTests.High, 100, []string{"submits over plain http: to login.unrelated-site.net"}},
		// Plain http is graded before the host is compared, so a page on http posting to itself
		// is still sending its secrets unencrypted
		{"http_page_self_submit.http", SiteTests.High, 100, []string{"submits over plain http: to example.com"}},
		{"login_mailto.http", SiteTests.High, 100, []string{"submits to mailto:owner@unrelated-site.net", "in plain text"}},
	})
}

// A form handing a secret to a data-collection service is graded by the kind of service.
func TestFormCollectors(t *testing.T) {
	runCases(t, []fixtureCase{
		{"login_formspree.http", SiteTests.High, 100, []string{"submits to Formspree (formspree.io)"}},
		{"otp_webhook_site.http", SiteTests.High, 100, []string{"collecting one-time codes submits to Webhook.site"}},
		{"login_telegram.http", SiteTests.Critical, 100, []string{"submits to Telegram Bot API (api.telegram.org)"}},
		// The collector's path must match: api.telegram.org outside /bot is not the Bot API,
		// so it is an ordinary foreign domain
		{"telegram_non_bot_path.http", SiteTests.Medium, 70, []string{"a domain unrelated to example.com"}},
	})
}

// Where a form actually submits is resolved the way a browser resolves it.
func TestActionResolution(t *testing.T) {
	runCases(t, []fixtureCase{
		// A submit button's formaction overrides the form's own action
		{"button_formaction.http", SiteTests.Critical, 100, []string{"(through a submit button's formaction) submits to Discord webhook"}},
		// A relative action resolves against <base>, not against the page address
		{"base_tag_foreign.http", SiteTests.Medium, 70, []string{"collect.unrelated-site.net, a domain unrelated"}},
		// The browser ignores commented-out markup, and so does the test
		{"commented_out_form.http", SiteTests.None, 100, []string{"The page has no form"}},
		// Markup quoted inside a script is a string, not a form on the page
		{"form_markup_inside_script.http", SiteTests.None, 100, []string{"The page has no form"}},
	})
}

// Sensitive fields are recognised by type, autocomplete token, and name or label, with card
// tried before one-time code and one-time code before password.
func TestSensitiveFieldRecognition(t *testing.T) {
	runCases(t, []fixtureCase{
		// "security code" is a card field, not a one-time code
		{"card_fields_mixed.http", SiteTests.Medium, 70, []string{"collecting card details and passwords"}},
		// "sms password" is a one-time code, not a password
		{"otp_sms_password.http", SiteTests.Medium, 70, []string{"collecting one-time codes submits"}},
		{"polish_labels.http", SiteTests.Medium, 70, []string{"collecting passwords, card details and one-time codes"}},
		{"autocomplete_otp.http", SiteTests.Medium, 70, []string{"collecting one-time codes submits"}},
		// Hidden and submit inputs are never typed into, whatever they are named
		{"ignored_hidden_password_name.http", SiteTests.None, 100, []string{"None of the 1 form(s) on the page collects"}},
	})

	result := UnitTestKit.RunResponse(t, CredentialFormTest.New(), "card_fields_mixed.http")
	forms := UnitTestKit.Metadata(t, result)["CredentialForms"].([]any)
	fields := forms[0].(map[string]any)["Fields"].([]any)
	want := []string{"card", "card", "password"}
	if len(fields) != len(want) {
		t.Fatalf("fields %v, want kinds %v", fields, want)
	}
	for index, field := range fields {
		if kind := field.(map[string]any)["Kind"]; kind != want[index] {
			t.Errorf("field %d is %v, want %s", index, kind, want[index])
		}
	}
}

// Inline scripts that send data to a collector are graded by the collector, weigh more on a page
// that collects secrets, and are less certain when no read of field values is recognised.
func TestScriptSubmissions(t *testing.T) {
	runCases(t, []fixtureCase{
		// A password field outside any form, read and sent to a bot
		{"script_telegram_reads_values.http", SiteTests.Critical, 90, []string{"reads the values typed into the page and sends them to Telegram Bot API"}},
		{"script_telegram_no_read.http", SiteTests.Critical, 80, []string{"An inline script sends data to Telegram Bot API"}},
		// JSON-encoded scripts escape the slashes of the URLs they carry
		{"script_json_escaped.http", SiteTests.Critical, 90, []string{"to Discord webhook"}},
		// An onsubmit handler is a script like any other
		{"onsubmit_handler.http", SiteTests.Critical, 90, []string{"to Slack webhook"}},
	})
}

// On a page with no sensitive field a script posting to a form backend is an ordinary contact
// form, while a bot or a request catcher still deserves a look.
func TestScriptsOnPagesWithoutSecrets(t *testing.T) {
	runCases(t, []fixtureCase{
		{"contact_formspree_script.http", SiteTests.None, 100, []string{"None of the 1 form(s) on the page collects"}},
		{"contact_telegram_script.http", SiteTests.Medium, 90, []string{"although the page has no field collecting a secret"}},
		{"contact_webhook_site_script.http", SiteTests.Low, 80, []string{"sends data to Webhook.site"}},
	})
}

// Only scripts the browser runs, that also make a network call, are reported.
func TestScriptsThatAreNotReported(t *testing.T) {
	for _, fixture := range []string{
		"script_link_without_sender.http", // Names a collector, makes no request
		"script_json_ld.http",             // Data, not JavaScript
		"script_external_src.http",        // Not inline; its source is not fetched
	} {
		t.Run(fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, CredentialFormTest.New(), fixture)
			UnitTestKit.Expect(t, result, SiteTests.None, "outside any form, and no inline script sending them")
			if scripts := UnitTestKit.Metadata(t, result)["ScriptSubmissions"].([]any); len(scripts) != 0 {
				t.Errorf("script submissions %v, want none", scripts)
			}
		})
	}
}

// A response whose body or address is missing cannot be inspected; that is reported as Info
// with low certainty rather than as a clean page.
func TestUnreadablePage(t *testing.T) {
	address, _ := url.Parse("https://example.com/")
	cases := map[string]SiteTests.ScanContext{
		"no body":    {Target: address, Response: &http.Response{Request: &http.Request{URL: address}, Header: http.Header{}}},
		"no address": {Target: address, Response: &http.Response{Header: http.Header{}}, Body: []byte("<form></form>")},
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			result := CredentialFormTest.New().Run(ctx)
			UnitTestKit.Expect(t, result, SiteTests.Info, "could not be inspected")
			if result.Certainty != 50 {
				t.Errorf("certainty %d, want 50", result.Certainty)
			}
		})
	}
}
