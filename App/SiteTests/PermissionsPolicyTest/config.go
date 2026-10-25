package PermissionsPolicyTest

// Identity of the test.
const (
	TestId          = "permissions-policy"
	TestName        = "Permissions-Policy Header Analysis"
	TestDescription = "Checks for Permissions-Policy header presence and configuration to assess browser feature access control"
	TestCategory    = "Headers"
)

// A policy naming fewer than minimalPolicyDirectives directives is graded as minimal, and one
// naming at least comprehensivePolicyDirectives, with nothing left open, as comprehensive.
const (
	minimalPolicyDirectives       = 3
	comprehensivePolicyDirectives = 5
)

// missingDescription explains the verdict when the response carries no Permissions-Policy header.
const missingDescription = "Missing Permissions-Policy header - all browser features available to page and embedded content without restrictions"

// Certainty reported when the header is present; an absent header is always reported with
// full certainty.
const Certainty = 90
