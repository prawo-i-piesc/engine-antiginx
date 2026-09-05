package CSPTest

// The directive vocabulary this test judges a policy against.

// criticalDirectives are the directives whose weakening actually opens the door to script
// injection.
var criticalDirectives = []string{"default-src", "script-src", "object-src", "style-src"}

// unsafeValues are the values that hand back the capability the directive was meant to take
// away.
var unsafeValues = []string{"'unsafe-inline'", "'unsafe-eval'", "*"}

// recommendedDirectives are the directives a policy is expected to set, mapped to what each of
// them is for, so a report can say why the missing one mattered.
var recommendedDirectives = map[string]string{
	"default-src":     "Sets fallback policy for resource loading",
	"script-src":      "Controls script execution and loading",
	"object-src":      "Prevents Flash/plugin attacks",
	"style-src":       "Controls stylesheet loading",
	"img-src":         "Controls image loading sources",
	"frame-ancestors": "Prevents clickjacking attacks",
	"base-uri":        "Prevents base tag injection attacks",
	"form-action":     "Controls form submission targets",
}

// importantDirectives are the directives counted when scoring how complete a policy is.
var importantDirectives = []string{"default-src", "script-src", "object-src", "style-src", "frame-ancestors", "base-uri"}
