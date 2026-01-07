package parser

// Params is the static registry of all supported command-line parameters with their configurations.
// Each parameter defines:
//   - Arguments: Whitelist of allowed values (empty means any value accepted)
//   - DefaultVal: Default value when parameter is provided without arguments
//   - ArgRequired: Whether arguments are mandatory
//   - ArgCount: Number of arguments (1 for single, -1 for multiple)
var Params = map[string]parameter{
	"--target": {
		Arguments:   []string{},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    1,
	},
	"--taskId": {
		Arguments:   []string{},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    1,
	},
	"--userAgent": {
		Arguments:   []string{},
		DefaultVal:  "Scanner/1.0",
		ArgRequired: false,
		ArgCount:    1,
	}, /*
		"--referer": {
			Arguments:   []string{},
			DefaultVal:  "",
			ArgRequired: false,
			ArgCount:    1,
		},*/
	"--tests": {
		Arguments: []string{"https", "hsts", "serv-h-a", "csp", "cookie-sec", "js-obf", "xframe", "permissions-policy", "x-content-type-options", "referrer-policy"},
		/*"refererPol", "xxss", "featurePol", "listing", "openRedirect", "fCookies", "fHttpOnly"*/
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    -1,
	}, /*
		"--httpMethods": {
			Arguments: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE",
				"CONNECT", "HEAD"},
			DefaultVal:  "",
			ArgRequired: true,
			ArgCount:    -1,
		},
		"--files": {
			Arguments:   []string{},
			DefaultVal:  "",
			ArgRequired: true,
			ArgCount:    -1,
		},*/
	"--antiBotDetection": {
		Arguments:   []string{},
		DefaultVal:  "", // DefaultVal is not used for flag parameters (ArgCount: 0)
		ArgRequired: false,
		ArgCount:    0,
	},
}
