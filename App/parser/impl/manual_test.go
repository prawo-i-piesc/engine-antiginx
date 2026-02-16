package impl

import (
	types2 "Engine-AntiGinx/App/parser/config/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParameterParser_Parse(t *testing.T) {
	tests := []types2.CliParserTest{
		// Happy path
		{
			Name:    "Happy path",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "hsts", "--antiBotDetection"},
			WantErr: false,
			Want: []*types2.CommandParameter{
				{
					Name:      "--target",
					Arguments: []string{"example.com"},
				},
				{
					Name:      "--tests",
					Arguments: []string{"https", "hsts"},
				},
				{
					Name:      "--antiBotDetection",
					Arguments: []string{},
				},
			},
		},
		{
			Name:    "Happy path",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "hsts", "--antiBotDetection", "--userAgent"},
			WantErr: false,
			Want: []*types2.CommandParameter{
				{
					Name:      "--target",
					Arguments: []string{"example.com"},
				},
				{
					Name:      "--tests",
					Arguments: []string{"https", "hsts"},
				},
				{
					Name:      "--antiBotDetection",
					Arguments: []string{},
				},
				{
					Name:      "--userAgent",
					Arguments: []string{"Scanner/1.0"},
				},
			},
		},
		{
			Name:    "Happy path",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "hsts", "--antiBotDetection", "--userAgent", "testUA"},
			WantErr: false,
			Want: []*types2.CommandParameter{
				{
					Name:      "--target",
					Arguments: []string{"example.com"},
				},
				{
					Name:      "--tests",
					Arguments: []string{"https", "hsts"},
				},
				{
					Name:      "--antiBotDetection",
					Arguments: []string{},
				},
				{
					Name:      "--userAgent",
					Arguments: []string{"testUA"},
				},
			},
		},

		// Code 100, number of Params
		{
			Name:    "Code 100, number of Params",
			Params:  []string{"scanner", "test"},
			WantErr: true,
		},

		// Code 303, too few arguments
		{
			Name:    "Code 303, too few arguments",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests"},
			WantErr: true,
		},
		// Code 303, arguments required param ignored
		{
			Name:    "Code 303, too few arguments",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "--antiBotDetection"},
			WantErr: true,
		},

		// Code 304, invalid argument
		{
			Name:    "Code 304, invalid argument",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "errorArgument"},
			WantErr: true,
		},
		// Code 304, invalid keyword
		{
			Name:    "Code 304, invalid argument",
			Params:  []string{"scanner", "test", "--target", "example.com", "--invalid", "errorArgument"},
			WantErr: true,
		},

		// Code 305, repetition of arguments
		{
			Name:    "Code 305, repetition of arguments",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "https"},
			WantErr: true,
		},

		// Code 306, too many arguments
		{
			Name:    "Code 306, too many arguments",
			Params:  []string{"scanner", "test", "--target", "example.com", "example2.com", "--tests", "https"},
			WantErr: true,
		},

		// Code 306, arguments passed to flag param
		{
			Name:    "Code 306, too few arguments",
			Params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "hsts", "--antiBotDetection", "argToFlagParam"},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			defer func() {
				r := recover()
				if !tt.WantErr {
					if r != nil {
						t.Errorf("Unexpected panic: %v", r)
					}
					return
				}

				if r == nil {
					t.Errorf("Expected panic but got none")
					return
				}
			}()

			testParser := CreateCommandParser()
			got := testParser.Parse(tt.Params)

			if !tt.WantErr {
				assert.Equal(t, tt.Want, got, "Parsed parameters are not exactly the same.")
			}
		})
	}
}
