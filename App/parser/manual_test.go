package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParameterParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		params  []string
		wantErr bool
		want    []*CommandParameter
	}{
		// Happy path
		{
			name:    "Happy path",
			params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "hsts", "--antiBotDetection"},
			wantErr: false,
			want: []*CommandParameter{
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
					Arguments: []string{""},
				},
			},
		},

		// Code 100, number of Params
		{
			name:    "Code 100, number of Params",
			params:  []string{"scanner"},
			wantErr: true,
		},

		// Code 201, test keyword
		{
			name:    "Code 201, test keyword",
			params:  []string{"scanner", "--target", "example.com", "--tests", "https"},
			wantErr: true,
		},

		// Code 303, too few arguments
		{
			name:    "Code 303, too few arguments",
			params:  []string{"scanner", "test", "--target", "example.com", "--tests"},
			wantErr: true,
		},
		// Code 303, arguments required param ignored
		{
			name:    "Code 303, too few arguments",
			params:  []string{"scanner", "test", "--target", "example.com", "--tests", "--antiBotDetection"},
			wantErr: true,
		},

		// Code 304, invalid argument
		{
			name:    "Code 304, invalid argument",
			params:  []string{"scanner", "test", "--target", "example.com", "--tests", "errorArgument"},
			wantErr: true,
		},

		// Code 305, repetition of arguments
		{
			name:    "Code 305, repetition of arguments",
			params:  []string{"scanner", "test", "--target", "example.com", "--tests", "https", "https"},
			wantErr: true,
		},

		// Code 306, too many arguments
		{
			name:    "Code 306, too many arguments",
			params:  []string{"scanner", "test", "--target", "example.com", "example2.com", "--tests", "https"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if !tt.wantErr {
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

			parser := CreateCommandParser()
			got := parser.Parse(tt.params)

			if !tt.wantErr {
				assert.Equal(t, tt.want, got, "Parsed parameters are not exactly the same.")
			}
		})
	}
}
