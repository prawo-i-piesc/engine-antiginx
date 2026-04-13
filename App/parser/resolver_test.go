package parser

import (
	"Engine-AntiGinx/App/Errors"
	"reflect"
	"testing"
)

type ResolverTest struct {
	name              string
	userParameters    []string
	wantErr           bool
	expectedCode      int
	expectedParser    reflect.Type // Używamy reflect.Type, aby sprawdzić typ interfejsu
	expectedFormatter reflect.Type
}

func TestResolver_Resolve(t *testing.T) {
	resolver := CreateResolver()
	tests := []ResolverTest{
		{
			name:           "Success - RawJson command",
			userParameters: []string{"bin", "rawjson"},
			wantErr:        false,
			// Sprawdzamy, czy typ zwróconego obiektu zgadza się z tym w rejestrze
			expectedParser:    reflect.TypeOf(whiteList["rawjson"].workerReference),
			expectedFormatter: reflect.TypeOf(whiteList["rawjson"].formatterReference),
		},
		{
			name:              "Success - Help command",
			userParameters:    []string{"bin", "help"},
			wantErr:           false,
			expectedParser:    reflect.TypeOf(whiteList["help"].workerReference),
			expectedFormatter: reflect.TypeOf(whiteList["help"].formatterReference),
		},
		{
			name:           "Panic - Insufficient parameters (Error 100)",
			userParameters: []string{"bin"},
			wantErr:        true,
			expectedCode:   100,
		},
		{
			name:           "Panic - Invalid worker param (Error 101)",
			userParameters: []string{"bin", "invalid_command"},
			wantErr:        true,
			expectedCode:   101,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if tt.wantErr {
					if r == nil {
						t.Errorf("The code did not panic, but we expected Error %d", tt.expectedCode)
					} else {
						err, ok := r.(Errors.Error)
						if !ok || err.Code != tt.expectedCode {
							t.Errorf("Recovered wrong error code. Got %v, want %d", r, tt.expectedCode)
						}
					}
				} else if r != nil {
					t.Errorf("The code panicked unexpectedly: %v", r)
				}
			}()

			p, f := resolver.Resolve(tt.userParameters)

			if !tt.wantErr {
				if reflect.TypeOf(p) != tt.expectedParser {
					t.Errorf("Got parser type %v, want %v", reflect.TypeOf(p), tt.expectedParser)
				}
				if reflect.TypeOf(f) != tt.expectedFormatter {
					t.Errorf("Got formatter type %v, want %v", reflect.TypeOf(f), tt.expectedFormatter)
				}
			}
		})
	}
}
