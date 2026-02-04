package parser

import (
	"Engine-AntiGinx/App/Errors"
	"fmt"
	"io"
)

type RawJsonParser struct {
	inputSource io.Reader
}

func CreateRawJsonParser(source io.Reader) *RawJsonParser {
	return &RawJsonParser{
		inputSource: source,
	}
}

func (rj *RawJsonParser) Parse(userParameters []string) []*CommandParameter {
	inputBytes, err := io.ReadAll(rj.inputSource)
	if err != nil {
		message := fmt.Sprintf("Raw Json parser error occurred. This could be due to: \n"+
			"- %v", err)
		panic(Errors.Error{
			Code:        100,
			Message:     message,
			Source:      "Raw Json Parser",
			IsRetryable: false,
		})
	}
	commands, err2 := DeserializeTests(inputBytes)
	if err2 != nil {
		panic(err)
	}

	parameters := commands.Parameters
	target := commands.Target
	if target == "" || parameters == nil || len(parameters) == 0 {
		message := `Raw Json parser error occurred. This could be due to:
				- empty target
				- not given or empty parameters`
		panic(Errors.Error{
			Code:        101,
			Message:     message,
			Source:      "Raw Json Parser",
			IsRetryable: false,
		})
	}

	finalList := append([]*CommandParameter{
		{
			Name:      "--target",
			Arguments: []string{target},
		}}, parameters...)
	err3 := CheckParameters(finalList)
	if err3 != nil {
		panic(err3)
	}
	return finalList
}
