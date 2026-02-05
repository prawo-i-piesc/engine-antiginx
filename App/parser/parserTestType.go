package parser

type manualParserTest struct {
	name    string
	params  []string
	wantErr bool
	want    []*CommandParameter
}

type jsonParserTest struct {
	name         string
	params       []string
	wantErrCode  int
	want         []*CommandParameter
	dataToReturn []byte
	fileName     string
	errToReturn  error
}

type desHelpTest struct {
	name       string
	expErrCode int
	filename   string
}
