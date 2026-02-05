package types

type ManualParserTest struct {
	Name    string
	Params  []string
	WantErr bool
	Want    []*CommandParameter
}

type JsonParserTest struct {
	Name         string
	Params       []string
	WantErrCode  int
	Want         []*CommandParameter
	DataToReturn []byte
	FileName     string
	ErrToReturn  error
}

type DesHelpTest struct {
	name       string
	expErrCode int
	filename   string
}
