package parser

import "os"

type FileReader interface {
	ReadFileW(filename string) ([]byte, error)
}

type OSFileReader struct{}

func CreateFileReader() *OSFileReader {
	return &OSFileReader{}
}

func (osf *OSFileReader) ReadFileW(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
