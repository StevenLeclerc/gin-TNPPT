package crunchyTools

import (
	"github.com/kardianos/osext"
	"io/ioutil"
	"os"
)

func GetApplicationRootFolder() string {
	actualPath, err := osext.ExecutableFolder()
	_ = HasError(err, "Crunchy-Tools - GetApplicationRootFolder - ExecutableFolder", false)
	return actualPath
}

func OpenFile(pathFile string) *os.File {
	dataFromFile, errOpenFile := os.OpenFile(pathFile, 0, 0755)
	_ = HasError(errOpenFile, "Crunchy-Tools - FileHelpers - OpenFile", false)
	return dataFromFile
}

func StringToFile(source string, fileName string, permission os.FileMode) error {
	sourceBytes := []byte(source)
	errWriteFile := ioutil.WriteFile(fileName, sourceBytes, permission)
	return HasError(errWriteFile, "Crunchy-Tools - FileHelpers - StringToFile", false)
}

func ByteToFile(source []byte, fileName string, permission os.FileMode) error {
	errWriteFile := ioutil.WriteFile(fileName, source, permission)
	return HasError(errWriteFile, "Crunchy-Tools - FileHelpers - ByteToFile", false)
}

func FileToString(file *os.File) string {
	stringFile, errStringify := ioutil.ReadAll(file)
	_ = HasError(errStringify, "Crunchy-Tools - FileHelpers - FileToString", false)
	return string(stringFile)
}

func FileToByte(file *os.File) []byte {
	stringFile, errStringify := ioutil.ReadAll(file)
	_ = HasError(errStringify, "Crunchy-Tools - FileHelpers - FileToByte", false)
	return stringFile
}
