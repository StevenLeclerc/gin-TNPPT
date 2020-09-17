package crunchyTools

import (
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

type ProtoHandlers struct {
	Handlers InterfaceProtoHandlers
}

type protoHandlersMethods struct {
	InterfaceProtoHandlers
}

type InterfaceProtoHandlers interface {
	WriteProtoToFile(pb proto.Message, filePath string) (output []byte, err error)
	GenerateJSONFromProtob(pb proto.Message) (jsonFromProtob string, err error)
}

func (protobHandler *protoHandlersMethods) WriteProtoToFile(pb proto.Message, filePath string) (output []byte, err error) {
	out, errMarshal := proto.Marshal(pb)
	_ = HasError(errMarshal, "ProtoHandlers - WriteProtoToFile - Marshal", false)
	if errByteToFile := ByteToFile(out, filePath, 0644); errByteToFile != nil {
		return nil, errByteToFile
	}
	return out, nil
}

func (protobHandler *protoHandlersMethods) GenerateJSONFromProtob(pb proto.Message) (jsonFromProtob string, err error) {
	jsonProto := &jsonpb.Marshaler{
		OrigName:     false,
		EnumsAsInts:  false,
		EmitDefaults: false,
		Indent:       "",
		AnyResolver:  nil,
	}
	return jsonProto.MarshalToString(pb)
}

func CreateProtoHandlers() *ProtoHandlers {
	return &ProtoHandlers{
		Handlers: &protoHandlersMethods{},
	}
}
