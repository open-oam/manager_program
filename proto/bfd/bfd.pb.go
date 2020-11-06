// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.6.1
// source: bfd/bfd.proto

package bfd

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Mode int32

const (
	Mode_DEMAND Mode = 0
	Mode_ASYNC  Mode = 1
)

// Enum value maps for Mode.
var (
	Mode_name = map[int32]string{
		0: "DEMAND",
		1: "ASYNC",
	}
	Mode_value = map[string]int32{
		"DEMAND": 0,
		"ASYNC":  1,
	}
)

func (x Mode) Enum() *Mode {
	p := new(Mode)
	*p = x
	return p
}

func (x Mode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Mode) Descriptor() protoreflect.EnumDescriptor {
	return file_bfd_bfd_proto_enumTypes[0].Descriptor()
}

func (Mode) Type() protoreflect.EnumType {
	return &file_bfd_bfd_proto_enumTypes[0]
}

func (x Mode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Mode.Descriptor instead.
func (Mode) EnumDescriptor() ([]byte, []int) {
	return file_bfd_bfd_proto_rawDescGZIP(), []int{0}
}

type CreateSessionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IPAddr      string `protobuf:"bytes,1,opt,name=IPAddr,proto3" json:"IPAddr,omitempty"`
	DesiredTx   uint32 `protobuf:"varint,2,opt,name=DesiredTx,proto3" json:"DesiredTx,omitempty"` // 150 ms
	DesiredRx   uint32 `protobuf:"varint,3,opt,name=DesiredRx,proto3" json:"DesiredRx,omitempty"` // 150 ms
	EchoRx      uint32 `protobuf:"varint,4,opt,name=EchoRx,proto3" json:"EchoRx,omitempty"`       //  50 ms
	DetectMulti uint32 `protobuf:"varint,5,opt,name=DetectMulti,proto3" json:"DetectMulti,omitempty"`
	Mode        Mode   `protobuf:"varint,6,opt,name=mode,proto3,enum=Mode" json:"mode,omitempty"`
}

func (x *CreateSessionRequest) Reset() {
	*x = CreateSessionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_bfd_bfd_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSessionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSessionRequest) ProtoMessage() {}

func (x *CreateSessionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_bfd_bfd_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateSessionRequest.ProtoReflect.Descriptor instead.
func (*CreateSessionRequest) Descriptor() ([]byte, []int) {
	return file_bfd_bfd_proto_rawDescGZIP(), []int{0}
}

func (x *CreateSessionRequest) GetIPAddr() string {
	if x != nil {
		return x.IPAddr
	}
	return ""
}

func (x *CreateSessionRequest) GetDesiredTx() uint32 {
	if x != nil {
		return x.DesiredTx
	}
	return 0
}

func (x *CreateSessionRequest) GetDesiredRx() uint32 {
	if x != nil {
		return x.DesiredRx
	}
	return 0
}

func (x *CreateSessionRequest) GetEchoRx() uint32 {
	if x != nil {
		return x.EchoRx
	}
	return 0
}

func (x *CreateSessionRequest) GetDetectMulti() uint32 {
	if x != nil {
		return x.DetectMulti
	}
	return 0
}

func (x *CreateSessionRequest) GetMode() Mode {
	if x != nil {
		return x.Mode
	}
	return Mode_DEMAND
}

type CreateSessionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IPAddr string `protobuf:"bytes,1,opt,name=IPAddr,proto3" json:"IPAddr,omitempty"`
}

func (x *CreateSessionResponse) Reset() {
	*x = CreateSessionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_bfd_bfd_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSessionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSessionResponse) ProtoMessage() {}

func (x *CreateSessionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_bfd_bfd_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateSessionResponse.ProtoReflect.Descriptor instead.
func (*CreateSessionResponse) Descriptor() ([]byte, []int) {
	return file_bfd_bfd_proto_rawDescGZIP(), []int{1}
}

func (x *CreateSessionResponse) GetIPAddr() string {
	if x != nil {
		return x.IPAddr
	}
	return ""
}

type SessionStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IPAddr string `protobuf:"bytes,1,opt,name=IPAddr,proto3" json:"IPAddr,omitempty"`
}

func (x *SessionStateRequest) Reset() {
	*x = SessionStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_bfd_bfd_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionStateRequest) ProtoMessage() {}

func (x *SessionStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_bfd_bfd_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionStateRequest.ProtoReflect.Descriptor instead.
func (*SessionStateRequest) Descriptor() ([]byte, []int) {
	return file_bfd_bfd_proto_rawDescGZIP(), []int{2}
}

func (x *SessionStateRequest) GetIPAddr() string {
	if x != nil {
		return x.IPAddr
	}
	return ""
}

type SessionStateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	State uint32 `protobuf:"varint,1,opt,name=State,proto3" json:"State,omitempty"`
}

func (x *SessionStateResponse) Reset() {
	*x = SessionStateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_bfd_bfd_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionStateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionStateResponse) ProtoMessage() {}

func (x *SessionStateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_bfd_bfd_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionStateResponse.ProtoReflect.Descriptor instead.
func (*SessionStateResponse) Descriptor() ([]byte, []int) {
	return file_bfd_bfd_proto_rawDescGZIP(), []int{3}
}

func (x *SessionStateResponse) GetState() uint32 {
	if x != nil {
		return x.State
	}
	return 0
}

var File_bfd_bfd_proto protoreflect.FileDescriptor

var file_bfd_bfd_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x62, 0x66, 0x64, 0x2f, 0x62, 0x66, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xbf, 0x01, 0x0a, 0x14, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x49, 0x50, 0x41, 0x64,
	0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72,
	0x12, 0x1c, 0x0a, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x54, 0x78, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x54, 0x78, 0x12, 0x1c,
	0x0a, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x52, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x52, 0x78, 0x12, 0x16, 0x0a, 0x06,
	0x45, 0x63, 0x68, 0x6f, 0x52, 0x78, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x45, 0x63,
	0x68, 0x6f, 0x52, 0x78, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x65, 0x74, 0x65, 0x63, 0x74, 0x4d, 0x75,
	0x6c, 0x74, 0x69, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x44, 0x65, 0x74, 0x65, 0x63,
	0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x12, 0x19, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x05, 0x2e, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x6d, 0x6f, 0x64,
	0x65, 0x22, 0x2f, 0x0a, 0x15, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x49, 0x50,
	0x41, 0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x49, 0x50, 0x41, 0x64,
	0x64, 0x72, 0x22, 0x2d, 0x0a, 0x13, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x49, 0x50, 0x41,
	0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x49, 0x50, 0x41, 0x64, 0x64,
	0x72, 0x22, 0x2c, 0x0a, 0x14, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2a,
	0x1d, 0x0a, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x45, 0x4d, 0x41, 0x4e,
	0x44, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x41, 0x53, 0x59, 0x4e, 0x43, 0x10, 0x01, 0x32, 0x84,
	0x01, 0x0a, 0x03, 0x42, 0x46, 0x44, 0x12, 0x3e, 0x0a, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x15, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16,
	0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x14, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x15, 0x2e, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x30, 0x01, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6f, 0x61, 0x6d, 0x2f, 0x6d, 0x61, 0x6e,
	0x61, 0x67, 0x65, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x62, 0x66, 0x64, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_bfd_bfd_proto_rawDescOnce sync.Once
	file_bfd_bfd_proto_rawDescData = file_bfd_bfd_proto_rawDesc
)

func file_bfd_bfd_proto_rawDescGZIP() []byte {
	file_bfd_bfd_proto_rawDescOnce.Do(func() {
		file_bfd_bfd_proto_rawDescData = protoimpl.X.CompressGZIP(file_bfd_bfd_proto_rawDescData)
	})
	return file_bfd_bfd_proto_rawDescData
}

var file_bfd_bfd_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_bfd_bfd_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_bfd_bfd_proto_goTypes = []interface{}{
	(Mode)(0),                     // 0: Mode
	(*CreateSessionRequest)(nil),  // 1: CreateSessionRequest
	(*CreateSessionResponse)(nil), // 2: CreateSessionResponse
	(*SessionStateRequest)(nil),   // 3: SessionStateRequest
	(*SessionStateResponse)(nil),  // 4: SessionStateResponse
}
var file_bfd_bfd_proto_depIdxs = []int32{
	0, // 0: CreateSessionRequest.mode:type_name -> Mode
	1, // 1: BFD.CreateSession:input_type -> CreateSessionRequest
	3, // 2: BFD.SessionState:input_type -> SessionStateRequest
	2, // 3: BFD.CreateSession:output_type -> CreateSessionResponse
	4, // 4: BFD.SessionState:output_type -> SessionStateResponse
	3, // [3:5] is the sub-list for method output_type
	1, // [1:3] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_bfd_bfd_proto_init() }
func file_bfd_bfd_proto_init() {
	if File_bfd_bfd_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_bfd_bfd_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateSessionRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_bfd_bfd_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateSessionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_bfd_bfd_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionStateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_bfd_bfd_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionStateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_bfd_bfd_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_bfd_bfd_proto_goTypes,
		DependencyIndexes: file_bfd_bfd_proto_depIdxs,
		EnumInfos:         file_bfd_bfd_proto_enumTypes,
		MessageInfos:      file_bfd_bfd_proto_msgTypes,
	}.Build()
	File_bfd_bfd_proto = out.File
	file_bfd_bfd_proto_rawDesc = nil
	file_bfd_bfd_proto_goTypes = nil
	file_bfd_bfd_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// BFDClient is the client API for BFD service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BFDClient interface {
	CreateSession(ctx context.Context, in *CreateSessionRequest, opts ...grpc.CallOption) (*CreateSessionResponse, error)
	SessionState(ctx context.Context, in *SessionStateRequest, opts ...grpc.CallOption) (BFD_SessionStateClient, error)
}

type bFDClient struct {
	cc grpc.ClientConnInterface
}

func NewBFDClient(cc grpc.ClientConnInterface) BFDClient {
	return &bFDClient{cc}
}

func (c *bFDClient) CreateSession(ctx context.Context, in *CreateSessionRequest, opts ...grpc.CallOption) (*CreateSessionResponse, error) {
	out := new(CreateSessionResponse)
	err := c.cc.Invoke(ctx, "/BFD/CreateSession", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bFDClient) SessionState(ctx context.Context, in *SessionStateRequest, opts ...grpc.CallOption) (BFD_SessionStateClient, error) {
	stream, err := c.cc.NewStream(ctx, &_BFD_serviceDesc.Streams[0], "/BFD/SessionState", opts...)
	if err != nil {
		return nil, err
	}
	x := &bFDSessionStateClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type BFD_SessionStateClient interface {
	Recv() (*SessionStateResponse, error)
	grpc.ClientStream
}

type bFDSessionStateClient struct {
	grpc.ClientStream
}

func (x *bFDSessionStateClient) Recv() (*SessionStateResponse, error) {
	m := new(SessionStateResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// BFDServer is the server API for BFD service.
type BFDServer interface {
	CreateSession(context.Context, *CreateSessionRequest) (*CreateSessionResponse, error)
	SessionState(*SessionStateRequest, BFD_SessionStateServer) error
}

// UnimplementedBFDServer can be embedded to have forward compatible implementations.
type UnimplementedBFDServer struct {
}

func (*UnimplementedBFDServer) CreateSession(context.Context, *CreateSessionRequest) (*CreateSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSession not implemented")
}
func (*UnimplementedBFDServer) SessionState(*SessionStateRequest, BFD_SessionStateServer) error {
	return status.Errorf(codes.Unimplemented, "method SessionState not implemented")
}

func RegisterBFDServer(s *grpc.Server, srv BFDServer) {
	s.RegisterService(&_BFD_serviceDesc, srv)
}

func _BFD_CreateSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BFDServer).CreateSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/BFD/CreateSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BFDServer).CreateSession(ctx, req.(*CreateSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BFD_SessionState_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SessionStateRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(BFDServer).SessionState(m, &bFDSessionStateServer{stream})
}

type BFD_SessionStateServer interface {
	Send(*SessionStateResponse) error
	grpc.ServerStream
}

type bFDSessionStateServer struct {
	grpc.ServerStream
}

func (x *bFDSessionStateServer) Send(m *SessionStateResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _BFD_serviceDesc = grpc.ServiceDesc{
	ServiceName: "BFD",
	HandlerType: (*BFDServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateSession",
			Handler:    _BFD_CreateSession_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SessionState",
			Handler:       _BFD_SessionState_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "bfd/bfd.proto",
}
