// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.13.0
// source: proto/bfd/bfd.proto

package bfd

import (
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
	return file_proto_bfd_bfd_proto_enumTypes[0].Descriptor()
}

func (Mode) Type() protoreflect.EnumType {
	return &file_proto_bfd_bfd_proto_enumTypes[0]
}

func (x Mode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Mode.Descriptor instead.
func (Mode) EnumDescriptor() ([]byte, []int) {
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{0}
}

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_bfd_bfd_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_proto_bfd_bfd_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{0}
}

type CreateSessionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IPAddr      string `protobuf:"bytes,1,opt,name=IPAddr,proto3" json:"IPAddr,omitempty"`
	DesiredTx   uint32 `protobuf:"varint,2,opt,name=DesiredTx,proto3" json:"DesiredTx,omitempty"`        // 150,000 us == 150 ms
	DesiredRx   uint32 `protobuf:"varint,3,opt,name=DesiredRx,proto3" json:"DesiredRx,omitempty"`        // 150,000 us == 150 ms
	EchoRx      uint32 `protobuf:"varint,4,opt,name=EchoRx,proto3" json:"EchoRx,omitempty"`              // 50,000  us == 50 ms
	DetectMulti uint32 `protobuf:"varint,5,opt,name=DetectMulti,proto3" json:"DetectMulti,omitempty"`    // 1
	Mode        Mode   `protobuf:"varint,6,opt,name=mode,proto3,enum=bfd.v1.Mode" json:"mode,omitempty"` // DEMAND
}

func (x *CreateSessionRequest) Reset() {
	*x = CreateSessionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_bfd_bfd_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSessionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSessionRequest) ProtoMessage() {}

func (x *CreateSessionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_bfd_bfd_proto_msgTypes[1]
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
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{1}
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

	LocalId uint32 `protobuf:"varint,1,opt,name=LocalId,proto3" json:"LocalId,omitempty"`
}

func (x *CreateSessionResponse) Reset() {
	*x = CreateSessionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_bfd_bfd_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSessionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSessionResponse) ProtoMessage() {}

func (x *CreateSessionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_bfd_bfd_proto_msgTypes[2]
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
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{2}
}

func (x *CreateSessionResponse) GetLocalId() uint32 {
	if x != nil {
		return x.LocalId
	}
	return 0
}

type SessionStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LocalId uint32 `protobuf:"varint,1,opt,name=LocalId,proto3" json:"LocalId,omitempty"`
}

func (x *SessionStateRequest) Reset() {
	*x = SessionStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_bfd_bfd_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionStateRequest) ProtoMessage() {}

func (x *SessionStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_bfd_bfd_proto_msgTypes[3]
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
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{3}
}

func (x *SessionStateRequest) GetLocalId() uint32 {
	if x != nil {
		return x.LocalId
	}
	return 0
}

type SessionInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LocalId uint32 `protobuf:"varint,1,opt,name=LocalId,proto3" json:"LocalId,omitempty"`
	State   uint32 `protobuf:"varint,2,opt,name=State,proto3" json:"State,omitempty"`
	Error   string `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
}

func (x *SessionInfo) Reset() {
	*x = SessionInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_bfd_bfd_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionInfo) ProtoMessage() {}

func (x *SessionInfo) ProtoReflect() protoreflect.Message {
	mi := &file_proto_bfd_bfd_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionInfo.ProtoReflect.Descriptor instead.
func (*SessionInfo) Descriptor() ([]byte, []int) {
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{4}
}

func (x *SessionInfo) GetLocalId() uint32 {
	if x != nil {
		return x.LocalId
	}
	return 0
}

func (x *SessionInfo) GetState() uint32 {
	if x != nil {
		return x.State
	}
	return 0
}

func (x *SessionInfo) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type ChangeModeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LocalId uint32 `protobuf:"varint,1,opt,name=LocalId,proto3" json:"LocalId,omitempty"`
	Mode    Mode   `protobuf:"varint,2,opt,name=Mode,proto3,enum=bfd.v1.Mode" json:"Mode,omitempty"`
}

func (x *ChangeModeRequest) Reset() {
	*x = ChangeModeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_bfd_bfd_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChangeModeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChangeModeRequest) ProtoMessage() {}

func (x *ChangeModeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_bfd_bfd_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChangeModeRequest.ProtoReflect.Descriptor instead.
func (*ChangeModeRequest) Descriptor() ([]byte, []int) {
	return file_proto_bfd_bfd_proto_rawDescGZIP(), []int{5}
}

func (x *ChangeModeRequest) GetLocalId() uint32 {
	if x != nil {
		return x.LocalId
	}
	return 0
}

func (x *ChangeModeRequest) GetMode() Mode {
	if x != nil {
		return x.Mode
	}
	return Mode_DEMAND
}

var File_proto_bfd_bfd_proto protoreflect.FileDescriptor

var file_proto_bfd_bfd_proto_rawDesc = []byte{
	0x0a, 0x13, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x66, 0x64, 0x2f, 0x62, 0x66, 0x64, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x62, 0x66, 0x64, 0x2e, 0x76, 0x31, 0x22, 0x07, 0x0a,
	0x05, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0xc6, 0x01, 0x0a, 0x14, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72,
	0x65, 0x64, 0x54, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x44, 0x65, 0x73, 0x69,
	0x72, 0x65, 0x64, 0x54, 0x78, 0x12, 0x1c, 0x0a, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64,
	0x52, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x44, 0x65, 0x73, 0x69, 0x72, 0x65,
	0x64, 0x52, 0x78, 0x12, 0x16, 0x0a, 0x06, 0x45, 0x63, 0x68, 0x6f, 0x52, 0x78, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x06, 0x45, 0x63, 0x68, 0x6f, 0x52, 0x78, 0x12, 0x20, 0x0a, 0x0b, 0x44,
	0x65, 0x74, 0x65, 0x63, 0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x44, 0x65, 0x74, 0x65, 0x63, 0x74, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x12, 0x20, 0x0a,
	0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x62, 0x66,
	0x64, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x22,
	0x31, 0x0a, 0x15, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x4c, 0x6f, 0x63, 0x61,
	0x6c, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x4c, 0x6f, 0x63, 0x61, 0x6c,
	0x49, 0x64, 0x22, 0x2f, 0x0a, 0x13, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x4c, 0x6f, 0x63,
	0x61, 0x6c, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x4c, 0x6f, 0x63, 0x61,
	0x6c, 0x49, 0x64, 0x22, 0x53, 0x0a, 0x0b, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x49, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x07, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x22, 0x4f, 0x0a, 0x11, 0x43, 0x68, 0x61, 0x6e,
	0x67, 0x65, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a,
	0x07, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x76, 0x31, 0x2e, 0x4d,
	0x6f, 0x64, 0x65, 0x52, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x2a, 0x1d, 0x0a, 0x04, 0x4d, 0x6f, 0x64,
	0x65, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x45, 0x4d, 0x41, 0x4e, 0x44, 0x10, 0x00, 0x12, 0x09, 0x0a,
	0x05, 0x41, 0x53, 0x59, 0x4e, 0x43, 0x10, 0x01, 0x32, 0xcf, 0x01, 0x0a, 0x03, 0x42, 0x46, 0x44,
	0x12, 0x4c, 0x0a, 0x0d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x1c, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1d, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x42,
	0x0a, 0x0c, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1b,
	0x2e, 0x62, 0x66, 0x64, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x62, 0x66,
	0x64, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f,
	0x30, 0x01, 0x12, 0x36, 0x0a, 0x0a, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x6f, 0x64, 0x65,
	0x12, 0x19, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65,
	0x4d, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0d, 0x2e, 0x62, 0x66,
	0x64, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6f, 0x61,
	0x6d, 0x2f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61,
	0x6d, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x66, 0x64, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_bfd_bfd_proto_rawDescOnce sync.Once
	file_proto_bfd_bfd_proto_rawDescData = file_proto_bfd_bfd_proto_rawDesc
)

func file_proto_bfd_bfd_proto_rawDescGZIP() []byte {
	file_proto_bfd_bfd_proto_rawDescOnce.Do(func() {
		file_proto_bfd_bfd_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_bfd_bfd_proto_rawDescData)
	})
	return file_proto_bfd_bfd_proto_rawDescData
}

var file_proto_bfd_bfd_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_proto_bfd_bfd_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_proto_bfd_bfd_proto_goTypes = []interface{}{
	(Mode)(0),                     // 0: bfd.v1.Mode
	(*Empty)(nil),                 // 1: bfd.v1.Empty
	(*CreateSessionRequest)(nil),  // 2: bfd.v1.CreateSessionRequest
	(*CreateSessionResponse)(nil), // 3: bfd.v1.CreateSessionResponse
	(*SessionStateRequest)(nil),   // 4: bfd.v1.SessionStateRequest
	(*SessionInfo)(nil),           // 5: bfd.v1.SessionInfo
	(*ChangeModeRequest)(nil),     // 6: bfd.v1.ChangeModeRequest
}
var file_proto_bfd_bfd_proto_depIdxs = []int32{
	0, // 0: bfd.v1.CreateSessionRequest.mode:type_name -> bfd.v1.Mode
	0, // 1: bfd.v1.ChangeModeRequest.Mode:type_name -> bfd.v1.Mode
	2, // 2: bfd.v1.BFD.CreateSession:input_type -> bfd.v1.CreateSessionRequest
	4, // 3: bfd.v1.BFD.SessionState:input_type -> bfd.v1.SessionStateRequest
	6, // 4: bfd.v1.BFD.ChangeMode:input_type -> bfd.v1.ChangeModeRequest
	3, // 5: bfd.v1.BFD.CreateSession:output_type -> bfd.v1.CreateSessionResponse
	5, // 6: bfd.v1.BFD.SessionState:output_type -> bfd.v1.SessionInfo
	1, // 7: bfd.v1.BFD.ChangeMode:output_type -> bfd.v1.Empty
	5, // [5:8] is the sub-list for method output_type
	2, // [2:5] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_proto_bfd_bfd_proto_init() }
func file_proto_bfd_bfd_proto_init() {
	if File_proto_bfd_bfd_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_bfd_bfd_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
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
		file_proto_bfd_bfd_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_proto_bfd_bfd_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
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
		file_proto_bfd_bfd_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
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
		file_proto_bfd_bfd_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionInfo); i {
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
		file_proto_bfd_bfd_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChangeModeRequest); i {
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
			RawDescriptor: file_proto_bfd_bfd_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_bfd_bfd_proto_goTypes,
		DependencyIndexes: file_proto_bfd_bfd_proto_depIdxs,
		EnumInfos:         file_proto_bfd_bfd_proto_enumTypes,
		MessageInfos:      file_proto_bfd_bfd_proto_msgTypes,
	}.Build()
	File_proto_bfd_bfd_proto = out.File
	file_proto_bfd_bfd_proto_rawDesc = nil
	file_proto_bfd_bfd_proto_goTypes = nil
	file_proto_bfd_bfd_proto_depIdxs = nil
}
