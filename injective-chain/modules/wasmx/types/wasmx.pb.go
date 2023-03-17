// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: injective/wasmx/v1/wasmx.proto

package types

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Params struct {
	// Set the status to active to indicate that contracts can be executed in begin blocker.
	IsExecutionEnabled bool `protobuf:"varint,1,opt,name=is_execution_enabled,json=isExecutionEnabled,proto3" json:"is_execution_enabled,omitempty"`
	// Maximum aggregate total gas to be used for the contract executions in the BeginBlocker.
	MaxBeginBlockTotalGas uint64 `protobuf:"varint,2,opt,name=max_begin_block_total_gas,json=maxBeginBlockTotalGas,proto3" json:"max_begin_block_total_gas,omitempty"`
	// the maximum gas limit each individual contract can consume in the BeginBlocker.
	MaxContractGasLimit uint64 `protobuf:"varint,3,opt,name=max_contract_gas_limit,json=maxContractGasLimit,proto3" json:"max_contract_gas_limit,omitempty"`
	// min_gas_price defines the minimum gas price the contracts must pay to be executed in the BeginBlocker.
	MinGasPrice uint64 `protobuf:"varint,4,opt,name=min_gas_price,json=minGasPrice,proto3" json:"min_gas_price,omitempty"`
}

func (m *Params) Reset()         { *m = Params{} }
func (m *Params) String() string { return proto.CompactTextString(m) }
func (*Params) ProtoMessage()    {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_6818ff331f2cddc4, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(m, src)
}
func (m *Params) XXX_Size() int {
	return m.Size()
}
func (m *Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Params proto.InternalMessageInfo

func (m *Params) GetIsExecutionEnabled() bool {
	if m != nil {
		return m.IsExecutionEnabled
	}
	return false
}

func (m *Params) GetMaxBeginBlockTotalGas() uint64 {
	if m != nil {
		return m.MaxBeginBlockTotalGas
	}
	return 0
}

func (m *Params) GetMaxContractGasLimit() uint64 {
	if m != nil {
		return m.MaxContractGasLimit
	}
	return 0
}

func (m *Params) GetMinGasPrice() uint64 {
	if m != nil {
		return m.MinGasPrice
	}
	return 0
}

type RegisteredContract struct {
	// limit of gas per BB execution
	GasLimit uint64 `protobuf:"varint,1,opt,name=gas_limit,json=gasLimit,proto3" json:"gas_limit,omitempty"`
	// gas price that contract is willing to pay for execution in BeginBlocker
	GasPrice uint64 `protobuf:"varint,2,opt,name=gas_price,json=gasPrice,proto3" json:"gas_price,omitempty"`
	// is contract currently active
	IsExecutable bool `protobuf:"varint,3,opt,name=is_executable,json=isExecutable,proto3" json:"is_executable,omitempty"`
	// code_id that is allowed to be executed (to prevent malicious updates) - if nil/0 any code_id can be executed
	CodeId uint64 `protobuf:"varint,4,opt,name=code_id,json=codeId,proto3" json:"code_id,omitempty"`
	// optional - admin addr that is allowed to update contract data
	AdminAddress string `protobuf:"bytes,5,opt,name=admin_address,json=adminAddress,proto3" json:"admin_address,omitempty"`
}

func (m *RegisteredContract) Reset()         { *m = RegisteredContract{} }
func (m *RegisteredContract) String() string { return proto.CompactTextString(m) }
func (*RegisteredContract) ProtoMessage()    {}
func (*RegisteredContract) Descriptor() ([]byte, []int) {
	return fileDescriptor_6818ff331f2cddc4, []int{1}
}
func (m *RegisteredContract) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *RegisteredContract) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_RegisteredContract.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *RegisteredContract) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RegisteredContract.Merge(m, src)
}
func (m *RegisteredContract) XXX_Size() int {
	return m.Size()
}
func (m *RegisteredContract) XXX_DiscardUnknown() {
	xxx_messageInfo_RegisteredContract.DiscardUnknown(m)
}

var xxx_messageInfo_RegisteredContract proto.InternalMessageInfo

func (m *RegisteredContract) GetGasLimit() uint64 {
	if m != nil {
		return m.GasLimit
	}
	return 0
}

func (m *RegisteredContract) GetGasPrice() uint64 {
	if m != nil {
		return m.GasPrice
	}
	return 0
}

func (m *RegisteredContract) GetIsExecutable() bool {
	if m != nil {
		return m.IsExecutable
	}
	return false
}

func (m *RegisteredContract) GetCodeId() uint64 {
	if m != nil {
		return m.CodeId
	}
	return 0
}

func (m *RegisteredContract) GetAdminAddress() string {
	if m != nil {
		return m.AdminAddress
	}
	return ""
}

func init() {
	proto.RegisterType((*Params)(nil), "injective.wasmx.v1.Params")
	proto.RegisterType((*RegisteredContract)(nil), "injective.wasmx.v1.RegisteredContract")
}

func init() { proto.RegisterFile("injective/wasmx/v1/wasmx.proto", fileDescriptor_6818ff331f2cddc4) }

var fileDescriptor_6818ff331f2cddc4 = []byte{
	// 420 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x92, 0xb1, 0x8e, 0xd3, 0x30,
	0x1c, 0xc6, 0xeb, 0xa3, 0x94, 0x9e, 0xb9, 0x2e, 0xe6, 0x40, 0x01, 0x44, 0xae, 0x2a, 0x4b, 0x19,
	0x68, 0x38, 0xdd, 0x82, 0xd8, 0x28, 0x3a, 0x55, 0x27, 0x6e, 0x38, 0x45, 0x4c, 0x2c, 0xd1, 0x3f,
	0xf6, 0x5f, 0x39, 0x43, 0x1c, 0x57, 0xb1, 0x5b, 0xc2, 0x5b, 0xf0, 0x08, 0xbc, 0x0b, 0xcb, 0x8d,
	0x95, 0x58, 0x98, 0x10, 0x6a, 0x17, 0x1e, 0x03, 0xd9, 0x6e, 0xc2, 0x6d, 0xce, 0xf7, 0xfb, 0xbe,
	0x2f, 0xfe, 0xdb, 0xa6, 0xb1, 0xac, 0x3e, 0x21, 0xb7, 0x72, 0x8d, 0xc9, 0x17, 0x30, 0xaa, 0x49,
	0xd6, 0xa7, 0x61, 0x31, 0x5b, 0xd6, 0xda, 0x6a, 0xc6, 0x3a, 0x3e, 0x0b, 0xf2, 0xfa, 0xf4, 0xc9,
	0x71, 0xa1, 0x0b, 0xed, 0x71, 0xe2, 0x56, 0xc1, 0x39, 0xf9, 0x49, 0xe8, 0xe0, 0x0a, 0x6a, 0x50,
	0x86, 0xbd, 0xa2, 0xc7, 0xd2, 0x64, 0xd8, 0x20, 0x5f, 0x59, 0xa9, 0xab, 0x0c, 0x2b, 0xc8, 0x4b,
	0x14, 0x11, 0x19, 0x93, 0xe9, 0x30, 0x65, 0xd2, 0x9c, 0xb7, 0xe8, 0x3c, 0x10, 0xf6, 0x9a, 0x3e,
	0x56, 0xd0, 0x64, 0x39, 0x16, 0xb2, 0xca, 0xf2, 0x52, 0xf3, 0xcf, 0x99, 0xd5, 0x16, 0xca, 0xac,
	0x00, 0x13, 0x1d, 0x8c, 0xc9, 0xb4, 0x9f, 0x3e, 0x54, 0xd0, 0xcc, 0x1d, 0x9f, 0x3b, 0xfc, 0xc1,
	0xd1, 0x05, 0x18, 0x76, 0x46, 0x1f, 0xb9, 0x24, 0xd7, 0x95, 0xad, 0x81, 0x5b, 0x17, 0xc8, 0x4a,
	0xa9, 0xa4, 0x8d, 0xee, 0xf8, 0xd8, 0x03, 0x05, 0xcd, 0xbb, 0x3d, 0x5c, 0x80, 0xb9, 0x74, 0x88,
	0x4d, 0xe8, 0x48, 0xc9, 0xca, 0x7b, 0x97, 0xb5, 0xe4, 0x18, 0xf5, 0xbd, 0xf7, 0xbe, 0x92, 0xd5,
	0x02, 0xcc, 0x95, 0x93, 0xde, 0xf4, 0xff, 0x7e, 0x3f, 0x21, 0x93, 0x1f, 0x84, 0xb2, 0x14, 0x0b,
	0x69, 0x2c, 0xd6, 0x28, 0xda, 0x22, 0xf6, 0x94, 0x1e, 0xfe, 0xff, 0x11, 0xf1, 0xe1, 0x61, 0xd1,
	0xb6, 0xef, 0x61, 0x68, 0x3e, 0xe8, 0xa0, 0xaf, 0x65, 0xcf, 0xe9, 0xa8, 0x3b, 0x1b, 0x37, 0xbb,
	0xdf, 0xe6, 0x30, 0x3d, 0x6a, 0x0f, 0xc5, 0x69, 0xec, 0x19, 0xbd, 0xc7, 0xb5, 0xc0, 0x4c, 0x8a,
	0xb0, 0xb3, 0x79, 0xff, 0xe6, 0xf7, 0x09, 0x49, 0x07, 0x4e, 0xbc, 0x10, 0xec, 0x05, 0x1d, 0x81,
	0x70, 0x03, 0x80, 0x10, 0x35, 0x1a, 0x13, 0xdd, 0x1d, 0x93, 0xe9, 0xe1, 0xde, 0x74, 0xe4, 0xd1,
	0xdb, 0x40, 0xc2, 0x14, 0x73, 0xbc, 0xd9, 0xc6, 0x64, 0xb3, 0x8d, 0xc9, 0x9f, 0x6d, 0x4c, 0xbe,
	0xed, 0xe2, 0xde, 0x66, 0x17, 0xf7, 0x7e, 0xed, 0xe2, 0xde, 0xc7, 0xf7, 0x85, 0xb4, 0xd7, 0xab,
	0x7c, 0xc6, 0xb5, 0x4a, 0x2e, 0xda, 0xab, 0xbe, 0x84, 0xdc, 0x24, 0xdd, 0xc5, 0xbf, 0xe4, 0xba,
	0xc6, 0xdb, 0x9f, 0xd7, 0x20, 0xab, 0x44, 0x69, 0xb1, 0x2a, 0xd1, 0xec, 0x5f, 0x8d, 0xfd, 0xba,
	0x44, 0x93, 0x0f, 0xfc, 0x4b, 0x38, 0xfb, 0x17, 0x00, 0x00, 0xff, 0xff, 0x28, 0x53, 0xfd, 0x61,
	0x55, 0x02, 0x00, 0x00,
}

func (this *Params) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Params)
	if !ok {
		that2, ok := that.(Params)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.IsExecutionEnabled != that1.IsExecutionEnabled {
		return false
	}
	if this.MaxBeginBlockTotalGas != that1.MaxBeginBlockTotalGas {
		return false
	}
	if this.MaxContractGasLimit != that1.MaxContractGasLimit {
		return false
	}
	if this.MinGasPrice != that1.MinGasPrice {
		return false
	}
	return true
}
func (this *RegisteredContract) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*RegisteredContract)
	if !ok {
		that2, ok := that.(RegisteredContract)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.GasLimit != that1.GasLimit {
		return false
	}
	if this.GasPrice != that1.GasPrice {
		return false
	}
	if this.IsExecutable != that1.IsExecutable {
		return false
	}
	if this.CodeId != that1.CodeId {
		return false
	}
	if this.AdminAddress != that1.AdminAddress {
		return false
	}
	return true
}
func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Params) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.MinGasPrice != 0 {
		i = encodeVarintWasmx(dAtA, i, uint64(m.MinGasPrice))
		i--
		dAtA[i] = 0x20
	}
	if m.MaxContractGasLimit != 0 {
		i = encodeVarintWasmx(dAtA, i, uint64(m.MaxContractGasLimit))
		i--
		dAtA[i] = 0x18
	}
	if m.MaxBeginBlockTotalGas != 0 {
		i = encodeVarintWasmx(dAtA, i, uint64(m.MaxBeginBlockTotalGas))
		i--
		dAtA[i] = 0x10
	}
	if m.IsExecutionEnabled {
		i--
		if m.IsExecutionEnabled {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *RegisteredContract) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RegisteredContract) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *RegisteredContract) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.AdminAddress) > 0 {
		i -= len(m.AdminAddress)
		copy(dAtA[i:], m.AdminAddress)
		i = encodeVarintWasmx(dAtA, i, uint64(len(m.AdminAddress)))
		i--
		dAtA[i] = 0x2a
	}
	if m.CodeId != 0 {
		i = encodeVarintWasmx(dAtA, i, uint64(m.CodeId))
		i--
		dAtA[i] = 0x20
	}
	if m.IsExecutable {
		i--
		if m.IsExecutable {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x18
	}
	if m.GasPrice != 0 {
		i = encodeVarintWasmx(dAtA, i, uint64(m.GasPrice))
		i--
		dAtA[i] = 0x10
	}
	if m.GasLimit != 0 {
		i = encodeVarintWasmx(dAtA, i, uint64(m.GasLimit))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintWasmx(dAtA []byte, offset int, v uint64) int {
	offset -= sovWasmx(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Params) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.IsExecutionEnabled {
		n += 2
	}
	if m.MaxBeginBlockTotalGas != 0 {
		n += 1 + sovWasmx(uint64(m.MaxBeginBlockTotalGas))
	}
	if m.MaxContractGasLimit != 0 {
		n += 1 + sovWasmx(uint64(m.MaxContractGasLimit))
	}
	if m.MinGasPrice != 0 {
		n += 1 + sovWasmx(uint64(m.MinGasPrice))
	}
	return n
}

func (m *RegisteredContract) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.GasLimit != 0 {
		n += 1 + sovWasmx(uint64(m.GasLimit))
	}
	if m.GasPrice != 0 {
		n += 1 + sovWasmx(uint64(m.GasPrice))
	}
	if m.IsExecutable {
		n += 2
	}
	if m.CodeId != 0 {
		n += 1 + sovWasmx(uint64(m.CodeId))
	}
	l = len(m.AdminAddress)
	if l > 0 {
		n += 1 + l + sovWasmx(uint64(l))
	}
	return n
}

func sovWasmx(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozWasmx(x uint64) (n int) {
	return sovWasmx(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowWasmx
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field IsExecutionEnabled", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.IsExecutionEnabled = bool(v != 0)
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxBeginBlockTotalGas", wireType)
			}
			m.MaxBeginBlockTotalGas = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxBeginBlockTotalGas |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxContractGasLimit", wireType)
			}
			m.MaxContractGasLimit = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxContractGasLimit |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MinGasPrice", wireType)
			}
			m.MinGasPrice = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MinGasPrice |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipWasmx(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthWasmx
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *RegisteredContract) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowWasmx
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: RegisteredContract: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RegisteredContract: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field GasLimit", wireType)
			}
			m.GasLimit = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.GasLimit |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field GasPrice", wireType)
			}
			m.GasPrice = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.GasPrice |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field IsExecutable", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.IsExecutable = bool(v != 0)
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field CodeId", wireType)
			}
			m.CodeId = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.CodeId |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AdminAddress", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthWasmx
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthWasmx
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AdminAddress = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipWasmx(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthWasmx
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipWasmx(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowWasmx
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowWasmx
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthWasmx
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupWasmx
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthWasmx
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthWasmx        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowWasmx          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupWasmx = fmt.Errorf("proto: unexpected end of group")
)