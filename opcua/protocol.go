// Copyright 2025 Edgeo SCADA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opcua

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"
)

// Message types for OPC UA binary protocol.
const (
	MessageTypeHello        = "HEL"
	MessageTypeAcknowledge  = "ACK"
	MessageTypeError        = "ERR"
	MessageTypeOpenChannel  = "OPN"
	MessageTypeCloseChannel = "CLO"
	MessageTypeMessage      = "MSG"
)

// Chunk types.
const (
	ChunkTypeFinal       byte = 'F'
	ChunkTypeIntermediate byte = 'C'
	ChunkTypeAbort       byte = 'A'
)

// MessageHeader represents the header of an OPC UA message.
type MessageHeader struct {
	MessageType [3]byte
	ChunkType   byte
	MessageSize uint32
}

// Encode encodes the message header.
func (h *MessageHeader) Encode() []byte {
	buf := make([]byte, 8)
	copy(buf[0:3], h.MessageType[:])
	buf[3] = h.ChunkType
	binary.LittleEndian.PutUint32(buf[4:8], h.MessageSize)
	return buf
}

// Decode decodes the message header from bytes.
func (h *MessageHeader) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: header too short", ErrInvalidMessage)
	}
	copy(h.MessageType[:], data[0:3])
	h.ChunkType = data[3]
	h.MessageSize = binary.LittleEndian.Uint32(data[4:8])
	return nil
}

// HelloMessage represents an OPC UA Hello message.
type HelloMessage struct {
	ProtocolVersion   uint32
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32
	MaxChunkCount     uint32
	EndpointURL       string
}

// Encode encodes the Hello message.
func (m *HelloMessage) Encode() []byte {
	urlBytes := []byte(m.EndpointURL)
	buf := make([]byte, 28+len(urlBytes))

	binary.LittleEndian.PutUint32(buf[0:4], m.ProtocolVersion)
	binary.LittleEndian.PutUint32(buf[4:8], m.ReceiveBufferSize)
	binary.LittleEndian.PutUint32(buf[8:12], m.SendBufferSize)
	binary.LittleEndian.PutUint32(buf[12:16], m.MaxMessageSize)
	binary.LittleEndian.PutUint32(buf[16:20], m.MaxChunkCount)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(len(urlBytes)))
	copy(buf[24:], urlBytes)

	return buf
}

// Decode decodes the Hello message from bytes.
func (m *HelloMessage) Decode(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("%w: hello message too short", ErrInvalidMessage)
	}

	m.ProtocolVersion = binary.LittleEndian.Uint32(data[0:4])
	m.ReceiveBufferSize = binary.LittleEndian.Uint32(data[4:8])
	m.SendBufferSize = binary.LittleEndian.Uint32(data[8:12])
	m.MaxMessageSize = binary.LittleEndian.Uint32(data[12:16])
	m.MaxChunkCount = binary.LittleEndian.Uint32(data[16:20])

	urlLen := binary.LittleEndian.Uint32(data[20:24])
	if len(data) < int(24+urlLen) {
		return fmt.Errorf("%w: endpoint URL truncated", ErrInvalidMessage)
	}
	m.EndpointURL = string(data[24 : 24+urlLen])

	return nil
}

// AcknowledgeMessage represents an OPC UA Acknowledge message.
type AcknowledgeMessage struct {
	ProtocolVersion   uint32
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32
	MaxChunkCount     uint32
}

// Encode encodes the Acknowledge message.
func (m *AcknowledgeMessage) Encode() []byte {
	buf := make([]byte, 20)
	binary.LittleEndian.PutUint32(buf[0:4], m.ProtocolVersion)
	binary.LittleEndian.PutUint32(buf[4:8], m.ReceiveBufferSize)
	binary.LittleEndian.PutUint32(buf[8:12], m.SendBufferSize)
	binary.LittleEndian.PutUint32(buf[12:16], m.MaxMessageSize)
	binary.LittleEndian.PutUint32(buf[16:20], m.MaxChunkCount)
	return buf
}

// Decode decodes the Acknowledge message from bytes.
func (m *AcknowledgeMessage) Decode(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("%w: acknowledge message too short", ErrInvalidMessage)
	}

	m.ProtocolVersion = binary.LittleEndian.Uint32(data[0:4])
	m.ReceiveBufferSize = binary.LittleEndian.Uint32(data[4:8])
	m.SendBufferSize = binary.LittleEndian.Uint32(data[8:12])
	m.MaxMessageSize = binary.LittleEndian.Uint32(data[12:16])
	m.MaxChunkCount = binary.LittleEndian.Uint32(data[16:20])

	return nil
}

// ErrorMessage represents an OPC UA Error message.
type ErrorMessage struct {
	Error  uint32
	Reason string
}

// Encode encodes the Error message.
func (m *ErrorMessage) Encode() []byte {
	reasonBytes := []byte(m.Reason)
	buf := make([]byte, 8+len(reasonBytes))
	binary.LittleEndian.PutUint32(buf[0:4], m.Error)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(reasonBytes)))
	copy(buf[8:], reasonBytes)
	return buf
}

// Decode decodes the Error message from bytes.
func (m *ErrorMessage) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: error message too short", ErrInvalidMessage)
	}

	m.Error = binary.LittleEndian.Uint32(data[0:4])
	reasonLen := int32(binary.LittleEndian.Uint32(data[4:8]))
	// In OPC UA, a string length of -1 means null/empty string
	if reasonLen < 0 {
		m.Reason = ""
		return nil
	}
	if len(data) < int(8+reasonLen) {
		return fmt.Errorf("%w: error reason truncated", ErrInvalidMessage)
	}
	m.Reason = string(data[8 : 8+reasonLen])

	return nil
}

// SecureChannelHeader represents the secure channel header.
type SecureChannelHeader struct {
	SecureChannelID uint32
}

// AsymmetricSecurityHeader represents the asymmetric security header.
type AsymmetricSecurityHeader struct {
	SecurityPolicyURI    string
	SenderCertificate    []byte
	ReceiverCertificate  []byte
}

// SymmetricSecurityHeader represents the symmetric security header.
type SymmetricSecurityHeader struct {
	TokenID uint32
}

// SequenceHeader represents the sequence header.
type SequenceHeader struct {
	SequenceNumber uint32
	RequestID      uint32
}

// RequestIDGenerator generates unique request IDs.
type RequestIDGenerator struct {
	counter uint32
}

// Next returns the next request ID.
func (g *RequestIDGenerator) Next() uint32 {
	return atomic.AddUint32(&g.counter, 1)
}

// SequenceNumberGenerator generates sequence numbers.
type SequenceNumberGenerator struct {
	counter uint32
}

// Next returns the next sequence number.
func (g *SequenceNumberGenerator) Next() uint32 {
	return atomic.AddUint32(&g.counter, 1)
}

// Encoder provides methods for encoding OPC UA types.
type Encoder struct {
	buf *bytes.Buffer
}

// NewEncoder creates a new encoder.
func NewEncoder() *Encoder {
	return &Encoder{buf: new(bytes.Buffer)}
}

// Bytes returns the encoded bytes.
func (e *Encoder) Bytes() []byte {
	return e.buf.Bytes()
}

// Reset resets the encoder.
func (e *Encoder) Reset() {
	e.buf.Reset()
}

// WriteBoolean writes a boolean value.
func (e *Encoder) WriteBoolean(v bool) {
	if v {
		e.buf.WriteByte(1)
	} else {
		e.buf.WriteByte(0)
	}
}

// WriteByte writes a byte value.
func (e *Encoder) WriteByte(v byte) {
	e.buf.WriteByte(v)
}

// WriteSByte writes a signed byte value.
func (e *Encoder) WriteSByte(v int8) {
	e.buf.WriteByte(byte(v))
}

// WriteUInt16 writes a uint16 value.
func (e *Encoder) WriteUInt16(v uint16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	e.buf.Write(buf[:])
}

// WriteInt16 writes an int16 value.
func (e *Encoder) WriteInt16(v int16) {
	e.WriteUInt16(uint16(v))
}

// WriteUInt32 writes a uint32 value.
func (e *Encoder) WriteUInt32(v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	e.buf.Write(buf[:])
}

// WriteInt32 writes an int32 value.
func (e *Encoder) WriteInt32(v int32) {
	e.WriteUInt32(uint32(v))
}

// WriteUInt64 writes a uint64 value.
func (e *Encoder) WriteUInt64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	e.buf.Write(buf[:])
}

// WriteInt64 writes an int64 value.
func (e *Encoder) WriteInt64(v int64) {
	e.WriteUInt64(uint64(v))
}

// WriteFloat writes a float32 value.
func (e *Encoder) WriteFloat(v float32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32FromFloat32(v))
	e.buf.Write(buf[:])
}

// WriteDouble writes a float64 value.
func (e *Encoder) WriteDouble(v float64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64FromFloat64(v))
	e.buf.Write(buf[:])
}

// WriteString writes a string value.
func (e *Encoder) WriteString(v string) {
	if v == "" {
		e.WriteInt32(-1)
		return
	}
	e.WriteInt32(int32(len(v)))
	e.buf.WriteString(v)
}

// WriteByteString writes a byte string value.
func (e *Encoder) WriteByteString(v []byte) {
	if v == nil {
		e.WriteInt32(-1)
		return
	}
	e.WriteInt32(int32(len(v)))
	e.buf.Write(v)
}

// WriteDateTime writes a DateTime value.
func (e *Encoder) WriteDateTime(t time.Time) {
	if t.IsZero() {
		e.WriteInt64(0)
		return
	}
	// OPC UA DateTime is 100-nanosecond intervals since January 1, 1601
	const epochDiff = 116444736000000000 // 100-ns intervals from 1601 to 1970
	ns := t.UnixNano()
	ticks := ns/100 + epochDiff
	e.WriteInt64(ticks)
}

// WriteGUID writes a GUID value.
func (e *Encoder) WriteGUID(v [16]byte) {
	// GUID encoding: Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE), Data4 (8 bytes)
	e.WriteUInt32(binary.BigEndian.Uint32(v[0:4]))
	e.WriteUInt16(binary.BigEndian.Uint16(v[4:6]))
	e.WriteUInt16(binary.BigEndian.Uint16(v[6:8]))
	e.buf.Write(v[8:16])
}

// WriteNodeID writes a NodeID value.
func (e *Encoder) WriteNodeID(n NodeID) {
	switch n.Type {
	case NodeIDTypeNumeric:
		if n.Namespace == 0 && n.Numeric <= 255 {
			// Two-byte numeric
			e.WriteByte(0x00)
			e.WriteByte(byte(n.Numeric))
		} else if n.Namespace <= 255 && n.Numeric <= 65535 {
			// Four-byte numeric
			e.WriteByte(0x01)
			e.WriteByte(byte(n.Namespace))
			e.WriteUInt16(uint16(n.Numeric))
		} else {
			// Numeric
			e.WriteByte(0x02)
			e.WriteUInt16(n.Namespace)
			e.WriteUInt32(n.Numeric)
		}
	case NodeIDTypeString:
		e.WriteByte(0x03)
		e.WriteUInt16(n.Namespace)
		e.WriteString(n.String)
	case NodeIDTypeGUID:
		e.WriteByte(0x04)
		e.WriteUInt16(n.Namespace)
		e.WriteGUID(n.GUID)
	case NodeIDTypeOpaque:
		e.WriteByte(0x05)
		e.WriteUInt16(n.Namespace)
		e.WriteByteString(n.Opaque)
	}
}

// WriteQualifiedName writes a QualifiedName value.
func (e *Encoder) WriteQualifiedName(q QualifiedName) {
	e.WriteUInt16(q.NamespaceIndex)
	e.WriteString(q.Name)
}

// WriteLocalizedText writes a LocalizedText value.
func (e *Encoder) WriteLocalizedText(l LocalizedText) {
	var encodingMask byte
	if l.Locale != "" {
		encodingMask |= 0x01
	}
	if l.Text != "" {
		encodingMask |= 0x02
	}
	e.WriteByte(encodingMask)
	if l.Locale != "" {
		e.WriteString(l.Locale)
	}
	if l.Text != "" {
		e.WriteString(l.Text)
	}
}

// WriteStatusCode writes a StatusCode value.
func (e *Encoder) WriteStatusCode(s StatusCode) {
	e.WriteUInt32(uint32(s))
}

// Decoder provides methods for decoding OPC UA types.
type Decoder struct {
	data []byte
	pos  int
}

// NewDecoder creates a new decoder.
func NewDecoder(data []byte) *Decoder {
	return &Decoder{data: data, pos: 0}
}

// Remaining returns the number of remaining bytes.
func (d *Decoder) Remaining() int {
	return len(d.data) - d.pos
}

// Skip skips n bytes in the decoder.
func (d *Decoder) Skip(n int) {
	d.pos += n
	if d.pos > len(d.data) {
		d.pos = len(d.data)
	}
}

// ReadBoolean reads a boolean value.
func (d *Decoder) ReadBoolean() (bool, error) {
	if d.pos >= len(d.data) {
		return false, fmt.Errorf("%w: unexpected end of data", ErrInvalidMessage)
	}
	v := d.data[d.pos] != 0
	d.pos++
	return v, nil
}

// ReadByte reads a byte value.
func (d *Decoder) ReadByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, fmt.Errorf("%w: unexpected end of data", ErrInvalidMessage)
	}
	v := d.data[d.pos]
	d.pos++
	return v, nil
}

// ReadSByte reads a signed byte value.
func (d *Decoder) ReadSByte() (int8, error) {
	b, err := d.ReadByte()
	return int8(b), err
}

// ReadUInt16 reads a uint16 value.
func (d *Decoder) ReadUInt16() (uint16, error) {
	if d.pos+2 > len(d.data) {
		return 0, fmt.Errorf("%w: unexpected end of data", ErrInvalidMessage)
	}
	v := binary.LittleEndian.Uint16(d.data[d.pos:])
	d.pos += 2
	return v, nil
}

// ReadInt16 reads an int16 value.
func (d *Decoder) ReadInt16() (int16, error) {
	v, err := d.ReadUInt16()
	return int16(v), err
}

// ReadUInt32 reads a uint32 value.
func (d *Decoder) ReadUInt32() (uint32, error) {
	if d.pos+4 > len(d.data) {
		return 0, fmt.Errorf("%w: unexpected end of data", ErrInvalidMessage)
	}
	v := binary.LittleEndian.Uint32(d.data[d.pos:])
	d.pos += 4
	return v, nil
}

// ReadInt32 reads an int32 value.
func (d *Decoder) ReadInt32() (int32, error) {
	v, err := d.ReadUInt32()
	return int32(v), err
}

// ReadUInt64 reads a uint64 value.
func (d *Decoder) ReadUInt64() (uint64, error) {
	if d.pos+8 > len(d.data) {
		return 0, fmt.Errorf("%w: unexpected end of data", ErrInvalidMessage)
	}
	v := binary.LittleEndian.Uint64(d.data[d.pos:])
	d.pos += 8
	return v, nil
}

// ReadInt64 reads an int64 value.
func (d *Decoder) ReadInt64() (int64, error) {
	v, err := d.ReadUInt64()
	return int64(v), err
}

// ReadFloat reads a float32 value.
func (d *Decoder) ReadFloat() (float32, error) {
	v, err := d.ReadUInt32()
	if err != nil {
		return 0, err
	}
	return float32FromUint32(v), nil
}

// ReadDouble reads a float64 value.
func (d *Decoder) ReadDouble() (float64, error) {
	v, err := d.ReadUInt64()
	if err != nil {
		return 0, err
	}
	return float64FromUint64(v), nil
}

// ReadString reads a string value.
func (d *Decoder) ReadString() (string, error) {
	length, err := d.ReadInt32()
	if err != nil {
		return "", err
	}
	if length < 0 {
		return "", nil
	}
	if d.pos+int(length) > len(d.data) {
		return "", fmt.Errorf("%w: string truncated", ErrInvalidMessage)
	}
	v := string(d.data[d.pos : d.pos+int(length)])
	d.pos += int(length)
	return v, nil
}

// ReadByteString reads a byte string value.
func (d *Decoder) ReadByteString() ([]byte, error) {
	length, err := d.ReadInt32()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, nil
	}
	if d.pos+int(length) > len(d.data) {
		return nil, fmt.Errorf("%w: byte string truncated", ErrInvalidMessage)
	}
	v := make([]byte, length)
	copy(v, d.data[d.pos:d.pos+int(length)])
	d.pos += int(length)
	return v, nil
}

// ReadDateTime reads a DateTime value.
func (d *Decoder) ReadDateTime() (time.Time, error) {
	ticks, err := d.ReadInt64()
	if err != nil {
		return time.Time{}, err
	}
	if ticks == 0 {
		return time.Time{}, nil
	}
	const epochDiff = 116444736000000000
	ns := (ticks - epochDiff) * 100
	return time.Unix(0, ns).UTC(), nil
}

// ReadGUID reads a GUID value.
func (d *Decoder) ReadGUID() ([16]byte, error) {
	var guid [16]byte
	if d.pos+16 > len(d.data) {
		return guid, fmt.Errorf("%w: GUID truncated", ErrInvalidMessage)
	}

	// Data1 (4 bytes LE)
	data1 := binary.LittleEndian.Uint32(d.data[d.pos:])
	binary.BigEndian.PutUint32(guid[0:4], data1)
	d.pos += 4

	// Data2 (2 bytes LE)
	data2, _ := d.ReadUInt16()
	binary.BigEndian.PutUint16(guid[4:6], data2)

	// Data3 (2 bytes LE)
	data3, _ := d.ReadUInt16()
	binary.BigEndian.PutUint16(guid[6:8], data3)

	// Data4 (8 bytes)
	copy(guid[8:16], d.data[d.pos:d.pos+8])
	d.pos += 8

	return guid, nil
}

// ReadNodeID reads a NodeID value.
func (d *Decoder) ReadNodeID() (NodeID, error) {
	encodingByte, err := d.ReadByte()
	if err != nil {
		return NodeID{}, err
	}

	nodeIDType := encodingByte & 0x0F

	switch nodeIDType {
	case 0x00: // Two-byte numeric
		id, err := d.ReadByte()
		if err != nil {
			return NodeID{}, err
		}
		return NodeID{Type: NodeIDTypeNumeric, Namespace: 0, Numeric: uint32(id)}, nil

	case 0x01: // Four-byte numeric
		ns, err := d.ReadByte()
		if err != nil {
			return NodeID{}, err
		}
		id, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		return NodeID{Type: NodeIDTypeNumeric, Namespace: uint16(ns), Numeric: uint32(id)}, nil

	case 0x02: // Numeric
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		id, err := d.ReadUInt32()
		if err != nil {
			return NodeID{}, err
		}
		return NodeID{Type: NodeIDTypeNumeric, Namespace: ns, Numeric: id}, nil

	case 0x03: // String
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		str, err := d.ReadString()
		if err != nil {
			return NodeID{}, err
		}
		return NodeID{Type: NodeIDTypeString, Namespace: ns, String: str}, nil

	case 0x04: // GUID
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		guid, err := d.ReadGUID()
		if err != nil {
			return NodeID{}, err
		}
		return NodeID{Type: NodeIDTypeGUID, Namespace: ns, GUID: guid}, nil

	case 0x05: // Opaque
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		opaque, err := d.ReadByteString()
		if err != nil {
			return NodeID{}, err
		}
		return NodeID{Type: NodeIDTypeOpaque, Namespace: ns, Opaque: opaque}, nil

	default:
		return NodeID{}, fmt.Errorf("%w: unknown NodeID type %d", ErrInvalidMessage, nodeIDType)
	}
}

// ReadExpandedNodeID reads an ExpandedNodeID value.
// ExpandedNodeID extends NodeID with optional NamespaceURI and ServerIndex.
func (d *Decoder) ReadExpandedNodeID() (NodeID, error) {
	encodingByte, err := d.ReadByte()
	if err != nil {
		return NodeID{}, err
	}

	nodeIDType := encodingByte & 0x0F
	hasNamespaceURI := encodingByte&0x80 != 0
	hasServerIndex := encodingByte&0x40 != 0

	var nodeID NodeID

	switch nodeIDType {
	case 0x00: // Two-byte numeric
		id, err := d.ReadByte()
		if err != nil {
			return NodeID{}, err
		}
		nodeID = NodeID{Type: NodeIDTypeNumeric, Namespace: 0, Numeric: uint32(id)}

	case 0x01: // Four-byte numeric
		ns, err := d.ReadByte()
		if err != nil {
			return NodeID{}, err
		}
		id, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		nodeID = NodeID{Type: NodeIDTypeNumeric, Namespace: uint16(ns), Numeric: uint32(id)}

	case 0x02: // Numeric
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		id, err := d.ReadUInt32()
		if err != nil {
			return NodeID{}, err
		}
		nodeID = NodeID{Type: NodeIDTypeNumeric, Namespace: ns, Numeric: id}

	case 0x03: // String
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		str, err := d.ReadString()
		if err != nil {
			return NodeID{}, err
		}
		nodeID = NodeID{Type: NodeIDTypeString, Namespace: ns, String: str}

	case 0x04: // GUID
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		guid, err := d.ReadGUID()
		if err != nil {
			return NodeID{}, err
		}
		nodeID = NodeID{Type: NodeIDTypeGUID, Namespace: ns, GUID: guid}

	case 0x05: // Opaque
		ns, err := d.ReadUInt16()
		if err != nil {
			return NodeID{}, err
		}
		opaque, err := d.ReadByteString()
		if err != nil {
			return NodeID{}, err
		}
		nodeID = NodeID{Type: NodeIDTypeOpaque, Namespace: ns, Opaque: opaque}

	default:
		return NodeID{}, fmt.Errorf("%w: unknown NodeID type %d", ErrInvalidMessage, nodeIDType)
	}

	// Skip NamespaceURI if present
	if hasNamespaceURI {
		_, err := d.ReadString()
		if err != nil {
			return NodeID{}, err
		}
	}

	// Skip ServerIndex if present
	if hasServerIndex {
		_, err := d.ReadUInt32()
		if err != nil {
			return NodeID{}, err
		}
	}

	return nodeID, nil
}

// ReadQualifiedName reads a QualifiedName value.
func (d *Decoder) ReadQualifiedName() (QualifiedName, error) {
	ns, err := d.ReadUInt16()
	if err != nil {
		return QualifiedName{}, err
	}
	name, err := d.ReadString()
	if err != nil {
		return QualifiedName{}, err
	}
	return QualifiedName{NamespaceIndex: ns, Name: name}, nil
}

// ReadLocalizedText reads a LocalizedText value.
func (d *Decoder) ReadLocalizedText() (LocalizedText, error) {
	encodingMask, err := d.ReadByte()
	if err != nil {
		return LocalizedText{}, err
	}

	var lt LocalizedText
	if encodingMask&0x01 != 0 {
		lt.Locale, err = d.ReadString()
		if err != nil {
			return LocalizedText{}, err
		}
	}
	if encodingMask&0x02 != 0 {
		lt.Text, err = d.ReadString()
		if err != nil {
			return LocalizedText{}, err
		}
	}
	return lt, nil
}

// ReadStatusCode reads a StatusCode value.
func (d *Decoder) ReadStatusCode() (StatusCode, error) {
	v, err := d.ReadUInt32()
	return StatusCode(v), err
}

// ReadDataValue reads a DataValue value.
func (d *Decoder) ReadDataValue() (DataValue, error) {
	encodingMask, err := d.ReadByte()
	if err != nil {
		return DataValue{}, err
	}

	var dv DataValue

	if encodingMask&0x01 != 0 {
		v, err := d.ReadVariant()
		if err != nil {
			return DataValue{}, err
		}
		dv.Value = &v
	}

	if encodingMask&0x02 != 0 {
		dv.StatusCode, err = d.ReadStatusCode()
		if err != nil {
			return DataValue{}, err
		}
	}

	if encodingMask&0x04 != 0 {
		dv.SourceTimestamp, err = d.ReadDateTime()
		if err != nil {
			return DataValue{}, err
		}
	}

	if encodingMask&0x10 != 0 {
		dv.SourcePicoseconds, err = d.ReadUInt16()
		if err != nil {
			return DataValue{}, err
		}
	}

	if encodingMask&0x08 != 0 {
		dv.ServerTimestamp, err = d.ReadDateTime()
		if err != nil {
			return DataValue{}, err
		}
	}

	if encodingMask&0x20 != 0 {
		dv.ServerPicoseconds, err = d.ReadUInt16()
		if err != nil {
			return DataValue{}, err
		}
	}

	return dv, nil
}

// ReadVariant reads a Variant value.
func (d *Decoder) ReadVariant() (Variant, error) {
	encodingMask, err := d.ReadByte()
	if err != nil {
		return Variant{}, err
	}

	typeID := TypeID(encodingMask & 0x3F)
	isArray := encodingMask&0x80 != 0
	hasDimensions := encodingMask&0x40 != 0

	if isArray {
		return d.readVariantArray(typeID, hasDimensions)
	}

	return d.readVariantScalar(typeID)
}

func (d *Decoder) readVariantScalar(typeID TypeID) (Variant, error) {
	var value interface{}
	var err error

	switch typeID {
	case TypeNull:
		value = nil
	case TypeBoolean:
		value, err = d.ReadBoolean()
	case TypeSByte:
		value, err = d.ReadSByte()
	case TypeByte:
		value, err = d.ReadByte()
	case TypeInt16:
		value, err = d.ReadInt16()
	case TypeUInt16:
		value, err = d.ReadUInt16()
	case TypeInt32:
		value, err = d.ReadInt32()
	case TypeUInt32:
		value, err = d.ReadUInt32()
	case TypeInt64:
		value, err = d.ReadInt64()
	case TypeUInt64:
		value, err = d.ReadUInt64()
	case TypeFloat:
		value, err = d.ReadFloat()
	case TypeDouble:
		value, err = d.ReadDouble()
	case TypeString:
		value, err = d.ReadString()
	case TypeDateTime:
		value, err = d.ReadDateTime()
	case TypeGUID:
		value, err = d.ReadGUID()
	case TypeByteString:
		value, err = d.ReadByteString()
	case TypeNodeID:
		value, err = d.ReadNodeID()
	case TypeStatusCode:
		value, err = d.ReadStatusCode()
	case TypeQualifiedName:
		value, err = d.ReadQualifiedName()
	case TypeLocalizedText:
		value, err = d.ReadLocalizedText()
	default:
		return Variant{}, fmt.Errorf("%w: unsupported variant type %d", ErrInvalidMessage, typeID)
	}

	if err != nil {
		return Variant{}, err
	}

	return Variant{Type: typeID, Value: value}, nil
}

func (d *Decoder) readVariantArray(typeID TypeID, hasDimensions bool) (Variant, error) {
	length, err := d.ReadInt32()
	if err != nil {
		return Variant{}, err
	}

	if length < 0 {
		return Variant{Type: typeID, Value: nil}, nil
	}

	values := make([]interface{}, length)
	for i := int32(0); i < length; i++ {
		v, err := d.readVariantScalar(typeID)
		if err != nil {
			return Variant{}, err
		}
		values[i] = v.Value
	}

	if hasDimensions {
		// Skip array dimensions for now
		dimCount, err := d.ReadInt32()
		if err != nil {
			return Variant{}, err
		}
		for i := int32(0); i < dimCount; i++ {
			_, err := d.ReadInt32()
			if err != nil {
				return Variant{}, err
			}
		}
	}

	return Variant{Type: typeID, Value: values}, nil
}

// Helper functions for float conversion
func uint32FromFloat32(f float32) uint32 {
	b := *(*[4]byte)(unsafe.Pointer(&f))
	return binary.LittleEndian.Uint32(b[:])
}

func float32FromUint32(u uint32) float32 {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], u)
	return *(*float32)(unsafe.Pointer(&b))
}

func uint64FromFloat64(f float64) uint64 {
	b := *(*[8]byte)(unsafe.Pointer(&f))
	return binary.LittleEndian.Uint64(b[:])
}

func float64FromUint64(u uint64) float64 {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], u)
	return *(*float64)(unsafe.Pointer(&b))
}
