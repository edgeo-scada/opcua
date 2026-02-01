package opcua

import (
	"fmt"
)

// RequestHeader contains the header for all OPC UA requests.
type RequestHeader struct {
	AuthenticationToken NodeID
	Timestamp           int64
	RequestHandle       uint32
	ReturnDiagnostics   uint32
	AuditEntryID        string
	TimeoutHint         uint32
	AdditionalHeader    interface{}
}

// ResponseHeader contains the header for all OPC UA responses.
type ResponseHeader struct {
	Timestamp          int64
	RequestHandle      uint32
	ServiceResult      StatusCode
	ServiceDiagnostics DiagnosticInfo
	StringTable        []string
	AdditionalHeader   interface{}
}

// ReadRequest represents an OPC UA Read service request.
type ReadRequest struct {
	RequestHeader       RequestHeader
	MaxAge              float64
	TimestampsToReturn  TimestampsToReturn
	NodesToRead         []ReadValueID
}

func (r *ReadRequest) ServiceID() ServiceID {
	return ServiceRead
}

func (r *ReadRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	// Encode request header
	encodeRequestHeader(e, &r.RequestHeader)

	// MaxAge
	e.WriteDouble(r.MaxAge)

	// TimestampsToReturn
	e.WriteUInt32(uint32(r.TimestampsToReturn))

	// NodesToRead array
	e.WriteInt32(int32(len(r.NodesToRead)))
	for _, node := range r.NodesToRead {
		e.WriteNodeID(node.NodeID)
		e.WriteUInt32(uint32(node.AttributeID))
		e.WriteString(node.IndexRange)
		e.WriteQualifiedName(node.DataEncoding)
	}

	return e.Bytes(), nil
}

// ReadResponse represents an OPC UA Read service response.
type ReadResponse struct {
	ResponseHeader  ResponseHeader
	Results         []DataValue
	DiagnosticInfos []DiagnosticInfo
}

func (r *ReadResponse) ServiceID() ServiceID {
	return ServiceRead
}

func (r *ReadResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	// Decode response header
	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	// Check for error
	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceRead, r.ResponseHeader.ServiceResult, "")
	}

	// Results array
	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]DataValue, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = d.ReadDataValue()
			if err != nil {
				return err
			}
		}
	}

	// DiagnosticInfos (skip for now)
	diagCount, _ := d.ReadInt32()
	if diagCount > 0 {
		r.DiagnosticInfos = make([]DiagnosticInfo, diagCount)
	}

	return nil
}

// WriteRequest represents an OPC UA Write service request.
type WriteRequest struct {
	RequestHeader RequestHeader
	NodesToWrite  []WriteValue
}

func (r *WriteRequest) ServiceID() ServiceID {
	return ServiceWrite
}

func (r *WriteRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	// Encode request header
	encodeRequestHeader(e, &r.RequestHeader)

	// NodesToWrite array
	e.WriteInt32(int32(len(r.NodesToWrite)))
	for _, node := range r.NodesToWrite {
		e.WriteNodeID(node.NodeID)
		e.WriteUInt32(uint32(node.AttributeID))
		e.WriteString(node.IndexRange)
		encodeDataValue(e, &node.Value)
	}

	return e.Bytes(), nil
}

// WriteResponse represents an OPC UA Write service response.
type WriteResponse struct {
	ResponseHeader  ResponseHeader
	Results         []StatusCode
	DiagnosticInfos []DiagnosticInfo
}

func (r *WriteResponse) ServiceID() ServiceID {
	return ServiceWrite
}

func (r *WriteResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceWrite, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]StatusCode, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = d.ReadStatusCode()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// BrowseRequest represents an OPC UA Browse service request.
type BrowseRequest struct {
	RequestHeader           RequestHeader
	View                    ViewDescription
	RequestedMaxReferencesPerNode uint32
	NodesToBrowse           []BrowseDescription
}

// ViewDescription describes a view.
type ViewDescription struct {
	ViewID      NodeID
	Timestamp   int64
	ViewVersion uint32
}

func (r *BrowseRequest) ServiceID() ServiceID {
	return ServiceBrowse
}

func (r *BrowseRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	// View
	e.WriteNodeID(r.View.ViewID)
	e.WriteInt64(r.View.Timestamp)
	e.WriteUInt32(r.View.ViewVersion)

	// RequestedMaxReferencesPerNode
	e.WriteUInt32(r.RequestedMaxReferencesPerNode)

	// NodesToBrowse array
	e.WriteInt32(int32(len(r.NodesToBrowse)))
	for _, node := range r.NodesToBrowse {
		e.WriteNodeID(node.NodeID)
		e.WriteUInt32(uint32(node.BrowseDirection))
		e.WriteNodeID(node.ReferenceTypeID)
		e.WriteBoolean(node.IncludeSubtypes)
		e.WriteUInt32(node.NodeClassMask)
		e.WriteUInt32(node.ResultMask)
	}

	return e.Bytes(), nil
}

// BrowseResponse represents an OPC UA Browse service response.
type BrowseResponse struct {
	ResponseHeader  ResponseHeader
	Results         []BrowseResult
	DiagnosticInfos []DiagnosticInfo
}

func (r *BrowseResponse) ServiceID() ServiceID {
	return ServiceBrowse
}

func (r *BrowseResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceBrowse, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]BrowseResult, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = decodeBrowseResult(d)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// CreateSubscriptionRequest represents an OPC UA CreateSubscription request.
type CreateSubscriptionRequest struct {
	RequestHeader               RequestHeader
	RequestedPublishingInterval float64
	RequestedLifetimeCount      uint32
	RequestedMaxKeepAliveCount  uint32
	MaxNotificationsPerPublish  uint32
	PublishingEnabled           bool
	Priority                    uint8
}

func (r *CreateSubscriptionRequest) ServiceID() ServiceID {
	return ServiceCreateSubscription
}

func (r *CreateSubscriptionRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteDouble(r.RequestedPublishingInterval)
	e.WriteUInt32(r.RequestedLifetimeCount)
	e.WriteUInt32(r.RequestedMaxKeepAliveCount)
	e.WriteUInt32(r.MaxNotificationsPerPublish)
	e.WriteBoolean(r.PublishingEnabled)
	e.WriteByte(r.Priority)

	return e.Bytes(), nil
}

// CreateSubscriptionResponseMsg represents an OPC UA CreateSubscription response.
type CreateSubscriptionResponseMsg struct {
	ResponseHeader            ResponseHeader
	SubscriptionID            uint32
	RevisedPublishingInterval float64
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
}

func (r *CreateSubscriptionResponseMsg) ServiceID() ServiceID {
	return ServiceCreateSubscription
}

func (r *CreateSubscriptionResponseMsg) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceCreateSubscription, r.ResponseHeader.ServiceResult, "")
	}

	r.SubscriptionID, err = d.ReadUInt32()
	if err != nil {
		return err
	}
	r.RevisedPublishingInterval, err = d.ReadDouble()
	if err != nil {
		return err
	}
	r.RevisedLifetimeCount, err = d.ReadUInt32()
	if err != nil {
		return err
	}
	r.RevisedMaxKeepAliveCount, err = d.ReadUInt32()
	if err != nil {
		return err
	}

	return nil
}

// DeleteSubscriptionsRequest represents an OPC UA DeleteSubscriptions request.
type DeleteSubscriptionsRequest struct {
	RequestHeader   RequestHeader
	SubscriptionIDs []uint32
}

func (r *DeleteSubscriptionsRequest) ServiceID() ServiceID {
	return ServiceDeleteSubscriptions
}

func (r *DeleteSubscriptionsRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteInt32(int32(len(r.SubscriptionIDs)))
	for _, id := range r.SubscriptionIDs {
		e.WriteUInt32(id)
	}

	return e.Bytes(), nil
}

// DeleteSubscriptionsResponse represents an OPC UA DeleteSubscriptions response.
type DeleteSubscriptionsResponse struct {
	ResponseHeader  ResponseHeader
	Results         []StatusCode
	DiagnosticInfos []DiagnosticInfo
}

func (r *DeleteSubscriptionsResponse) ServiceID() ServiceID {
	return ServiceDeleteSubscriptions
}

func (r *DeleteSubscriptionsResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceDeleteSubscriptions, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]StatusCode, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = d.ReadStatusCode()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// CreateMonitoredItemsRequest represents an OPC UA CreateMonitoredItems request.
type CreateMonitoredItemsRequest struct {
	RequestHeader      RequestHeader
	SubscriptionID     uint32
	TimestampsToReturn TimestampsToReturn
	ItemsToCreate      []MonitoredItemCreateRequest
}

func (r *CreateMonitoredItemsRequest) ServiceID() ServiceID {
	return ServiceCreateMonitoredItems
}

func (r *CreateMonitoredItemsRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteUInt32(r.SubscriptionID)
	e.WriteUInt32(uint32(r.TimestampsToReturn))

	e.WriteInt32(int32(len(r.ItemsToCreate)))
	for _, item := range r.ItemsToCreate {
		// ItemToMonitor
		e.WriteNodeID(item.ItemToMonitor.NodeID)
		e.WriteUInt32(uint32(item.ItemToMonitor.AttributeID))
		e.WriteString(item.ItemToMonitor.IndexRange)
		e.WriteQualifiedName(item.ItemToMonitor.DataEncoding)

		// MonitoringMode
		e.WriteUInt32(uint32(item.MonitoringMode))

		// RequestedParameters
		e.WriteUInt32(item.RequestedParameters.ClientHandle)
		e.WriteDouble(item.RequestedParameters.SamplingInterval)
		// Filter (ExtensionObject) - null
		e.WriteNodeID(NodeID{}) // TypeId = null NodeID
		e.WriteByte(0x00)       // Encoding = no body
		e.WriteUInt32(item.RequestedParameters.QueueSize)
		e.WriteBoolean(item.RequestedParameters.DiscardOldest)
	}

	return e.Bytes(), nil
}

// CreateMonitoredItemsResponse represents an OPC UA CreateMonitoredItems response.
type CreateMonitoredItemsResponse struct {
	ResponseHeader  ResponseHeader
	Results         []MonitoredItemCreateResult
	DiagnosticInfos []DiagnosticInfo
}

func (r *CreateMonitoredItemsResponse) ServiceID() ServiceID {
	return ServiceCreateMonitoredItems
}

func (r *CreateMonitoredItemsResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceCreateMonitoredItems, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]MonitoredItemCreateResult, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = decodeMonitoredItemCreateResult(d)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteMonitoredItemsRequest represents an OPC UA DeleteMonitoredItems request.
type DeleteMonitoredItemsRequest struct {
	RequestHeader    RequestHeader
	SubscriptionID   uint32
	MonitoredItemIDs []uint32
}

func (r *DeleteMonitoredItemsRequest) ServiceID() ServiceID {
	return ServiceDeleteMonitoredItems
}

func (r *DeleteMonitoredItemsRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteUInt32(r.SubscriptionID)

	e.WriteInt32(int32(len(r.MonitoredItemIDs)))
	for _, id := range r.MonitoredItemIDs {
		e.WriteUInt32(id)
	}

	return e.Bytes(), nil
}

// DeleteMonitoredItemsResponse represents an OPC UA DeleteMonitoredItems response.
type DeleteMonitoredItemsResponse struct {
	ResponseHeader  ResponseHeader
	Results         []StatusCode
	DiagnosticInfos []DiagnosticInfo
}

func (r *DeleteMonitoredItemsResponse) ServiceID() ServiceID {
	return ServiceDeleteMonitoredItems
}

func (r *DeleteMonitoredItemsResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceDeleteMonitoredItems, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]StatusCode, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = d.ReadStatusCode()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// PublishRequest represents an OPC UA Publish request.
type PublishRequest struct {
	RequestHeader                         RequestHeader
	SubscriptionAcknowledgements          []SubscriptionAcknowledgement
}

// SubscriptionAcknowledgement acknowledges a notification.
type SubscriptionAcknowledgement struct {
	SubscriptionID uint32
	SequenceNumber uint32
}

func (r *PublishRequest) ServiceID() ServiceID {
	return ServicePublish
}

func (r *PublishRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteInt32(int32(len(r.SubscriptionAcknowledgements)))
	for _, ack := range r.SubscriptionAcknowledgements {
		e.WriteUInt32(ack.SubscriptionID)
		e.WriteUInt32(ack.SequenceNumber)
	}

	return e.Bytes(), nil
}

// PublishResponse represents an OPC UA Publish response.
type PublishResponse struct {
	ResponseHeader                   ResponseHeader
	SubscriptionID                   uint32
	AvailableSequenceNumbers         []uint32
	MoreNotifications                bool
	NotificationMessage              NotificationMessage
	Results                          []StatusCode
	DiagnosticInfos                  []DiagnosticInfo
}

// NotificationMessage contains notifications.
type NotificationMessage struct {
	SequenceNumber   uint32
	PublishTime      int64
	NotificationData []interface{}
}

func (r *PublishResponse) ServiceID() ServiceID {
	return ServicePublish
}

func (r *PublishResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServicePublish, r.ResponseHeader.ServiceResult, "")
	}

	r.SubscriptionID, err = d.ReadUInt32()
	if err != nil {
		return err
	}

	// AvailableSequenceNumbers
	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.AvailableSequenceNumbers = make([]uint32, count)
		for i := int32(0); i < count; i++ {
			r.AvailableSequenceNumbers[i], err = d.ReadUInt32()
			if err != nil {
				return err
			}
		}
	}

	r.MoreNotifications, err = d.ReadBoolean()
	if err != nil {
		return err
	}

	// NotificationMessage
	r.NotificationMessage.SequenceNumber, err = d.ReadUInt32()
	if err != nil {
		return err
	}
	r.NotificationMessage.PublishTime, err = d.ReadInt64()
	if err != nil {
		return err
	}

	// NotificationData - array of ExtensionObjects containing notifications
	notifCount, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if notifCount > 0 {
		r.NotificationMessage.NotificationData = make([]interface{}, 0, notifCount)
		for i := int32(0); i < notifCount; i++ {
			// Read ExtensionObject
			typeID, err := d.ReadNodeID()
			if err != nil {
				return err
			}
			encoding, err := d.ReadByte()
			if err != nil {
				return err
			}

			if encoding == 0x01 {
				// Binary body
				bodyLen, err := d.ReadInt32()
				if err != nil {
					return err
				}

				// Check if this is a DataChangeNotification (TypeId = 811)
				if typeID.Type == NodeIDTypeNumeric && typeID.Numeric == 811 {
					// Decode DataChangeNotification
					dcn, err := decodeDataChangeNotification(d, int(bodyLen))
					if err != nil {
						return err
					}
					r.NotificationMessage.NotificationData = append(r.NotificationMessage.NotificationData, dcn)
				} else {
					// Skip unknown notification types
					d.Skip(int(bodyLen))
				}
			}
		}
	}

	// Results
	resultCount, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if resultCount > 0 {
		r.Results = make([]StatusCode, resultCount)
		for i := int32(0); i < resultCount; i++ {
			r.Results[i], err = d.ReadStatusCode()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// CallRequest represents an OPC UA Call service request.
type CallRequest struct {
	RequestHeader RequestHeader
	MethodsToCall []CallMethodRequest
}

func (r *CallRequest) ServiceID() ServiceID {
	return ServiceCall
}

func (r *CallRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteInt32(int32(len(r.MethodsToCall)))
	for _, method := range r.MethodsToCall {
		e.WriteNodeID(method.ObjectID)
		e.WriteNodeID(method.MethodID)
		e.WriteInt32(int32(len(method.InputArguments)))
		for _, arg := range method.InputArguments {
			encodeVariant(e, &arg)
		}
	}

	return e.Bytes(), nil
}

// CallResponse represents an OPC UA Call service response.
type CallResponse struct {
	ResponseHeader  ResponseHeader
	Results         []CallMethodResult
	DiagnosticInfos []DiagnosticInfo
}

func (r *CallResponse) ServiceID() ServiceID {
	return ServiceCall
}

func (r *CallResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceCall, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}
	if count > 0 {
		r.Results = make([]CallMethodResult, count)
		for i := int32(0); i < count; i++ {
			r.Results[i], err = decodeCallMethodResult(d)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Helper functions

func encodeRequestHeader(e *Encoder, h *RequestHeader) {
	e.WriteNodeID(h.AuthenticationToken)
	e.WriteInt64(h.Timestamp)
	e.WriteUInt32(h.RequestHandle)
	e.WriteUInt32(h.ReturnDiagnostics)
	e.WriteString(h.AuditEntryID)
	e.WriteUInt32(h.TimeoutHint)
	// AdditionalHeader (ExtensionObject) - null
	e.WriteNodeID(NodeID{}) // TypeId = null NodeID
	e.WriteByte(0x00)       // Encoding = no body
}

func decodeResponseHeader(d *Decoder) (ResponseHeader, error) {
	var h ResponseHeader
	var err error

	h.Timestamp, err = d.ReadInt64()
	if err != nil {
		return h, err
	}
	h.RequestHandle, err = d.ReadUInt32()
	if err != nil {
		return h, err
	}
	h.ServiceResult, err = d.ReadStatusCode()
	if err != nil {
		return h, err
	}

	// ServiceDiagnostics (DiagnosticInfo) - simplified
	encodingMask, err := d.ReadByte()
	if err != nil {
		return h, err
	}
	if encodingMask != 0 {
		// Skip diagnostic info fields
		if encodingMask&0x01 != 0 {
			_, _ = d.ReadInt32() // SymbolicId
		}
		if encodingMask&0x02 != 0 {
			_, _ = d.ReadInt32() // NamespaceURI
		}
		if encodingMask&0x04 != 0 {
			_, _ = d.ReadInt32() // Locale
		}
		if encodingMask&0x08 != 0 {
			_, _ = d.ReadInt32() // LocalizedText
		}
		if encodingMask&0x10 != 0 {
			_, _ = d.ReadString() // AdditionalInfo
		}
		if encodingMask&0x20 != 0 {
			_, _ = d.ReadStatusCode() // InnerStatusCode
		}
	}

	// StringTable
	stringCount, err := d.ReadInt32()
	if err != nil {
		return h, err
	}
	if stringCount > 0 {
		h.StringTable = make([]string, stringCount)
		for i := int32(0); i < stringCount; i++ {
			h.StringTable[i], err = d.ReadString()
			if err != nil {
				return h, err
			}
		}
	}

	// AdditionalHeader (ExtensionObject) - skip
	_, _ = d.ReadNodeID() // TypeId
	_, _ = d.ReadByte()   // Encoding

	return h, nil
}

func encodeDataValue(e *Encoder, dv *DataValue) {
	var encodingMask byte
	if dv.Value != nil {
		encodingMask |= 0x01
	}
	if dv.StatusCode != StatusGood {
		encodingMask |= 0x02
	}
	if !dv.SourceTimestamp.IsZero() {
		encodingMask |= 0x04
	}
	if !dv.ServerTimestamp.IsZero() {
		encodingMask |= 0x08
	}

	e.WriteByte(encodingMask)

	if encodingMask&0x01 != 0 {
		encodeVariant(e, dv.Value)
	}
	if encodingMask&0x02 != 0 {
		e.WriteStatusCode(dv.StatusCode)
	}
	if encodingMask&0x04 != 0 {
		e.WriteDateTime(dv.SourceTimestamp)
	}
	if encodingMask&0x08 != 0 {
		e.WriteDateTime(dv.ServerTimestamp)
	}
}

func encodeVariant(e *Encoder, v *Variant) {
	if v == nil || v.Value == nil {
		e.WriteByte(0) // Null variant
		return
	}

	e.WriteByte(byte(v.Type))

	switch v.Type {
	case TypeBoolean:
		e.WriteBoolean(v.Value.(bool))
	case TypeSByte:
		e.WriteSByte(v.Value.(int8))
	case TypeByte:
		e.WriteByte(v.Value.(byte))
	case TypeInt16:
		e.WriteInt16(v.Value.(int16))
	case TypeUInt16:
		e.WriteUInt16(v.Value.(uint16))
	case TypeInt32:
		e.WriteInt32(v.Value.(int32))
	case TypeUInt32:
		e.WriteUInt32(v.Value.(uint32))
	case TypeInt64:
		e.WriteInt64(v.Value.(int64))
	case TypeUInt64:
		e.WriteUInt64(v.Value.(uint64))
	case TypeFloat:
		e.WriteFloat(v.Value.(float32))
	case TypeDouble:
		e.WriteDouble(v.Value.(float64))
	case TypeString:
		e.WriteString(v.Value.(string))
	case TypeDateTime:
		// Handle as int64 ticks
		if t, ok := v.Value.(int64); ok {
			e.WriteInt64(t)
		}
	case TypeByteString:
		e.WriteByteString(v.Value.([]byte))
	case TypeNodeID:
		e.WriteNodeID(v.Value.(NodeID))
	case TypeStatusCode:
		e.WriteStatusCode(v.Value.(StatusCode))
	case TypeQualifiedName:
		e.WriteQualifiedName(v.Value.(QualifiedName))
	case TypeLocalizedText:
		e.WriteLocalizedText(v.Value.(LocalizedText))
	}
}

func decodeBrowseResult(d *Decoder) (BrowseResult, error) {
	var br BrowseResult
	var err error

	br.StatusCode, err = d.ReadStatusCode()
	if err != nil {
		return br, err
	}

	br.ContinuationPoint, err = d.ReadByteString()
	if err != nil {
		return br, err
	}

	count, err := d.ReadInt32()
	if err != nil {
		return br, err
	}

	if count > 0 {
		br.References = make([]ReferenceDescription, count)
		for i := int32(0); i < count; i++ {
			br.References[i], err = decodeReferenceDescription(d)
			if err != nil {
				return br, err
			}
		}
	}

	return br, nil
}

func decodeReferenceDescription(d *Decoder) (ReferenceDescription, error) {
	var rd ReferenceDescription
	var err error

	rd.ReferenceTypeID, err = d.ReadNodeID()
	if err != nil {
		return rd, err
	}

	rd.IsForward, err = d.ReadBoolean()
	if err != nil {
		return rd, err
	}

	// NodeId (ExpandedNodeID)
	rd.NodeID, err = d.ReadExpandedNodeID()
	if err != nil {
		return rd, err
	}

	rd.BrowseName, err = d.ReadQualifiedName()
	if err != nil {
		return rd, err
	}

	rd.DisplayName, err = d.ReadLocalizedText()
	if err != nil {
		return rd, err
	}

	nodeClass, err := d.ReadUInt32()
	if err != nil {
		return rd, err
	}
	rd.NodeClass = NodeClass(nodeClass)

	// TypeDefinition (ExpandedNodeID)
	rd.TypeDefinition, err = d.ReadExpandedNodeID()
	if err != nil {
		return rd, err
	}

	return rd, nil
}

func decodeMonitoredItemCreateResult(d *Decoder) (MonitoredItemCreateResult, error) {
	var r MonitoredItemCreateResult
	var err error

	r.StatusCode, err = d.ReadStatusCode()
	if err != nil {
		return r, err
	}

	r.MonitoredItemID, err = d.ReadUInt32()
	if err != nil {
		return r, err
	}

	r.RevisedSamplingInterval, err = d.ReadDouble()
	if err != nil {
		return r, err
	}

	r.RevisedQueueSize, err = d.ReadUInt32()
	if err != nil {
		return r, err
	}

	// FilterResult (ExtensionObject) - skip
	_, _ = d.ReadNodeID() // TypeId
	enc, _ := d.ReadByte() // Encoding
	if enc == 0x01 {
		// Has binary body - read length and skip
		bodyLen, _ := d.ReadInt32()
		if bodyLen > 0 {
			d.Skip(int(bodyLen))
		}
	}

	return r, nil
}

func decodeCallMethodResult(d *Decoder) (CallMethodResult, error) {
	var r CallMethodResult
	var err error

	r.StatusCode, err = d.ReadStatusCode()
	if err != nil {
		return r, err
	}

	// InputArgumentResults
	argResultCount, err := d.ReadInt32()
	if err != nil {
		return r, err
	}
	if argResultCount > 0 {
		r.InputArgumentResults = make([]StatusCode, argResultCount)
		for i := int32(0); i < argResultCount; i++ {
			r.InputArgumentResults[i], err = d.ReadStatusCode()
			if err != nil {
				return r, err
			}
		}
	}

	// InputArgumentDiagnosticInfos - skip
	diagCount, _ := d.ReadInt32()
	if diagCount > 0 {
		r.InputArgumentDiagnosticInfos = make([]DiagnosticInfo, diagCount)
	}

	// OutputArguments
	outputCount, err := d.ReadInt32()
	if err != nil {
		return r, err
	}
	if outputCount > 0 {
		r.OutputArguments = make([]Variant, outputCount)
		for i := int32(0); i < outputCount; i++ {
			r.OutputArguments[i], err = d.ReadVariant()
			if err != nil {
				return r, err
			}
		}
	}

	return r, nil
}

// DataChangeNotificationData represents a DataChangeNotification from the server.
type DataChangeNotificationData struct {
	MonitoredItems []MonitoredItemNotification
}

// MonitoredItemNotification represents a single monitored item notification.
type MonitoredItemNotification struct {
	ClientHandle uint32
	Value        DataValue
}

func decodeDataChangeNotification(d *Decoder, bodyLen int) (*DataChangeNotificationData, error) {
	dcn := &DataChangeNotificationData{}

	// MonitoredItems array
	itemCount, err := d.ReadInt32()
	if err != nil {
		return nil, err
	}

	if itemCount > 0 {
		dcn.MonitoredItems = make([]MonitoredItemNotification, itemCount)
		for i := int32(0); i < itemCount; i++ {
			dcn.MonitoredItems[i].ClientHandle, err = d.ReadUInt32()
			if err != nil {
				return nil, err
			}
			dcn.MonitoredItems[i].Value, err = d.ReadDataValue()
			if err != nil {
				return nil, err
			}
		}
	}

	// DiagnosticInfos array - skip
	diagCount, err := d.ReadInt32()
	if err != nil {
		return nil, err
	}
	if diagCount > 0 {
		// Skip diagnostic infos
		for i := int32(0); i < diagCount; i++ {
			enc, _ := d.ReadByte()
			if enc != 0 {
				// Skip based on encoding mask
				if enc&0x01 != 0 {
					d.ReadInt32()
				}
				if enc&0x02 != 0 {
					d.ReadInt32()
				}
				if enc&0x04 != 0 {
					d.ReadInt32()
				}
				if enc&0x08 != 0 {
					d.ReadInt32()
				}
				if enc&0x10 != 0 {
					d.ReadString()
				}
				if enc&0x20 != 0 {
					d.ReadStatusCode()
				}
			}
		}
	}

	return dcn, nil
}

// GetEndpointsRequest represents an OPC UA GetEndpoints request.
type GetEndpointsRequest struct {
	RequestHeader  RequestHeader
	EndpointURL    string
	LocaleIDs      []string
	ProfileURIs    []string
}

func (r *GetEndpointsRequest) ServiceID() ServiceID {
	return ServiceGetEndpoints
}

func (r *GetEndpointsRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	e.WriteString(r.EndpointURL)

	e.WriteInt32(int32(len(r.LocaleIDs)))
	for _, locale := range r.LocaleIDs {
		e.WriteString(locale)
	}

	e.WriteInt32(int32(len(r.ProfileURIs)))
	for _, profile := range r.ProfileURIs {
		e.WriteString(profile)
	}

	return e.Bytes(), nil
}

// GetEndpointsResponse represents an OPC UA GetEndpoints response.
type GetEndpointsResponse struct {
	ResponseHeader ResponseHeader
	Endpoints      []EndpointDescription
}

func (r *GetEndpointsResponse) ServiceID() ServiceID {
	return ServiceGetEndpoints
}

func (r *GetEndpointsResponse) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceGetEndpoints, r.ResponseHeader.ServiceResult, "")
	}

	count, err := d.ReadInt32()
	if err != nil {
		return err
	}

	if count > 0 {
		r.Endpoints = make([]EndpointDescription, count)
		for i := int32(0); i < count; i++ {
			r.Endpoints[i], err = decodeEndpointDescription(d)
			if err != nil {
				return fmt.Errorf("failed to decode endpoint %d: %w", i, err)
			}
		}
	}

	return nil
}

func decodeEndpointDescription(d *Decoder) (EndpointDescription, error) {
	var ep EndpointDescription
	var err error

	ep.EndpointURL, err = d.ReadString()
	if err != nil {
		return ep, err
	}

	ep.Server, err = decodeApplicationDescription(d)
	if err != nil {
		return ep, err
	}

	ep.ServerCertificate, err = d.ReadByteString()
	if err != nil {
		return ep, err
	}

	secMode, err := d.ReadUInt32()
	if err != nil {
		return ep, err
	}
	ep.SecurityMode = MessageSecurityMode(secMode)

	ep.SecurityPolicyURI, err = d.ReadString()
	if err != nil {
		return ep, err
	}

	// UserIdentityTokens
	tokenCount, err := d.ReadInt32()
	if err != nil {
		return ep, err
	}
	if tokenCount > 0 {
		ep.UserIdentityTokens = make([]UserTokenPolicy, tokenCount)
		for i := int32(0); i < tokenCount; i++ {
			ep.UserIdentityTokens[i], err = decodeUserTokenPolicy(d)
			if err != nil {
				return ep, err
			}
		}
	}

	ep.TransportProfileURI, err = d.ReadString()
	if err != nil {
		return ep, err
	}

	ep.SecurityLevel, err = d.ReadByte()
	if err != nil {
		return ep, err
	}

	return ep, nil
}

func decodeApplicationDescription(d *Decoder) (ApplicationDescription, error) {
	var app ApplicationDescription
	var err error

	app.ApplicationURI, err = d.ReadString()
	if err != nil {
		return app, err
	}

	app.ProductURI, err = d.ReadString()
	if err != nil {
		return app, err
	}

	app.ApplicationName, err = d.ReadLocalizedText()
	if err != nil {
		return app, err
	}

	appType, err := d.ReadUInt32()
	if err != nil {
		return app, err
	}
	app.ApplicationType = ApplicationType(appType)

	app.GatewayServerURI, err = d.ReadString()
	if err != nil {
		return app, err
	}

	app.DiscoveryProfileURI, err = d.ReadString()
	if err != nil {
		return app, err
	}

	// DiscoveryURLs
	urlCount, err := d.ReadInt32()
	if err != nil {
		return app, err
	}
	if urlCount > 0 {
		app.DiscoveryURLs = make([]string, urlCount)
		for i := int32(0); i < urlCount; i++ {
			app.DiscoveryURLs[i], err = d.ReadString()
			if err != nil {
				return app, err
			}
		}
	}

	return app, nil
}

func decodeUserTokenPolicy(d *Decoder) (UserTokenPolicy, error) {
	var policy UserTokenPolicy
	var err error

	policy.PolicyID, err = d.ReadString()
	if err != nil {
		return policy, err
	}

	tokenType, err := d.ReadUInt32()
	if err != nil {
		return policy, err
	}
	policy.TokenType = UserTokenType(tokenType)

	policy.IssuedTokenType, err = d.ReadString()
	if err != nil {
		return policy, err
	}

	policy.IssuerEndpointURL, err = d.ReadString()
	if err != nil {
		return policy, err
	}

	policy.SecurityPolicyURI, err = d.ReadString()
	if err != nil {
		return policy, err
	}

	return policy, nil
}

// CreateSessionRequest represents an OPC UA CreateSession request.
type CreateSessionRequest struct {
	RequestHeader           RequestHeader
	ClientDescription       ApplicationDescription
	ServerURI               string
	EndpointURL             string
	SessionName             string
	ClientNonce             []byte
	ClientCertificate       []byte
	RequestedSessionTimeout float64
	MaxResponseMessageSize  uint32
}

func (r *CreateSessionRequest) ServiceID() ServiceID {
	return ServiceCreateSession
}

func (r *CreateSessionRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	// ClientDescription (ApplicationDescription)
	e.WriteString(r.ClientDescription.ApplicationURI)
	e.WriteString(r.ClientDescription.ProductURI)
	e.WriteLocalizedText(r.ClientDescription.ApplicationName)
	e.WriteUInt32(uint32(r.ClientDescription.ApplicationType))
	e.WriteString(r.ClientDescription.GatewayServerURI)
	e.WriteString(r.ClientDescription.DiscoveryProfileURI)
	e.WriteInt32(int32(len(r.ClientDescription.DiscoveryURLs)))
	for _, url := range r.ClientDescription.DiscoveryURLs {
		e.WriteString(url)
	}

	e.WriteString(r.ServerURI)
	e.WriteString(r.EndpointURL)
	e.WriteString(r.SessionName)
	e.WriteByteString(r.ClientNonce)
	e.WriteByteString(r.ClientCertificate)
	e.WriteDouble(r.RequestedSessionTimeout)
	e.WriteUInt32(r.MaxResponseMessageSize)

	return e.Bytes(), nil
}

// CreateSessionResponseMsg represents an OPC UA CreateSession response.
type CreateSessionResponseMsg struct {
	ResponseHeader             ResponseHeader
	SessionID                  NodeID
	AuthenticationToken        NodeID
	RevisedSessionTimeout      float64
	ServerNonce                []byte
	ServerCertificate          []byte
	ServerEndpoints            []EndpointDescription
	ServerSoftwareCertificates []SignedSoftwareCertificate
	ServerSignature            SignatureData
	MaxRequestMessageSize      uint32
}

func (r *CreateSessionResponseMsg) ServiceID() ServiceID {
	return ServiceCreateSession
}

func (r *CreateSessionResponseMsg) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceCreateSession, r.ResponseHeader.ServiceResult, "")
	}

	r.SessionID, err = d.ReadNodeID()
	if err != nil {
		return fmt.Errorf("failed to read SessionID: %w", err)
	}

	r.AuthenticationToken, err = d.ReadNodeID()
	if err != nil {
		return fmt.Errorf("failed to read AuthenticationToken: %w", err)
	}

	r.RevisedSessionTimeout, err = d.ReadDouble()
	if err != nil {
		return fmt.Errorf("failed to read RevisedSessionTimeout: %w", err)
	}

	r.ServerNonce, err = d.ReadByteString()
	if err != nil {
		return fmt.Errorf("failed to read ServerNonce: %w", err)
	}

	r.ServerCertificate, err = d.ReadByteString()
	if err != nil {
		return fmt.Errorf("failed to read ServerCertificate: %w", err)
	}

	// ServerEndpoints array
	endpointCount, err := d.ReadInt32()
	if err != nil {
		return fmt.Errorf("failed to read ServerEndpoints count: %w", err)
	}
	if endpointCount > 0 {
		r.ServerEndpoints = make([]EndpointDescription, endpointCount)
		for i := int32(0); i < endpointCount; i++ {
			r.ServerEndpoints[i], err = decodeEndpointDescription(d)
			if err != nil {
				return fmt.Errorf("failed to decode endpoint %d: %w", i, err)
			}
		}
	}

	// ServerSoftwareCertificates array
	certCount, err := d.ReadInt32()
	if err != nil {
		return fmt.Errorf("failed to read ServerSoftwareCertificates count: %w", err)
	}
	if certCount > 0 {
		r.ServerSoftwareCertificates = make([]SignedSoftwareCertificate, certCount)
		for i := int32(0); i < certCount; i++ {
			r.ServerSoftwareCertificates[i].CertificateData, _ = d.ReadByteString()
			r.ServerSoftwareCertificates[i].Signature, _ = d.ReadByteString()
		}
	}

	// ServerSignature
	r.ServerSignature.Algorithm, _ = d.ReadString()
	r.ServerSignature.Signature, _ = d.ReadByteString()

	r.MaxRequestMessageSize, _ = d.ReadUInt32()

	return nil
}

// ActivateSessionRequest represents an OPC UA ActivateSession request.
type ActivateSessionRequest struct {
	RequestHeader                RequestHeader
	ClientSignature              SignatureData
	ClientSoftwareCertificates   []SignedSoftwareCertificate
	LocaleIDs                    []string
	UserIdentityToken            interface{} // ExtensionObject
	UserTokenSignature           SignatureData
}

func (r *ActivateSessionRequest) ServiceID() ServiceID {
	return ServiceActivateSession
}

func (r *ActivateSessionRequest) Encode() ([]byte, error) {
	e := NewEncoder()

	encodeRequestHeader(e, &r.RequestHeader)

	// ClientSignature
	e.WriteString(r.ClientSignature.Algorithm)
	e.WriteByteString(r.ClientSignature.Signature)

	// ClientSoftwareCertificates array
	e.WriteInt32(int32(len(r.ClientSoftwareCertificates)))
	for _, cert := range r.ClientSoftwareCertificates {
		e.WriteByteString(cert.CertificateData)
		e.WriteByteString(cert.Signature)
	}

	// LocaleIDs array
	e.WriteInt32(int32(len(r.LocaleIDs)))
	for _, locale := range r.LocaleIDs {
		e.WriteString(locale)
	}

	// UserIdentityToken (ExtensionObject)
	encodeUserIdentityToken(e, r.UserIdentityToken)

	// UserTokenSignature
	e.WriteString(r.UserTokenSignature.Algorithm)
	e.WriteByteString(r.UserTokenSignature.Signature)

	return e.Bytes(), nil
}

// encodeUserIdentityToken encodes a user identity token as an ExtensionObject.
func encodeUserIdentityToken(e *Encoder, token interface{}) {
	switch t := token.(type) {
	case *AnonymousIdentityToken:
		// TypeId for AnonymousIdentityToken_Encoding_DefaultBinary = 321
		e.WriteNodeID(NewNumericNodeID(0, 321))
		e.WriteByte(0x01) // Encoding = Binary body

		// Encode the body
		bodyEncoder := NewEncoder()
		bodyEncoder.WriteString(t.PolicyID)
		body := bodyEncoder.Bytes()

		e.WriteInt32(int32(len(body)))
		e.buf.Write(body)

	case *UserNameIdentityToken:
		// TypeId for UserNameIdentityToken_Encoding_DefaultBinary = 324
		e.WriteNodeID(NewNumericNodeID(0, 324))
		e.WriteByte(0x01) // Encoding = Binary body

		// Encode the body
		bodyEncoder := NewEncoder()
		bodyEncoder.WriteString(t.PolicyID)
		bodyEncoder.WriteString(t.UserName)
		bodyEncoder.WriteByteString(t.Password)
		bodyEncoder.WriteString(t.EncryptionAlgorithm)
		body := bodyEncoder.Bytes()

		e.WriteInt32(int32(len(body)))
		e.buf.Write(body)

	case *X509IdentityToken:
		// TypeId for X509IdentityToken_Encoding_DefaultBinary = 327
		e.WriteNodeID(NewNumericNodeID(0, 327))
		e.WriteByte(0x01) // Encoding = Binary body

		// Encode the body
		bodyEncoder := NewEncoder()
		bodyEncoder.WriteString(t.PolicyID)
		bodyEncoder.WriteByteString(t.CertificateData)
		body := bodyEncoder.Bytes()

		e.WriteInt32(int32(len(body)))
		e.buf.Write(body)

	default:
		// Null ExtensionObject (anonymous by default)
		e.WriteNodeID(NewNumericNodeID(0, 321)) // AnonymousIdentityToken
		e.WriteByte(0x01)                        // Encoding = Binary body

		bodyEncoder := NewEncoder()
		bodyEncoder.WriteString("") // Empty PolicyID
		body := bodyEncoder.Bytes()

		e.WriteInt32(int32(len(body)))
		e.buf.Write(body)
	}
}

// AnonymousIdentityToken represents an anonymous user identity.
type AnonymousIdentityToken struct {
	PolicyID string
}

// UserNameIdentityToken represents a username/password user identity.
type UserNameIdentityToken struct {
	PolicyID            string
	UserName            string
	Password            []byte
	EncryptionAlgorithm string
}

// X509IdentityToken represents an X.509 certificate user identity.
type X509IdentityToken struct {
	PolicyID        string
	CertificateData []byte
}

// ActivateSessionResponseMsg represents an OPC UA ActivateSession response.
type ActivateSessionResponseMsg struct {
	ResponseHeader  ResponseHeader
	ServerNonce     []byte
	Results         []StatusCode
	DiagnosticInfos []DiagnosticInfo
}

func (r *ActivateSessionResponseMsg) ServiceID() ServiceID {
	return ServiceActivateSession
}

func (r *ActivateSessionResponseMsg) Decode(data []byte) error {
	d := NewDecoder(data)

	var err error
	r.ResponseHeader, err = decodeResponseHeader(d)
	if err != nil {
		return err
	}

	if r.ResponseHeader.ServiceResult.IsBad() {
		return NewOPCUAError(ServiceActivateSession, r.ResponseHeader.ServiceResult, "")
	}

	r.ServerNonce, err = d.ReadByteString()
	if err != nil {
		return fmt.Errorf("failed to read ServerNonce: %w", err)
	}

	// Results array
	resultCount, err := d.ReadInt32()
	if err != nil {
		return fmt.Errorf("failed to read Results count: %w", err)
	}
	if resultCount > 0 {
		r.Results = make([]StatusCode, resultCount)
		for i := int32(0); i < resultCount; i++ {
			r.Results[i], err = d.ReadStatusCode()
			if err != nil {
				return fmt.Errorf("failed to read result %d: %w", i, err)
			}
		}
	}

	// DiagnosticInfos array (simplified - skip for now)
	diagCount, _ := d.ReadInt32()
	if diagCount > 0 {
		r.DiagnosticInfos = make([]DiagnosticInfo, diagCount)
	}

	return nil
}
