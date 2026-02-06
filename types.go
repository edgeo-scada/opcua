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

// Package opcua provides an OPC UA client and server implementation.
package opcua

import (
	"context"
	"time"
)

// NodeIDType represents the type of a NodeID.
type NodeIDType uint8

// NodeID types.
const (
	NodeIDTypeNumeric NodeIDType = iota
	NodeIDTypeString
	NodeIDTypeGUID
	NodeIDTypeOpaque
)

// NodeID represents an OPC UA NodeID.
type NodeID struct {
	Type       NodeIDType
	Namespace  uint16
	Numeric    uint32
	String     string
	GUID       [16]byte
	Opaque     []byte
}

// NewNumericNodeID creates a new numeric NodeID.
func NewNumericNodeID(namespace uint16, id uint32) NodeID {
	return NodeID{
		Type:      NodeIDTypeNumeric,
		Namespace: namespace,
		Numeric:   id,
	}
}

// NewStringNodeID creates a new string NodeID.
func NewStringNodeID(namespace uint16, id string) NodeID {
	return NodeID{
		Type:      NodeIDTypeString,
		Namespace: namespace,
		String:    id,
	}
}

// ServiceID represents an OPC UA service identifier.
type ServiceID uint32

// OPC UA Service IDs.
const (
	ServiceFindServers               ServiceID = 422
	ServiceGetEndpoints              ServiceID = 428
	ServiceCreateSession             ServiceID = 461
	ServiceActivateSession           ServiceID = 467
	ServiceCloseSession              ServiceID = 473
	ServiceCancel                    ServiceID = 479
	ServiceAddNodes                  ServiceID = 486
	ServiceAddReferences             ServiceID = 492
	ServiceDeleteNodes               ServiceID = 498
	ServiceDeleteReferences          ServiceID = 504
	ServiceBrowse                    ServiceID = 527
	ServiceBrowseNext                ServiceID = 533
	ServiceTranslateBrowsePathsToNodeIds ServiceID = 554
	ServiceRegisterNodes             ServiceID = 560
	ServiceUnregisterNodes           ServiceID = 566
	ServiceQueryFirst                ServiceID = 615
	ServiceQueryNext                 ServiceID = 621
	ServiceRead                      ServiceID = 631
	ServiceHistoryRead               ServiceID = 664
	ServiceWrite                     ServiceID = 673
	ServiceHistoryUpdate             ServiceID = 700
	ServiceCall                      ServiceID = 712
	ServiceCreateMonitoredItems      ServiceID = 751
	ServiceModifyMonitoredItems      ServiceID = 763
	ServiceSetMonitoringMode         ServiceID = 769
	ServiceSetTriggering             ServiceID = 775
	ServiceDeleteMonitoredItems      ServiceID = 781
	ServiceCreateSubscription        ServiceID = 787
	ServiceModifySubscription        ServiceID = 793
	ServiceSetPublishingMode         ServiceID = 799
	ServicePublish                   ServiceID = 826
	ServiceRepublish                 ServiceID = 832
	ServiceTransferSubscriptions     ServiceID = 841
	ServiceDeleteSubscriptions       ServiceID = 847
)

// String returns the string representation of a ServiceID.
func (s ServiceID) String() string {
	switch s {
	case ServiceFindServers:
		return "FindServers"
	case ServiceGetEndpoints:
		return "GetEndpoints"
	case ServiceCreateSession:
		return "CreateSession"
	case ServiceActivateSession:
		return "ActivateSession"
	case ServiceCloseSession:
		return "CloseSession"
	case ServiceCancel:
		return "Cancel"
	case ServiceBrowse:
		return "Browse"
	case ServiceBrowseNext:
		return "BrowseNext"
	case ServiceTranslateBrowsePathsToNodeIds:
		return "TranslateBrowsePathsToNodeIds"
	case ServiceRegisterNodes:
		return "RegisterNodes"
	case ServiceUnregisterNodes:
		return "UnregisterNodes"
	case ServiceRead:
		return "Read"
	case ServiceHistoryRead:
		return "HistoryRead"
	case ServiceWrite:
		return "Write"
	case ServiceHistoryUpdate:
		return "HistoryUpdate"
	case ServiceCall:
		return "Call"
	case ServiceCreateMonitoredItems:
		return "CreateMonitoredItems"
	case ServiceModifyMonitoredItems:
		return "ModifyMonitoredItems"
	case ServiceSetMonitoringMode:
		return "SetMonitoringMode"
	case ServiceDeleteMonitoredItems:
		return "DeleteMonitoredItems"
	case ServiceCreateSubscription:
		return "CreateSubscription"
	case ServiceModifySubscription:
		return "ModifySubscription"
	case ServiceSetPublishingMode:
		return "SetPublishingMode"
	case ServicePublish:
		return "Publish"
	case ServiceRepublish:
		return "Republish"
	case ServiceTransferSubscriptions:
		return "TransferSubscriptions"
	case ServiceDeleteSubscriptions:
		return "DeleteSubscriptions"
	default:
		return "Unknown"
	}
}

// AttributeID represents an OPC UA attribute identifier.
type AttributeID uint32

// OPC UA Attribute IDs.
const (
	AttributeNodeID                  AttributeID = 1
	AttributeNodeClass               AttributeID = 2
	AttributeBrowseName              AttributeID = 3
	AttributeDisplayName             AttributeID = 4
	AttributeDescription             AttributeID = 5
	AttributeWriteMask               AttributeID = 6
	AttributeUserWriteMask           AttributeID = 7
	AttributeIsAbstract              AttributeID = 8
	AttributeSymmetric               AttributeID = 9
	AttributeInverseName             AttributeID = 10
	AttributeContainsNoLoops         AttributeID = 11
	AttributeEventNotifier           AttributeID = 12
	AttributeValue                   AttributeID = 13
	AttributeDataType                AttributeID = 14
	AttributeValueRank               AttributeID = 15
	AttributeArrayDimensions         AttributeID = 16
	AttributeAccessLevel             AttributeID = 17
	AttributeUserAccessLevel         AttributeID = 18
	AttributeMinimumSamplingInterval AttributeID = 19
	AttributeHistorizing             AttributeID = 20
	AttributeExecutable              AttributeID = 21
	AttributeUserExecutable          AttributeID = 22
)

// String returns the string representation of an AttributeID.
func (a AttributeID) String() string {
	switch a {
	case AttributeNodeID:
		return "NodeId"
	case AttributeNodeClass:
		return "NodeClass"
	case AttributeBrowseName:
		return "BrowseName"
	case AttributeDisplayName:
		return "DisplayName"
	case AttributeDescription:
		return "Description"
	case AttributeWriteMask:
		return "WriteMask"
	case AttributeUserWriteMask:
		return "UserWriteMask"
	case AttributeIsAbstract:
		return "IsAbstract"
	case AttributeSymmetric:
		return "Symmetric"
	case AttributeInverseName:
		return "InverseName"
	case AttributeContainsNoLoops:
		return "ContainsNoLoops"
	case AttributeEventNotifier:
		return "EventNotifier"
	case AttributeValue:
		return "Value"
	case AttributeDataType:
		return "DataType"
	case AttributeValueRank:
		return "ValueRank"
	case AttributeArrayDimensions:
		return "ArrayDimensions"
	case AttributeAccessLevel:
		return "AccessLevel"
	case AttributeUserAccessLevel:
		return "UserAccessLevel"
	case AttributeMinimumSamplingInterval:
		return "MinimumSamplingInterval"
	case AttributeHistorizing:
		return "Historizing"
	case AttributeExecutable:
		return "Executable"
	case AttributeUserExecutable:
		return "UserExecutable"
	default:
		return "Unknown"
	}
}

// NodeClass represents the class of an OPC UA node.
type NodeClass uint32

// OPC UA Node Classes.
const (
	NodeClassUnspecified   NodeClass = 0
	NodeClassObject        NodeClass = 1
	NodeClassVariable      NodeClass = 2
	NodeClassMethod        NodeClass = 4
	NodeClassObjectType    NodeClass = 8
	NodeClassVariableType  NodeClass = 16
	NodeClassReferenceType NodeClass = 32
	NodeClassDataType      NodeClass = 64
	NodeClassView          NodeClass = 128
)

// String returns the string representation of a NodeClass.
func (n NodeClass) String() string {
	switch n {
	case NodeClassUnspecified:
		return "Unspecified"
	case NodeClassObject:
		return "Object"
	case NodeClassVariable:
		return "Variable"
	case NodeClassMethod:
		return "Method"
	case NodeClassObjectType:
		return "ObjectType"
	case NodeClassVariableType:
		return "VariableType"
	case NodeClassReferenceType:
		return "ReferenceType"
	case NodeClassDataType:
		return "DataType"
	case NodeClassView:
		return "View"
	default:
		return "Unknown"
	}
}

// BrowseDirection represents the direction to browse in the address space.
type BrowseDirection uint32

// Browse directions.
const (
	BrowseDirectionForward BrowseDirection = 0
	BrowseDirectionInverse BrowseDirection = 1
	BrowseDirectionBoth    BrowseDirection = 2
)

// TimestampsToReturn specifies which timestamps to return.
type TimestampsToReturn uint32

// Timestamps to return options.
const (
	TimestampsToReturnSource  TimestampsToReturn = 0
	TimestampsToReturnServer  TimestampsToReturn = 1
	TimestampsToReturnBoth    TimestampsToReturn = 2
	TimestampsToReturnNeither TimestampsToReturn = 3
)

// MessageSecurityMode represents the security mode for messages.
type MessageSecurityMode uint32

// Message security modes.
const (
	MessageSecurityModeInvalid        MessageSecurityMode = 0
	MessageSecurityModeNone           MessageSecurityMode = 1
	MessageSecurityModeSign           MessageSecurityMode = 2
	MessageSecurityModeSignAndEncrypt MessageSecurityMode = 3
)

// String returns the string representation of a MessageSecurityMode.
func (m MessageSecurityMode) String() string {
	switch m {
	case MessageSecurityModeNone:
		return "None"
	case MessageSecurityModeSign:
		return "Sign"
	case MessageSecurityModeSignAndEncrypt:
		return "SignAndEncrypt"
	default:
		return "Invalid"
	}
}

// SecurityPolicy represents an OPC UA security policy.
type SecurityPolicy string

// Security policies.
const (
	SecurityPolicyNone           SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#None"
	SecurityPolicyBasic128Rsa15  SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
	SecurityPolicyBasic256       SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
	SecurityPolicyBasic256Sha256 SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	SecurityPolicyAes128Sha256   SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	SecurityPolicyAes256Sha256   SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
)

// Protocol constants.
const (
	// DefaultTimeout is the default timeout for OPC UA operations.
	DefaultTimeout = 5 * time.Second

	// DefaultPort is the default OPC UA TCP port.
	DefaultPort = 4840

	// ProtocolVersion is the OPC UA binary protocol version.
	ProtocolVersion uint32 = 0

	// MaxMessageSize is the maximum message size (0 = no limit).
	MaxMessageSize uint32 = 0

	// MaxChunkCount is the maximum number of chunks (0 = no limit).
	MaxChunkCount uint32 = 0

	// DefaultReceiveBufferSize is the default receive buffer size.
	DefaultReceiveBufferSize uint32 = 65535

	// DefaultSendBufferSize is the default send buffer size.
	DefaultSendBufferSize uint32 = 65535

	// DefaultMaxMessageSize is the default maximum message size.
	DefaultMaxMessageSize uint32 = 16777216
)

// DataValue represents an OPC UA DataValue.
type DataValue struct {
	Value           *Variant
	StatusCode      StatusCode
	SourceTimestamp time.Time
	ServerTimestamp time.Time
	SourcePicoseconds uint16
	ServerPicoseconds uint16
}

// Variant represents an OPC UA Variant.
type Variant struct {
	Type  TypeID
	Value interface{}
}

// TypeID represents an OPC UA built-in type.
type TypeID uint8

// OPC UA Built-in Types.
const (
	TypeNull           TypeID = 0
	TypeBoolean        TypeID = 1
	TypeSByte          TypeID = 2
	TypeByte           TypeID = 3
	TypeInt16          TypeID = 4
	TypeUInt16         TypeID = 5
	TypeInt32          TypeID = 6
	TypeUInt32         TypeID = 7
	TypeInt64          TypeID = 8
	TypeUInt64         TypeID = 9
	TypeFloat          TypeID = 10
	TypeDouble         TypeID = 11
	TypeString         TypeID = 12
	TypeDateTime       TypeID = 13
	TypeGUID           TypeID = 14
	TypeByteString     TypeID = 15
	TypeXMLElement     TypeID = 16
	TypeNodeID         TypeID = 17
	TypeExpandedNodeID TypeID = 18
	TypeStatusCode     TypeID = 19
	TypeQualifiedName  TypeID = 20
	TypeLocalizedText  TypeID = 21
	TypeExtensionObject TypeID = 22
	TypeDataValue      TypeID = 23
	TypeVariant        TypeID = 24
	TypeDiagnosticInfo TypeID = 25
)

// StatusCode represents an OPC UA StatusCode.
type StatusCode uint32

// QualifiedName represents an OPC UA QualifiedName.
type QualifiedName struct {
	NamespaceIndex uint16
	Name           string
}

// LocalizedText represents an OPC UA LocalizedText.
type LocalizedText struct {
	Locale string
	Text   string
}

// ReadValueID represents a node attribute to read.
type ReadValueID struct {
	NodeID       NodeID
	AttributeID  AttributeID
	IndexRange   string
	DataEncoding QualifiedName
}

// WriteValue represents a value to write to a node attribute.
type WriteValue struct {
	NodeID      NodeID
	AttributeID AttributeID
	IndexRange  string
	Value       DataValue
}

// BrowseDescription describes what to browse from a node.
type BrowseDescription struct {
	NodeID          NodeID
	BrowseDirection BrowseDirection
	ReferenceTypeID NodeID
	IncludeSubtypes bool
	NodeClassMask   uint32
	ResultMask      uint32
}

// ReferenceDescription describes a reference returned from a browse.
type ReferenceDescription struct {
	ReferenceTypeID NodeID
	IsForward       bool
	NodeID          NodeID
	BrowseName      QualifiedName
	DisplayName     LocalizedText
	NodeClass       NodeClass
	TypeDefinition  NodeID
}

// BrowseResult contains the result of a browse operation.
type BrowseResult struct {
	StatusCode         StatusCode
	ContinuationPoint  []byte
	References         []ReferenceDescription
}

// Request represents an OPC UA request that can be encoded.
type Request interface {
	ServiceID() ServiceID
	Encode() ([]byte, error)
}

// Response represents an OPC UA response that can be decoded.
type Response interface {
	ServiceID() ServiceID
	Decode(data []byte) error
}

// Transporter defines the interface for sending and receiving OPC UA messages.
type Transporter interface {
	Send(ctx context.Context, msg []byte) ([]byte, error)
	Close() error
}

// Handler defines the interface for handling OPC UA requests on the server side.
type Handler interface {
	// Discovery services
	FindServers(endpointURL string) ([]ApplicationDescription, error)
	GetEndpoints(endpointURL string) ([]EndpointDescription, error)

	// Session services
	CreateSession(clientDescription ApplicationDescription, serverURI string, endpointURL string, sessionName string, clientNonce []byte, clientCertificate []byte, requestedSessionTimeout float64, maxResponseMessageSize uint32) (*CreateSessionResponse, error)
	ActivateSession(clientSignature SignatureData, clientSoftwareCertificates []SignedSoftwareCertificate, localeIDs []string, userIdentityToken interface{}, userTokenSignature SignatureData) (*ActivateSessionResponse, error)
	CloseSession(deleteSubscriptions bool) error

	// Node management services
	Browse(nodesToBrowse []BrowseDescription, maxReferencesPerNode uint32) ([]BrowseResult, error)
	BrowseNext(releaseContinuationPoints bool, continuationPoints [][]byte) ([]BrowseResult, error)
	TranslateBrowsePathsToNodeIds(browsePaths []BrowsePath) ([]BrowsePathResult, error)
	RegisterNodes(nodesToRegister []NodeID) ([]NodeID, error)
	UnregisterNodes(nodesToUnregister []NodeID) error

	// Attribute services
	Read(maxAge float64, timestampsToReturn TimestampsToReturn, nodesToRead []ReadValueID) ([]DataValue, error)
	Write(nodesToWrite []WriteValue) ([]StatusCode, error)
	HistoryRead(historyReadDetails interface{}, timestampsToReturn TimestampsToReturn, releaseContinuationPoints bool, nodesToRead []HistoryReadValueID) ([]HistoryReadResult, error)

	// Method services
	Call(methodsToCall []CallMethodRequest) ([]CallMethodResult, error)

	// Subscription services
	CreateSubscription(requestedPublishingInterval float64, requestedLifetimeCount uint32, requestedMaxKeepAliveCount uint32, maxNotificationsPerPublish uint32, publishingEnabled bool, priority uint8) (*CreateSubscriptionResponse, error)
	ModifySubscription(subscriptionID uint32, requestedPublishingInterval float64, requestedLifetimeCount uint32, requestedMaxKeepAliveCount uint32, maxNotificationsPerPublish uint32, priority uint8) (*ModifySubscriptionResponse, error)
	DeleteSubscriptions(subscriptionIDs []uint32) ([]StatusCode, error)
	SetPublishingMode(publishingEnabled bool, subscriptionIDs []uint32) ([]StatusCode, error)

	// MonitoredItem services
	CreateMonitoredItems(subscriptionID uint32, timestampsToReturn TimestampsToReturn, itemsToCreate []MonitoredItemCreateRequest) ([]MonitoredItemCreateResult, error)
	ModifyMonitoredItems(subscriptionID uint32, timestampsToReturn TimestampsToReturn, itemsToModify []MonitoredItemModifyRequest) ([]MonitoredItemModifyResult, error)
	DeleteMonitoredItems(subscriptionID uint32, monitoredItemIDs []uint32) ([]StatusCode, error)
	SetMonitoringMode(subscriptionID uint32, monitoringMode MonitoringMode, monitoredItemIDs []uint32) ([]StatusCode, error)
}

// ConnectionState represents the state of a client connection.
type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
	StateSecureChannelOpen
	StateSessionActive
)

// String returns the string representation of the connection state.
func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateSecureChannelOpen:
		return "secure_channel_open"
	case StateSessionActive:
		return "session_active"
	default:
		return "unknown"
	}
}

// ApplicationDescription describes an OPC UA application.
type ApplicationDescription struct {
	ApplicationURI      string
	ProductURI          string
	ApplicationName     LocalizedText
	ApplicationType     ApplicationType
	GatewayServerURI    string
	DiscoveryProfileURI string
	DiscoveryURLs       []string
}

// ApplicationType represents the type of an OPC UA application.
type ApplicationType uint32

// Application types.
const (
	ApplicationTypeServer          ApplicationType = 0
	ApplicationTypeClient          ApplicationType = 1
	ApplicationTypeClientAndServer ApplicationType = 2
	ApplicationTypeDiscoveryServer ApplicationType = 3
)

// EndpointDescription describes an OPC UA endpoint.
type EndpointDescription struct {
	EndpointURL         string
	Server              ApplicationDescription
	ServerCertificate   []byte
	SecurityMode        MessageSecurityMode
	SecurityPolicyURI   string
	UserIdentityTokens  []UserTokenPolicy
	TransportProfileURI string
	SecurityLevel       uint8
}

// UserTokenPolicy describes a user identity token policy.
type UserTokenPolicy struct {
	PolicyID          string
	TokenType         UserTokenType
	IssuedTokenType   string
	IssuerEndpointURL string
	SecurityPolicyURI string
}

// UserTokenType represents the type of user identity token.
type UserTokenType uint32

// User token types.
const (
	UserTokenTypeAnonymous   UserTokenType = 0
	UserTokenTypeUserName    UserTokenType = 1
	UserTokenTypeCertificate UserTokenType = 2
	UserTokenTypeIssuedToken UserTokenType = 3
)

// SignatureData contains a digital signature.
type SignatureData struct {
	Algorithm string
	Signature []byte
}

// SignedSoftwareCertificate contains a signed software certificate.
type SignedSoftwareCertificate struct {
	CertificateData []byte
	Signature       []byte
}

// CreateSessionResponse contains the response to a CreateSession request.
type CreateSessionResponse struct {
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

// ActivateSessionResponse contains the response to an ActivateSession request.
type ActivateSessionResponse struct {
	ServerNonce     []byte
	Results         []StatusCode
	DiagnosticInfos []DiagnosticInfo
}

// DiagnosticInfo contains diagnostic information.
type DiagnosticInfo struct {
	SymbolicID          int32
	NamespaceURI        int32
	Locale              int32
	LocalizedText       int32
	AdditionalInfo      string
	InnerStatusCode     StatusCode
	InnerDiagnosticInfo *DiagnosticInfo
}

// BrowsePath describes a browse path.
type BrowsePath struct {
	StartingNode NodeID
	RelativePath RelativePath
}

// RelativePath is a sequence of browse names.
type RelativePath struct {
	Elements []RelativePathElement
}

// RelativePathElement is a single element of a relative path.
type RelativePathElement struct {
	ReferenceTypeID NodeID
	IsInverse       bool
	IncludeSubtypes bool
	TargetName      QualifiedName
}

// BrowsePathResult contains the result of a TranslateBrowsePathsToNodeIds operation.
type BrowsePathResult struct {
	StatusCode StatusCode
	Targets    []BrowsePathTarget
}

// BrowsePathTarget contains a target node of a browse path.
type BrowsePathTarget struct {
	TargetID          NodeID
	RemainingPathIndex uint32
}

// HistoryReadValueID identifies a node for history read.
type HistoryReadValueID struct {
	NodeID             NodeID
	IndexRange         string
	DataEncoding       QualifiedName
	ContinuationPoint  []byte
}

// HistoryReadResult contains the result of a history read.
type HistoryReadResult struct {
	StatusCode        StatusCode
	ContinuationPoint []byte
	HistoryData       interface{}
}

// CallMethodRequest describes a method to call.
type CallMethodRequest struct {
	ObjectID       NodeID
	MethodID       NodeID
	InputArguments []Variant
}

// CallMethodResult contains the result of a method call.
type CallMethodResult struct {
	StatusCode            StatusCode
	InputArgumentResults  []StatusCode
	InputArgumentDiagnosticInfos []DiagnosticInfo
	OutputArguments       []Variant
}

// CreateSubscriptionResponse contains the response to a CreateSubscription request.
type CreateSubscriptionResponse struct {
	SubscriptionID            uint32
	RevisedPublishingInterval float64
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
}

// ModifySubscriptionResponse contains the response to a ModifySubscription request.
type ModifySubscriptionResponse struct {
	RevisedPublishingInterval float64
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
}

// MonitoringMode represents the monitoring mode for a monitored item.
type MonitoringMode uint32

// Monitoring modes.
const (
	MonitoringModeDisabled  MonitoringMode = 0
	MonitoringModeSampling  MonitoringMode = 1
	MonitoringModeReporting MonitoringMode = 2
)

// MonitoredItemCreateRequest describes a monitored item to create.
type MonitoredItemCreateRequest struct {
	ItemToMonitor        ReadValueID
	MonitoringMode       MonitoringMode
	RequestedParameters  MonitoringParameters
}

// MonitoringParameters contains monitoring parameters.
type MonitoringParameters struct {
	ClientHandle     uint32
	SamplingInterval float64
	Filter           interface{}
	QueueSize        uint32
	DiscardOldest    bool
}

// MonitoredItemCreateResult contains the result of creating a monitored item.
type MonitoredItemCreateResult struct {
	StatusCode             StatusCode
	MonitoredItemID        uint32
	RevisedSamplingInterval float64
	RevisedQueueSize       uint32
	FilterResult           interface{}
}

// MonitoredItemModifyRequest describes a monitored item to modify.
type MonitoredItemModifyRequest struct {
	MonitoredItemID     uint32
	RequestedParameters MonitoringParameters
}

// MonitoredItemModifyResult contains the result of modifying a monitored item.
type MonitoredItemModifyResult struct {
	StatusCode             StatusCode
	RevisedSamplingInterval float64
	RevisedQueueSize       uint32
	FilterResult           interface{}
}
