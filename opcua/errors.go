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
	"errors"
	"fmt"
)

// StatusCode severity levels.
const (
	StatusSeverityGood        uint32 = 0x00000000
	StatusSeverityUncertain   uint32 = 0x40000000
	StatusSeverityBad         uint32 = 0x80000000
	StatusSeverityMask        uint32 = 0xC0000000
)

// Common OPC UA Status Codes.
const (
	StatusGood                                   StatusCode = 0x00000000
	StatusUncertain                              StatusCode = 0x40000000
	StatusBad                                    StatusCode = 0x80000000
	StatusBadUnexpectedError                     StatusCode = 0x80010000
	StatusBadInternalError                       StatusCode = 0x80020000
	StatusBadOutOfMemory                         StatusCode = 0x80030000
	StatusBadResourceUnavailable                 StatusCode = 0x80040000
	StatusBadCommunicationError                  StatusCode = 0x80050000
	StatusBadEncodingError                       StatusCode = 0x80060000
	StatusBadDecodingError                       StatusCode = 0x80070000
	StatusBadEncodingLimitsExceeded              StatusCode = 0x80080000
	StatusBadRequestTooLarge                     StatusCode = 0x80B80000
	StatusBadResponseTooLarge                    StatusCode = 0x80B90000
	StatusBadUnknownResponse                     StatusCode = 0x80090000
	StatusBadTimeout                             StatusCode = 0x800A0000
	StatusBadServiceUnsupported                  StatusCode = 0x800B0000
	StatusBadShutdown                            StatusCode = 0x800C0000
	StatusBadServerNotConnected                  StatusCode = 0x800D0000
	StatusBadServerHalted                        StatusCode = 0x800E0000
	StatusBadNothingToDo                         StatusCode = 0x800F0000
	StatusBadTooManyOperations                   StatusCode = 0x80100000
	StatusBadTooManyMonitoredItems               StatusCode = 0x80DB0000
	StatusBadDataTypeIdUnknown                   StatusCode = 0x80110000
	StatusBadCertificateInvalid                  StatusCode = 0x80120000
	StatusBadSecurityChecksFailed                StatusCode = 0x80130000
	StatusBadCertificatePolicyCheckFailed        StatusCode = 0x81140000
	StatusBadCertificateTimeInvalid              StatusCode = 0x80140000
	StatusBadCertificateIssuerTimeInvalid        StatusCode = 0x80150000
	StatusBadCertificateHostNameInvalid          StatusCode = 0x80160000
	StatusBadCertificateUriInvalid               StatusCode = 0x80170000
	StatusBadCertificateUseNotAllowed            StatusCode = 0x80180000
	StatusBadCertificateIssuerUseNotAllowed      StatusCode = 0x80190000
	StatusBadCertificateUntrusted                StatusCode = 0x801A0000
	StatusBadCertificateRevocationUnknown        StatusCode = 0x801B0000
	StatusBadCertificateIssuerRevocationUnknown  StatusCode = 0x801C0000
	StatusBadCertificateRevoked                  StatusCode = 0x801D0000
	StatusBadCertificateIssuerRevoked            StatusCode = 0x801E0000
	StatusBadCertificateChainIncomplete          StatusCode = 0x810D0000
	StatusBadUserAccessDenied                    StatusCode = 0x801F0000
	StatusBadIdentityTokenInvalid                StatusCode = 0x80200000
	StatusBadIdentityTokenRejected               StatusCode = 0x80210000
	StatusBadSecureChannelIdInvalid              StatusCode = 0x80220000
	StatusBadInvalidTimestamp                    StatusCode = 0x80230000
	StatusBadNonceInvalid                        StatusCode = 0x80240000
	StatusBadSessionIdInvalid                    StatusCode = 0x80250000
	StatusBadSessionClosed                       StatusCode = 0x80260000
	StatusBadSessionNotActivated                 StatusCode = 0x80270000
	StatusBadSubscriptionIdInvalid               StatusCode = 0x80280000
	StatusBadRequestHeaderInvalid                StatusCode = 0x802A0000
	StatusBadTimestampsToReturnInvalid           StatusCode = 0x802B0000
	StatusBadRequestCancelledByClient            StatusCode = 0x802C0000
	StatusBadTooManyArguments                    StatusCode = 0x80E50000
	StatusBadLicenseExpired                      StatusCode = 0x810E0000
	StatusBadLicenseLimitsExceeded               StatusCode = 0x810F0000
	StatusBadLicenseNotAvailable                 StatusCode = 0x81100000
	StatusGoodSubscriptionTransferred            StatusCode = 0x002D0000
	StatusGoodCompletesAsynchronously            StatusCode = 0x002E0000
	StatusGoodOverload                           StatusCode = 0x002F0000
	StatusGoodClamped                            StatusCode = 0x00300000
	StatusBadNoCommunication                     StatusCode = 0x80310000
	StatusBadWaitingForInitialData               StatusCode = 0x80320000
	StatusBadNodeIdInvalid                       StatusCode = 0x80330000
	StatusBadNodeIdUnknown                       StatusCode = 0x80340000
	StatusBadAttributeIdInvalid                  StatusCode = 0x80350000
	StatusBadIndexRangeInvalid                   StatusCode = 0x80360000
	StatusBadIndexRangeNoData                    StatusCode = 0x80370000
	StatusBadDataEncodingInvalid                 StatusCode = 0x80380000
	StatusBadDataEncodingUnsupported             StatusCode = 0x80390000
	StatusBadNotReadable                         StatusCode = 0x803A0000
	StatusBadNotWritable                         StatusCode = 0x803B0000
	StatusBadOutOfRange                          StatusCode = 0x803C0000
	StatusBadNotSupported                        StatusCode = 0x803D0000
	StatusBadNotFound                            StatusCode = 0x803E0000
	StatusBadObjectDeleted                       StatusCode = 0x803F0000
	StatusBadNotImplemented                      StatusCode = 0x80400000
	StatusBadMonitoringModeInvalid               StatusCode = 0x80410000
	StatusBadMonitoredItemIdInvalid              StatusCode = 0x80420000
	StatusBadMonitoredItemFilterInvalid          StatusCode = 0x80430000
	StatusBadMonitoredItemFilterUnsupported      StatusCode = 0x80440000
	StatusBadFilterNotAllowed                    StatusCode = 0x80450000
	StatusBadStructureMissing                    StatusCode = 0x80460000
	StatusBadEventFilterInvalid                  StatusCode = 0x80470000
	StatusBadContentFilterInvalid                StatusCode = 0x80480000
	StatusBadFilterOperatorInvalid               StatusCode = 0x80C10000
	StatusBadFilterOperatorUnsupported           StatusCode = 0x80C20000
	StatusBadFilterOperandCountMismatch          StatusCode = 0x80C30000
	StatusBadFilterOperandInvalid                StatusCode = 0x80490000
	StatusBadFilterElementInvalid                StatusCode = 0x80C40000
	StatusBadFilterLiteralInvalid                StatusCode = 0x80C50000
	StatusBadContinuationPointInvalid            StatusCode = 0x804A0000
	StatusBadNoContinuationPoints                StatusCode = 0x804B0000
	StatusBadReferenceTypeIdInvalid              StatusCode = 0x804C0000
	StatusBadBrowseDirectionInvalid              StatusCode = 0x804D0000
	StatusBadNodeNotInView                       StatusCode = 0x804E0000
	StatusBadNumericOverflow                     StatusCode = 0x81120000
	StatusBadServerUriInvalid                    StatusCode = 0x804F0000
	StatusBadServerNameMissing                   StatusCode = 0x80500000
	StatusBadDiscoveryUrlMissing                 StatusCode = 0x80510000
	StatusBadSempahoreFileMissing                StatusCode = 0x80520000
	StatusBadRequestTypeInvalid                  StatusCode = 0x80530000
	StatusBadSecurityModeRejected                StatusCode = 0x80540000
	StatusBadSecurityPolicyRejected              StatusCode = 0x80550000
	StatusBadTooManySessions                     StatusCode = 0x80560000
	StatusBadUserSignatureInvalid                StatusCode = 0x80570000
	StatusBadApplicationSignatureInvalid         StatusCode = 0x80580000
	StatusBadNoValidCertificates                 StatusCode = 0x80590000
	StatusBadIdentityChangeNotSupported          StatusCode = 0x80C60000
	StatusBadRequestCancelledByRequest           StatusCode = 0x805A0000
	StatusBadParentNodeIdInvalid                 StatusCode = 0x805B0000
	StatusBadReferenceNotAllowed                 StatusCode = 0x805C0000
	StatusBadNodeIdRejected                      StatusCode = 0x805D0000
	StatusBadNodeIdExists                        StatusCode = 0x805E0000
	StatusBadNodeClassInvalid                    StatusCode = 0x805F0000
	StatusBadBrowseNameInvalid                   StatusCode = 0x80600000
	StatusBadBrowseNameDuplicated                StatusCode = 0x80610000
	StatusBadNodeAttributesInvalid               StatusCode = 0x80620000
	StatusBadTypeDefinitionInvalid               StatusCode = 0x80630000
	StatusBadSourceNodeIdInvalid                 StatusCode = 0x80640000
	StatusBadTargetNodeIdInvalid                 StatusCode = 0x80650000
	StatusBadDuplicateReferenceNotAllowed        StatusCode = 0x80660000
	StatusBadInvalidSelfReference                StatusCode = 0x80670000
	StatusBadReferenceLocalOnly                  StatusCode = 0x80680000
	StatusBadNoDeleteRights                      StatusCode = 0x80690000
	StatusUncertainReferenceNotDeleted           StatusCode = 0x40BC0000
	StatusBadServerIndexInvalid                  StatusCode = 0x806A0000
	StatusBadViewIdUnknown                       StatusCode = 0x806B0000
	StatusBadViewTimestampInvalid                StatusCode = 0x80C90000
	StatusBadViewParameterMismatch               StatusCode = 0x80CA0000
	StatusBadViewVersionInvalid                  StatusCode = 0x80CB0000
	StatusUncertainNotAllNodesAvailable          StatusCode = 0x40C00000
	StatusGoodResultsMayBeIncomplete             StatusCode = 0x00BA0000
	StatusBadNotTypeDefinition                   StatusCode = 0x80C80000
	StatusUncertainReferenceOutOfServer          StatusCode = 0x406C0000
	StatusBadTooManyMatches                      StatusCode = 0x806D0000
	StatusBadQueryTooComplex                     StatusCode = 0x806E0000
	StatusBadNoMatch                             StatusCode = 0x806F0000
	StatusBadMaxAgeInvalid                       StatusCode = 0x80700000
	StatusBadSecurityModeInsufficient            StatusCode = 0x80E60000
	StatusBadHistoryOperationInvalid             StatusCode = 0x80710000
	StatusBadHistoryOperationUnsupported         StatusCode = 0x80720000
	StatusBadInvalidTimestampArgument            StatusCode = 0x80BD0000
	StatusBadWriteNotSupported                   StatusCode = 0x80730000
	StatusBadTypeMismatch                        StatusCode = 0x80740000
	StatusBadMethodInvalid                       StatusCode = 0x80750000
	StatusBadArgumentsMissing                    StatusCode = 0x80760000
	StatusBadNotExecutable                       StatusCode = 0x81110000
	StatusBadTooManySubscriptions                StatusCode = 0x80770000
	StatusBadTooManyPublishRequests              StatusCode = 0x80780000
	StatusBadNoSubscription                      StatusCode = 0x80790000
	StatusBadSequenceNumberUnknown               StatusCode = 0x807A0000
	StatusBadMessageNotAvailable                 StatusCode = 0x807B0000
	StatusBadInsufficientClientProfile           StatusCode = 0x807C0000
	StatusBadStateNotActive                      StatusCode = 0x80BF0000
	StatusBadAlreadyExists                       StatusCode = 0x81150000
	StatusBadTcpServerTooBusy                    StatusCode = 0x807D0000
	StatusBadTcpMessageTypeInvalid               StatusCode = 0x807E0000
	StatusBadTcpSecureChannelUnknown             StatusCode = 0x807F0000
	StatusBadTcpMessageTooLarge                  StatusCode = 0x80800000
	StatusBadTcpNotEnoughResources               StatusCode = 0x80810000
	StatusBadTcpInternalError                    StatusCode = 0x80820000
	StatusBadTcpEndpointUrlInvalid               StatusCode = 0x80830000
	StatusBadRequestInterrupted                  StatusCode = 0x80840000
	StatusBadRequestTimeout                      StatusCode = 0x80850000
	StatusBadSecureChannelClosed                 StatusCode = 0x80860000
	StatusBadSecureChannelTokenUnknown           StatusCode = 0x80870000
	StatusBadSequenceNumberInvalid               StatusCode = 0x80880000
	StatusBadProtocolVersionUnsupported          StatusCode = 0x80BE0000
	StatusBadConfigurationError                  StatusCode = 0x80890000
	StatusBadNotConnected                        StatusCode = 0x808A0000
	StatusBadDeviceFailure                       StatusCode = 0x808B0000
	StatusBadSensorFailure                       StatusCode = 0x808C0000
	StatusBadOutOfService                        StatusCode = 0x808D0000
	StatusBadDeadbandFilterInvalid               StatusCode = 0x808E0000
	StatusUncertainNoCommunicationLastUsableValue StatusCode = 0x408F0000
	StatusUncertainLastUsableValue               StatusCode = 0x40900000
	StatusUncertainSubstituteValue               StatusCode = 0x40910000
	StatusUncertainInitialValue                  StatusCode = 0x40920000
	StatusUncertainSensorNotAccurate             StatusCode = 0x40930000
	StatusUncertainEngineeringUnitsExceeded      StatusCode = 0x40940000
	StatusUncertainSubNormal                     StatusCode = 0x40950000
	StatusGoodLocalOverride                      StatusCode = 0x00960000
	StatusBadRefreshInProgress                   StatusCode = 0x80970000
	StatusBadConditionAlreadyDisabled            StatusCode = 0x80980000
	StatusBadConditionAlreadyEnabled             StatusCode = 0x80CC0000
	StatusBadConditionDisabled                   StatusCode = 0x80990000
	StatusBadEventIdUnknown                      StatusCode = 0x809A0000
	StatusBadEventNotAcknowledgeable             StatusCode = 0x80BB0000
	StatusBadDialogNotActive                     StatusCode = 0x80CD0000
	StatusBadDialogResponseInvalid               StatusCode = 0x80CE0000
	StatusBadConditionBranchAlreadyAcked         StatusCode = 0x80CF0000
	StatusBadConditionBranchAlreadyConfirmed     StatusCode = 0x80D00000
	StatusBadConditionAlreadyShelved             StatusCode = 0x80D10000
	StatusBadConditionNotShelved                 StatusCode = 0x80D20000
	StatusBadShelvingTimeOutOfRange              StatusCode = 0x80D30000
	StatusBadNoData                              StatusCode = 0x809B0000
	StatusBadBoundNotFound                       StatusCode = 0x80D70000
	StatusBadBoundNotSupported                   StatusCode = 0x80D80000
	StatusBadDataLost                            StatusCode = 0x809D0000
	StatusBadDataUnavailable                     StatusCode = 0x809E0000
	StatusBadEntryExists                         StatusCode = 0x809F0000
	StatusBadNoEntryExists                       StatusCode = 0x80A00000
	StatusBadTimestampNotSupported               StatusCode = 0x80A10000
	StatusGoodEntryInserted                      StatusCode = 0x00A20000
	StatusGoodEntryReplaced                      StatusCode = 0x00A30000
	StatusUncertainDataSubNormal                 StatusCode = 0x40A40000
	StatusGoodNoData                             StatusCode = 0x00A50000
	StatusGoodMoreData                           StatusCode = 0x00A60000
	StatusBadAggregateListMismatch               StatusCode = 0x80D40000
	StatusBadAggregateNotSupported               StatusCode = 0x80D50000
	StatusBadAggregateInvalidInputs              StatusCode = 0x80D60000
	StatusBadAggregateConfigurationRejected      StatusCode = 0x80DA0000
	StatusGoodDataIgnored                        StatusCode = 0x00D90000
	StatusBadRequestNotAllowed                   StatusCode = 0x80E40000
	StatusBadRequestNotComplete                  StatusCode = 0x81130000
	StatusGoodEdited                             StatusCode = 0x00DC0000
	StatusGoodPostActionFailed                   StatusCode = 0x00DD0000
	StatusUncertainDominantValueChanged          StatusCode = 0x40DE0000
	StatusGoodDependentValueChanged              StatusCode = 0x00E00000
	StatusBadDominantValueChanged                StatusCode = 0x80E10000
	StatusUncertainDependentValueChanged         StatusCode = 0x40E20000
	StatusBadDependentValueChanged               StatusCode = 0x80E30000
	StatusGoodCommunicationEvent                 StatusCode = 0x00A70000
	StatusGoodShutdownEvent                      StatusCode = 0x00A80000
	StatusGoodCallAgain                          StatusCode = 0x00A90000
	StatusGoodNonCriticalTimeout                 StatusCode = 0x00AA0000
	StatusBadInvalidArgument                     StatusCode = 0x80AB0000
	StatusBadConnectionRejected                  StatusCode = 0x80AC0000
	StatusBadDisconnect                          StatusCode = 0x80AD0000
	StatusBadConnectionClosed                    StatusCode = 0x80AE0000
	StatusBadInvalidState                        StatusCode = 0x80AF0000
	StatusBadEndOfStream                         StatusCode = 0x80B00000
	StatusBadNoDataAvailable                     StatusCode = 0x80B10000
	StatusBadWaitingForResponse                  StatusCode = 0x80B20000
	StatusBadOperationAbandoned                  StatusCode = 0x80B30000
	StatusBadExpectedStreamToBlock               StatusCode = 0x80B40000
	StatusBadWouldBlock                          StatusCode = 0x80B50000
	StatusBadSyntaxError                         StatusCode = 0x80B60000
	StatusBadMaxConnectionsReached               StatusCode = 0x80B70000
)

// statusCodeInfo contains name and description for a status code.
type statusCodeInfo struct {
	name        string
	description string
}

// statusCodeMap maps status codes to their info.
var statusCodeMap = map[StatusCode]statusCodeInfo{
	StatusGood:                                   {"Good", "The operation completed successfully"},
	StatusBadUnexpectedError:                     {"BadUnexpectedError", "An unexpected error occurred"},
	StatusBadInternalError:                       {"BadInternalError", "An internal error occurred"},
	StatusBadOutOfMemory:                         {"BadOutOfMemory", "Not enough memory to complete the operation"},
	StatusBadResourceUnavailable:                 {"BadResourceUnavailable", "An operating system resource is not available"},
	StatusBadCommunicationError:                  {"BadCommunicationError", "A low level communication error occurred"},
	StatusBadEncodingError:                       {"BadEncodingError", "Encoding halted because of invalid data"},
	StatusBadDecodingError:                       {"BadDecodingError", "Decoding halted because of invalid data"},
	StatusBadEncodingLimitsExceeded:              {"BadEncodingLimitsExceeded", "The message encoding/decoding limits have been exceeded"},
	StatusBadRequestTooLarge:                     {"BadRequestTooLarge", "The request message size exceeds limits"},
	StatusBadResponseTooLarge:                    {"BadResponseTooLarge", "The response message size exceeds limits"},
	StatusBadUnknownResponse:                     {"BadUnknownResponse", "An unrecognized response was received from the server"},
	StatusBadTimeout:                             {"BadTimeout", "The operation timed out"},
	StatusBadServiceUnsupported:                  {"BadServiceUnsupported", "The server does not support the requested service"},
	StatusBadShutdown:                            {"BadShutdown", "The operation was cancelled because the application is shutting down"},
	StatusBadServerNotConnected:                  {"BadServerNotConnected", "The operation could not complete because the client is not connected to the server"},
	StatusBadServerHalted:                        {"BadServerHalted", "The server has stopped and cannot process any requests"},
	StatusBadNothingToDo:                         {"BadNothingToDo", "No processing could be done because there was nothing to do"},
	StatusBadTooManyOperations:                   {"BadTooManyOperations", "The request could not be processed because it specified too many operations"},
	StatusBadTooManyMonitoredItems:               {"BadTooManyMonitoredItems", "The request could not be processed because there are too many monitored items"},
	StatusBadDataTypeIdUnknown:                   {"BadDataTypeIdUnknown", "The extension object cannot be decoded because the data type is not known"},
	StatusBadCertificateInvalid:                  {"BadCertificateInvalid", "The certificate provided is not valid"},
	StatusBadSecurityChecksFailed:                {"BadSecurityChecksFailed", "An error occurred verifying security"},
	StatusBadCertificateTimeInvalid:              {"BadCertificateTimeInvalid", "The certificate has expired or is not yet valid"},
	StatusBadCertificateIssuerTimeInvalid:        {"BadCertificateIssuerTimeInvalid", "An issuer certificate has expired or is not yet valid"},
	StatusBadCertificateHostNameInvalid:          {"BadCertificateHostNameInvalid", "The hostname used to connect does not match a hostname in the certificate"},
	StatusBadCertificateUriInvalid:               {"BadCertificateUriInvalid", "The URI in the certificate does not match the application URI"},
	StatusBadCertificateUseNotAllowed:            {"BadCertificateUseNotAllowed", "The certificate may not be used for the requested operation"},
	StatusBadCertificateIssuerUseNotAllowed:      {"BadCertificateIssuerUseNotAllowed", "The issuer certificate may not be used for the requested operation"},
	StatusBadCertificateUntrusted:                {"BadCertificateUntrusted", "The certificate is not trusted"},
	StatusBadCertificateRevocationUnknown:        {"BadCertificateRevocationUnknown", "It was not possible to determine if the certificate has been revoked"},
	StatusBadCertificateIssuerRevocationUnknown:  {"BadCertificateIssuerRevocationUnknown", "It was not possible to determine if the issuer certificate has been revoked"},
	StatusBadCertificateRevoked:                  {"BadCertificateRevoked", "The certificate has been revoked"},
	StatusBadCertificateIssuerRevoked:            {"BadCertificateIssuerRevoked", "The issuer certificate has been revoked"},
	StatusBadCertificateChainIncomplete:          {"BadCertificateChainIncomplete", "The certificate chain is incomplete"},
	StatusBadUserAccessDenied:                    {"BadUserAccessDenied", "User access denied"},
	StatusBadIdentityTokenInvalid:                {"BadIdentityTokenInvalid", "The user identity token is not valid"},
	StatusBadIdentityTokenRejected:               {"BadIdentityTokenRejected", "The user identity token is rejected by the server"},
	StatusBadSecureChannelIdInvalid:              {"BadSecureChannelIdInvalid", "The specified secure channel is no longer valid"},
	StatusBadInvalidTimestamp:                    {"BadInvalidTimestamp", "The timestamp is outside the range allowed by the server"},
	StatusBadNonceInvalid:                        {"BadNonceInvalid", "The nonce does not appear to be a valid nonce"},
	StatusBadSessionIdInvalid:                    {"BadSessionIdInvalid", "The session ID is not valid"},
	StatusBadSessionClosed:                       {"BadSessionClosed", "The session was closed by the client"},
	StatusBadSessionNotActivated:                 {"BadSessionNotActivated", "The session cannot be used because it has not been activated"},
	StatusBadSubscriptionIdInvalid:               {"BadSubscriptionIdInvalid", "The subscription ID is not valid"},
	StatusBadRequestHeaderInvalid:                {"BadRequestHeaderInvalid", "The header for the request is missing or invalid"},
	StatusBadTimestampsToReturnInvalid:           {"BadTimestampsToReturnInvalid", "The timestamps to return parameter is invalid"},
	StatusBadRequestCancelledByClient:            {"BadRequestCancelledByClient", "The request was cancelled by the client"},
	StatusBadNoCommunication:                     {"BadNoCommunication", "Communication with the data source is not available"},
	StatusBadWaitingForInitialData:               {"BadWaitingForInitialData", "Waiting for the server to obtain values from the data source"},
	StatusBadNodeIdInvalid:                       {"BadNodeIdInvalid", "The node ID format is not valid"},
	StatusBadNodeIdUnknown:                       {"BadNodeIdUnknown", "The node ID refers to a node that does not exist"},
	StatusBadAttributeIdInvalid:                  {"BadAttributeIdInvalid", "The attribute ID is not valid for this node"},
	StatusBadIndexRangeInvalid:                   {"BadIndexRangeInvalid", "The index range is invalid"},
	StatusBadIndexRangeNoData:                    {"BadIndexRangeNoData", "No data exists within the range of indexes specified"},
	StatusBadDataEncodingInvalid:                 {"BadDataEncodingInvalid", "The data encoding is invalid"},
	StatusBadDataEncodingUnsupported:             {"BadDataEncodingUnsupported", "The server does not support the requested data encoding"},
	StatusBadNotReadable:                         {"BadNotReadable", "The access level does not allow reading the value"},
	StatusBadNotWritable:                         {"BadNotWritable", "The access level does not allow writing the value"},
	StatusBadOutOfRange:                          {"BadOutOfRange", "The value was out of range"},
	StatusBadNotSupported:                        {"BadNotSupported", "The requested operation is not supported"},
	StatusBadNotFound:                            {"BadNotFound", "A requested item was not found"},
	StatusBadObjectDeleted:                       {"BadObjectDeleted", "The object cannot be used because it has been deleted"},
	StatusBadNotImplemented:                      {"BadNotImplemented", "Requested operation is not implemented"},
	StatusBadMonitoringModeInvalid:               {"BadMonitoringModeInvalid", "The monitoring mode is invalid"},
	StatusBadMonitoredItemIdInvalid:              {"BadMonitoredItemIdInvalid", "The monitored item ID is not valid"},
	StatusBadMonitoredItemFilterInvalid:          {"BadMonitoredItemFilterInvalid", "The monitored item filter parameter is not valid"},
	StatusBadMonitoredItemFilterUnsupported:      {"BadMonitoredItemFilterUnsupported", "The server does not support the requested monitored item filter"},
	StatusBadFilterNotAllowed:                    {"BadFilterNotAllowed", "A monitoring filter cannot be used with the attribute specified"},
	StatusBadContinuationPointInvalid:            {"BadContinuationPointInvalid", "The continuation point is not valid"},
	StatusBadNoContinuationPoints:                {"BadNoContinuationPoints", "The server has no continuation points available"},
	StatusBadReferenceTypeIdInvalid:              {"BadReferenceTypeIdInvalid", "The reference type ID is not valid"},
	StatusBadBrowseDirectionInvalid:              {"BadBrowseDirectionInvalid", "The browse direction is not valid"},
	StatusBadNodeNotInView:                       {"BadNodeNotInView", "The node is not part of the view"},
	StatusBadServerUriInvalid:                    {"BadServerUriInvalid", "The server URI is not valid"},
	StatusBadServerNameMissing:                   {"BadServerNameMissing", "No server name was specified"},
	StatusBadDiscoveryUrlMissing:                 {"BadDiscoveryUrlMissing", "No discovery URL was specified"},
	StatusBadRequestTypeInvalid:                  {"BadRequestTypeInvalid", "The request type is not valid for the secure channel"},
	StatusBadSecurityModeRejected:                {"BadSecurityModeRejected", "The security mode does not meet the security policy requirements"},
	StatusBadSecurityPolicyRejected:              {"BadSecurityPolicyRejected", "The security policy does not meet the security policy requirements"},
	StatusBadTooManySessions:                     {"BadTooManySessions", "The server has reached its maximum number of sessions"},
	StatusBadUserSignatureInvalid:                {"BadUserSignatureInvalid", "The user token signature is not valid"},
	StatusBadApplicationSignatureInvalid:         {"BadApplicationSignatureInvalid", "The signature generated with the client certificate is not valid"},
	StatusBadNoValidCertificates:                 {"BadNoValidCertificates", "The client did not provide a valid certificate"},
	StatusBadTypeMismatch:                        {"BadTypeMismatch", "The value provided does not match the expected data type"},
	StatusBadMethodInvalid:                       {"BadMethodInvalid", "The method ID does not refer to a valid method"},
	StatusBadArgumentsMissing:                    {"BadArgumentsMissing", "Required argument(s) are missing"},
	StatusBadTooManySubscriptions:                {"BadTooManySubscriptions", "Too many subscriptions"},
	StatusBadTooManyPublishRequests:              {"BadTooManyPublishRequests", "Too many publish requests have been queued"},
	StatusBadNoSubscription:                      {"BadNoSubscription", "There is no subscription available for this session"},
	StatusBadTcpServerTooBusy:                    {"BadTcpServerTooBusy", "The server cannot process the request because it is too busy"},
	StatusBadTcpMessageTypeInvalid:               {"BadTcpMessageTypeInvalid", "The type of the message is not valid"},
	StatusBadTcpSecureChannelUnknown:             {"BadTcpSecureChannelUnknown", "The secure channel is not known"},
	StatusBadTcpMessageTooLarge:                  {"BadTcpMessageTooLarge", "The message size exceeds the maximum allowed"},
	StatusBadTcpNotEnoughResources:               {"BadTcpNotEnoughResources", "There are not enough resources to process the request"},
	StatusBadTcpInternalError:                    {"BadTcpInternalError", "An internal error occurred"},
	StatusBadTcpEndpointUrlInvalid:               {"BadTcpEndpointUrlInvalid", "The endpoint URL is not valid"},
	StatusBadRequestInterrupted:                  {"BadRequestInterrupted", "The request was interrupted by a network error"},
	StatusBadRequestTimeout:                      {"BadRequestTimeout", "The request timed out"},
	StatusBadSecureChannelClosed:                 {"BadSecureChannelClosed", "The secure channel has been closed"},
	StatusBadSecureChannelTokenUnknown:           {"BadSecureChannelTokenUnknown", "The token has expired or is not recognized"},
	StatusBadSequenceNumberInvalid:               {"BadSequenceNumberInvalid", "The sequence number is not valid"},
	StatusBadProtocolVersionUnsupported:          {"BadProtocolVersionUnsupported", "The protocol version is not supported"},
	StatusBadConfigurationError:                  {"BadConfigurationError", "There is a configuration error"},
	StatusBadNotConnected:                        {"BadNotConnected", "The variable should receive its value from another variable but has never been configured"},
	StatusBadDeviceFailure:                       {"BadDeviceFailure", "There has been a failure in the device/data source"},
	StatusBadSensorFailure:                       {"BadSensorFailure", "There has been a failure in the sensor"},
	StatusBadOutOfService:                        {"BadOutOfService", "The source of the data is not operational"},
	StatusBadInvalidArgument:                     {"BadInvalidArgument", "One or more arguments are invalid"},
	StatusBadConnectionRejected:                  {"BadConnectionRejected", "The server rejected the connection"},
	StatusBadDisconnect:                          {"BadDisconnect", "The connection was disconnected"},
	StatusBadConnectionClosed:                    {"BadConnectionClosed", "The connection was closed"},
	StatusBadInvalidState:                        {"BadInvalidState", "The operation cannot be completed because the object is closed or in an invalid state"},
	StatusBadEndOfStream:                         {"BadEndOfStream", "Cannot move beyond end of the stream"},
	StatusBadNoDataAvailable:                     {"BadNoDataAvailable", "No data is currently available"},
	StatusBadWaitingForResponse:                  {"BadWaitingForResponse", "The server is waiting for a response to a request it sent"},
	StatusBadOperationAbandoned:                  {"BadOperationAbandoned", "The operation was abandoned because a previous operation is still running"},
	StatusBadExpectedStreamToBlock:               {"BadExpectedStreamToBlock", "The stream did not return all data requested (normally because it would block)"},
	StatusBadWouldBlock:                          {"BadWouldBlock", "Non blocking behaviour is required and the operation would block"},
	StatusBadSyntaxError:                         {"BadSyntaxError", "A value had an invalid syntax"},
	StatusBadMaxConnectionsReached:               {"BadMaxConnectionsReached", "The server has reached the maximum number of connections it supports"},
	StatusBadSecurityModeInsufficient:            {"BadSecurityModeInsufficient", "The security mode is not acceptable for the operation"},
}

// String returns the string representation of the status code.
func (s StatusCode) String() string {
	if info, ok := statusCodeMap[s]; ok {
		return info.name
	}
	return fmt.Sprintf("StatusCode(0x%08X)", uint32(s))
}

// Description returns a human-readable description of the status code.
func (s StatusCode) Description() string {
	if info, ok := statusCodeMap[s]; ok {
		return info.description
	}
	// Provide severity-based fallback descriptions
	switch {
	case s.IsGood():
		return "The operation completed successfully"
	case s.IsUncertain():
		return "The operation completed with uncertain result"
	case s.IsBad():
		return "The operation failed"
	default:
		return "Unknown status"
	}
}

// Error returns a formatted error string with code, name, and description.
func (s StatusCode) Error() string {
	if info, ok := statusCodeMap[s]; ok {
		return fmt.Sprintf("%s (0x%08X): %s", info.name, uint32(s), info.description)
	}
	return fmt.Sprintf("StatusCode 0x%08X", uint32(s))
}

// IsGood returns true if the status code indicates success.
func (s StatusCode) IsGood() bool {
	return (uint32(s) & StatusSeverityMask) == StatusSeverityGood
}

// IsUncertain returns true if the status code indicates uncertainty.
func (s StatusCode) IsUncertain() bool {
	return (uint32(s) & StatusSeverityMask) == StatusSeverityUncertain
}

// IsBad returns true if the status code indicates failure.
func (s StatusCode) IsBad() bool {
	return (uint32(s) & StatusSeverityMask) == StatusSeverityBad
}

// OPCUAError represents an OPC UA protocol error.
type OPCUAError struct {
	ServiceID  ServiceID
	StatusCode StatusCode
	Message    string
}

// Error implements the error interface.
func (e *OPCUAError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("opcua: %s (%s): %s", e.StatusCode, e.ServiceID, e.Message)
	}
	return fmt.Sprintf("opcua: %s (%s)", e.StatusCode, e.ServiceID)
}

// Is checks if the error matches the target.
func (e *OPCUAError) Is(target error) bool {
	t, ok := target.(*OPCUAError)
	if !ok {
		return false
	}
	return e.StatusCode == t.StatusCode
}

// Common errors.
var (
	// ErrInvalidResponse indicates the response was malformed or unexpected.
	ErrInvalidResponse = errors.New("opcua: invalid response")

	// ErrInvalidMessage indicates a malformed message.
	ErrInvalidMessage = errors.New("opcua: invalid message")

	// ErrTimeout indicates a timeout occurred.
	ErrTimeout = errors.New("opcua: timeout")

	// ErrConnectionClosed indicates the connection was closed.
	ErrConnectionClosed = errors.New("opcua: connection closed")

	// ErrSessionClosed indicates the session was closed.
	ErrSessionClosed = errors.New("opcua: session closed")

	// ErrSessionNotActivated indicates the session is not activated.
	ErrSessionNotActivated = errors.New("opcua: session not activated")

	// ErrSecureChannelClosed indicates the secure channel was closed.
	ErrSecureChannelClosed = errors.New("opcua: secure channel closed")

	// ErrPoolExhausted indicates no connections are available in the pool.
	ErrPoolExhausted = errors.New("opcua: connection pool exhausted")

	// ErrPoolClosed indicates the pool has been closed.
	ErrPoolClosed = errors.New("opcua: connection pool closed")

	// ErrNotConnected indicates the client is not connected.
	ErrNotConnected = errors.New("opcua: not connected")

	// ErrMaxRetriesExceeded indicates the maximum number of retries was exceeded.
	ErrMaxRetriesExceeded = errors.New("opcua: max retries exceeded")

	// ErrInvalidNodeID indicates an invalid NodeID was specified.
	ErrInvalidNodeID = errors.New("opcua: invalid node ID")

	// ErrInvalidEndpoint indicates an invalid endpoint was specified.
	ErrInvalidEndpoint = errors.New("opcua: invalid endpoint")

	// ErrSecurityPolicyNotSupported indicates the security policy is not supported.
	ErrSecurityPolicyNotSupported = errors.New("opcua: security policy not supported")

	// ErrCertificateRequired indicates a certificate is required.
	ErrCertificateRequired = errors.New("opcua: certificate required")

	// ErrSubscriptionNotFound indicates the subscription was not found.
	ErrSubscriptionNotFound = errors.New("opcua: subscription not found")

	// ErrMonitoredItemNotFound indicates the monitored item was not found.
	ErrMonitoredItemNotFound = errors.New("opcua: monitored item not found")
)

// NewOPCUAError creates a new OPC UA error.
func NewOPCUAError(svc ServiceID, sc StatusCode, msg string) *OPCUAError {
	return &OPCUAError{
		ServiceID:  svc,
		StatusCode: sc,
		Message:    msg,
	}
}

// IsStatusCode checks if an error has a specific status code.
func IsStatusCode(err error, code StatusCode) bool {
	var opcuaErr *OPCUAError
	if errors.As(err, &opcuaErr) {
		return opcuaErr.StatusCode == code
	}
	return false
}

// IsBadStatusCode checks if an error has a bad status code.
func IsBadStatusCode(err error) bool {
	var opcuaErr *OPCUAError
	if errors.As(err, &opcuaErr) {
		return opcuaErr.StatusCode.IsBad()
	}
	return false
}

// IsTimeout checks if the error is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout) || IsStatusCode(err, StatusBadTimeout)
}

// IsNotConnected checks if the error indicates not connected.
func IsNotConnected(err error) bool {
	return errors.Is(err, ErrNotConnected) || IsStatusCode(err, StatusBadNotConnected)
}

// IsSessionClosed checks if the error indicates session closed.
func IsSessionClosed(err error) bool {
	return errors.Is(err, ErrSessionClosed) || IsStatusCode(err, StatusBadSessionClosed)
}

// IsSecureChannelClosed checks if the error indicates secure channel closed.
func IsSecureChannelClosed(err error) bool {
	return errors.Is(err, ErrSecureChannelClosed) || IsStatusCode(err, StatusBadSecureChannelClosed)
}

// IsNodeIDUnknown checks if the error indicates an unknown node ID.
func IsNodeIDUnknown(err error) bool {
	return IsStatusCode(err, StatusBadNodeIdUnknown)
}

// IsAttributeInvalid checks if the error indicates an invalid attribute.
func IsAttributeInvalid(err error) bool {
	return IsStatusCode(err, StatusBadAttributeIdInvalid)
}

// IsNotReadable checks if the error indicates the value is not readable.
func IsNotReadable(err error) bool {
	return IsStatusCode(err, StatusBadNotReadable)
}

// IsNotWritable checks if the error indicates the value is not writable.
func IsNotWritable(err error) bool {
	return IsStatusCode(err, StatusBadNotWritable)
}

// IsUserAccessDenied checks if the error indicates access denied.
func IsUserAccessDenied(err error) bool {
	return IsStatusCode(err, StatusBadUserAccessDenied)
}
