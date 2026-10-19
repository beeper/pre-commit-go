package event

type MessageStatus string

const (
	MessageStatusSuccess   MessageStatus = "SUCCESS"
	MessageStatusRetriable MessageStatus = "FAIL_RETRIABLE"
	MessageStatusFail      MessageStatus = "FAIL_PERMANENT"
)

type MessageStatusReason string

const (
	MessageStatusGenericError      MessageStatusReason = "m.foreign_network_error"
	MessageStatusUnsupported       MessageStatusReason = "m.event_type_not_supported"
	MessageStatusTooOld            MessageStatusReason = "m.event_too_old"
	MessageStatusNetworkError      MessageStatusReason = "m.foreign_network_error"
	MessageStatusNoPermission      MessageStatusReason = "m.no_permission"
	MessageStatusBridgeUnavailable MessageStatusReason = "m.bridge_unavailable"
)

type RoomFeatures struct {
	ID          string
	MaxTextSize int
	Edit        int
}
