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
	File        FileFeatureMap
}

type MessageType string

const (
	MsgText  MessageType = "m.text"
	MsgImage MessageType = "m.image"
	MsgVideo MessageType = "m.video"
	MsgAudio MessageType = "m.audio"
	MsgFile  MessageType = "m.file"
)

type CapabilityMsgType = MessageType

const CapMsgGIF CapabilityMsgType = "fi.mau.gif"

type CapabilitySupportLevel int

const (
	CapLevelRejected       CapabilitySupportLevel = -2
	CapLevelUnsupported    CapabilitySupportLevel = 0
	CapLevelFullySupported CapabilitySupportLevel = 2
)

type FileFeatures struct {
	MimeTypes map[string]CapabilitySupportLevel
}

type FileFeatureMap map[CapabilityMsgType]*FileFeatures

type FileInfo struct {
	MimeType string
	Width    int
}

type EncryptedFileInfo struct{}

type MessageEventContent struct {
	MsgType MessageType
	Body    string
	URL     string
	File    *EncryptedFileInfo
	Info    *FileInfo
}
