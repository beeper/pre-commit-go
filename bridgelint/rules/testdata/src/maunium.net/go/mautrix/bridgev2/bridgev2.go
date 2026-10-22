// Package bridgev2 is a minimal stub of maunium.net/go/mautrix/bridgev2 for bridgelint tests.
package bridgev2

import (
	"context"
	"errors"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
)

type MessageStatus struct {
	Status        event.MessageStatus
	ErrorReason   event.MessageStatusReason
	InternalError error
	Message       string
	IsCertain     bool
	SendNotice    bool
}

func (ms MessageStatus) Error() string { return ms.Message }

func (ms MessageStatus) WithSendNotice(send bool) MessageStatus   { ms.SendNotice = send; return ms }
func (ms MessageStatus) WithIsCertain(certain bool) MessageStatus { ms.IsCertain = certain; return ms }
func (ms MessageStatus) WithMessage(msg string) MessageStatus     { ms.Message = msg; return ms }
func (ms MessageStatus) WithStatus(s event.MessageStatus) MessageStatus {
	ms.Status = s
	return ms
}
func (ms MessageStatus) WithErrorReason(r event.MessageStatusReason) MessageStatus {
	ms.ErrorReason = r
	return ms
}
func (ms MessageStatus) WithErrorAsMessage() MessageStatus { return ms }

type HumanError interface {
	error
	HumanError() string
}

func WrapErrorInStatus(err error) MessageStatus { return MessageStatus{InternalError: err} }

var (
	ErrNotLoggedIn            = errors.New("not logged in")
	ErrUnsupportedMessageType = WrapErrorInStatus(errors.New("unsupported message type")).WithErrorReason(event.MessageStatusUnsupported)
	ErrMediaTooLarge          = WrapErrorInStatus(errors.New("too large")).WithErrorReason(event.MessageStatusUnsupported)
)

type RespError mautrix.RespError

func (re RespError) Error() string { return re.Err }

func WrapRespErr(err error, target mautrix.RespError) RespError {
	return RespError{ErrCode: target.ErrCode, Err: err.Error(), StatusCode: target.StatusCode}
}

func WrapRespErrManual(err error, code string, status int) RespError {
	return RespError{ErrCode: code, Err: err.Error(), StatusCode: status}
}

type BridgeStateQueue struct{}

func (bsq *BridgeStateQueue) Send(state status.BridgeState) {}

type UserLogin struct {
	BridgeState *BridgeStateQueue
}

type MatrixMessage struct{ Content string }
type MatrixViewLimitedMedia struct{ Content string }
type MatrixMessageResponse struct{}
type MatrixEdit struct{}
type MatrixReaction struct{}
type ResolveIdentifierResponse struct{}
type LoginStep struct{}
type LoginFlow struct{}

type NetworkAPI interface {
	Connect(ctx context.Context)
	Disconnect()
	IsLoggedIn() bool
	LogoutRemote(ctx context.Context)
	HandleMatrixMessage(ctx context.Context, msg *MatrixMessage) (*MatrixMessageResponse, error)
}

type EditHandlingNetworkAPI interface {
	NetworkAPI
	HandleMatrixEdit(ctx context.Context, msg *MatrixEdit) error
}

type ReactionHandlingNetworkAPI interface {
	NetworkAPI
	HandleMatrixReaction(ctx context.Context, msg *MatrixReaction) error
}

type IdentifierResolvingNetworkAPI interface {
	NetworkAPI
	ResolveIdentifier(ctx context.Context, identifier string, createChat bool) (*ResolveIdentifierResponse, error)
}

type NetworkConnector interface {
	GetLoginFlows() []LoginFlow
	CreateLogin(ctx context.Context, user any, flowID string) (LoginProcess, error)
}

type LoginProcess interface {
	Start(ctx context.Context) (*LoginStep, error)
	Cancel()
}

type LoginProcessUserInput interface {
	LoginProcess
	SubmitUserInput(ctx context.Context, input map[string]string) (*LoginStep, error)
}

type LoginInputDataField struct {
	ID      string
	Name    string
	Pattern string
}

type Bridge struct{}

func (br *Bridge) QueueRemoteEvent(login *UserLogin, evt any) {}
