package status

type BridgeStateEvent string

const (
	StateConnecting          BridgeStateEvent = "CONNECTING"
	StateBackfilling         BridgeStateEvent = "BACKFILLING"
	StateConnected           BridgeStateEvent = "CONNECTED"
	StateTransientDisconnect BridgeStateEvent = "TRANSIENT_DISCONNECT"
	StateBadCredentials      BridgeStateEvent = "BAD_CREDENTIALS"
	StateUnknownError        BridgeStateEvent = "UNKNOWN_ERROR"
	StateLoggedOut           BridgeStateEvent = "LOGGED_OUT"
)

type BridgeStateUserAction string

const (
	UserActionOpenNative BridgeStateUserAction = "OPEN_NATIVE"
	UserActionRelogin    BridgeStateUserAction = "RELOGIN"
	UserActionRestart    BridgeStateUserAction = "RESTART"
)

type BridgeStateErrorCode string

type BridgeStateErrorMap map[BridgeStateErrorCode]string

func (bem BridgeStateErrorMap) Update(data BridgeStateErrorMap) {
	for k, v := range data {
		bem[k] = v
	}
}

var BridgeStateHumanErrors = make(BridgeStateErrorMap)

type BridgeState struct {
	StateEvent BridgeStateEvent
	Error      BridgeStateErrorCode
	Message    string
	UserAction BridgeStateUserAction
	Info       map[string]any
}
