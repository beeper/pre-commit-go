package mcrej

import "maunium.net/go/mautrix/event"

var rejected = event.FileFeatureMap{
	event.MsgImage: {MimeTypes: map[string]event.CapabilitySupportLevel{"image/gif": event.CapLevelRejected, "image/png": event.CapLevelFullySupported}},
}
