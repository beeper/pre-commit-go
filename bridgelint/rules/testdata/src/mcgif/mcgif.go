package mcgif

import "maunium.net/go/mautrix/event"

var caps = &event.RoomFeatures{
	File: event.FileFeatureMap{
		event.MsgImage:  {MimeTypes: map[string]event.CapabilitySupportLevel{"image/gif": event.CapLevelFullySupported}},
		event.CapMsgGIF: {MimeTypes: map[string]event.CapabilitySupportLevel{"image/gif": event.CapLevelFullySupported}},
	},
}

var rejected = event.FileFeatureMap{
	event.MsgImage: {MimeTypes: map[string]event.CapabilitySupportLevel{"image/gif": event.CapLevelRejected}},
}
