package mc

import (
	"crypto/sha256"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

var imageMimes = map[string]event.CapabilitySupportLevel{
	"image/png": event.CapLevelFullySupported,
	"image/gif": event.CapLevelFullySupported, // want `MC002`
}

var caps = &event.RoomFeatures{
	File: event.FileFeatureMap{
		event.MsgImage: {MimeTypes: imageMimes},
		event.MsgVideo: {MimeTypes: map[string]event.CapabilitySupportLevel{"image/gif": event.CapLevelFullySupported}},
	},
}

func directURI(url string) (string, error) { return "mxc://" + url, nil }

func avatarLiteral(mxc string) *bridgev2.Avatar {
	return &bridgev2.Avatar{ID: mxc, MXC: mxc} // want `MC001`
}

func avatarLiteralHashed(mxc string) *bridgev2.Avatar {
	return &bridgev2.Avatar{ID: mxc, MXC: mxc, Hash: sha256.Sum256([]byte(mxc))}
}

const defaultAvatar = "mxc://example.com/default"

func avatarConstant() *bridgev2.Avatar {
	return &bridgev2.Avatar{ID: defaultAvatar, MXC: defaultAvatar}
}

func avatarRemoved(mxc string) *bridgev2.Avatar {
	return &bridgev2.Avatar{MXC: mxc, Remove: true}
}

func avatarHashedLater(mxc string) *bridgev2.Avatar {
	a := &bridgev2.Avatar{ID: mxc, MXC: mxc}
	a.Hash = sha256.Sum256([]byte(mxc))
	return a
}

func avatarAssigned(url string, direct bool) *bridgev2.Avatar {
	avatar := &bridgev2.Avatar{ID: url, Get: func() ([]byte, error) { return nil, nil }}
	if direct {
		var err error
		avatar.MXC, err = directURI(url) // want `MC001`
		_ = err
	}
	return avatar
}

func avatarAssignedHashed(url string) *bridgev2.Avatar {
	avatar := &bridgev2.Avatar{ID: url}
	avatar.MXC, _ = directURI(url)
	avatar.Hash = sha256.Sum256([]byte(url))
	return avatar
}

type userInfo struct{ Avatar *bridgev2.Avatar }

func avatarField(url string) *userInfo {
	info := &userInfo{}
	info.Avatar = &bridgev2.Avatar{ID: url}
	info.Avatar.MXC, _ = directURI(url) // want `MC001`
	return info
}

func avatarFromHelper(url string) *bridgev2.Avatar {
	avatar := avatarLiteralHashed(url)
	avatar.MXC, _ = directURI(url)
	return avatar
}

func avatarCleared(a *bridgev2.Avatar) {
	b := &bridgev2.Avatar{ID: "x"}
	b.MXC = ""
	_ = b
}

type attachment struct {
	Type, URL, Mime string
}

func mediaSwitch(att *attachment) *event.MessageEventContent {
	content := &event.MessageEventContent{}
	switch att.Type {
	case "image":
		content.MsgType, content.Body = event.MsgImage, "image" // want `MC003`
	case "video":
		content.MsgType, content.Body = event.MsgVideo, "video" // want `MC003`
	case "file":
		content.MsgType, content.Body = event.MsgFile, "file"
		content.Info = &event.FileInfo{MimeType: att.Mime}
	default:
		return nil
	}
	content.URL, _ = directURI(att.URL)
	return content
}

func mediaConditionalInfo(att *attachment) *event.MessageEventContent {
	content := &event.MessageEventContent{MsgType: event.MsgImage, URL: att.URL}
	if att.Mime != "" {
		content.Info = &event.FileInfo{MimeType: att.Mime}
	}
	return content
}

func mediaInfoField(att *attachment) *event.MessageEventContent {
	content := &event.MessageEventContent{MsgType: event.MsgAudio, URL: att.URL, Info: &event.FileInfo{}}
	content.Info.MimeType = att.Mime
	return content
}

func fillInfo(c *event.MessageEventContent) {}

func mediaHelperFills(att *attachment) *event.MessageEventContent {
	content := &event.MessageEventContent{MsgType: event.MsgVideo, URL: att.URL}
	fillInfo(content)
	return content
}

func mediaLiteral(att *attachment) *event.MessageEventContent {
	return &event.MessageEventContent{MsgType: event.MsgImage, URL: att.URL} // want `MC003`
}

func mediaLiteralArg(att *attachment) {
	fillInfo(&event.MessageEventContent{MsgType: event.MsgImage, URL: att.URL})
}

func mediaNoURL(att *attachment) *event.MessageEventContent {
	return &event.MessageEventContent{MsgType: event.MsgImage, Body: "image unavailable"}
}

func textContent() *event.MessageEventContent {
	content := &event.MessageEventContent{MsgType: event.MsgText, URL: "x"}
	return content
}

func mediaParam(content *event.MessageEventContent) {
	content.MsgType = event.MsgImage
	content.URL = "x"
}

func mediaReplaced(att *attachment, other *event.MessageEventContent) *event.MessageEventContent {
	content := &event.MessageEventContent{MsgType: event.MsgImage, URL: att.URL}
	content = other
	return content
}
