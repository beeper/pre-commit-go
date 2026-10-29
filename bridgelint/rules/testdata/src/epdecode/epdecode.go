package epdecode

import (
	"encoding/json"
	"io"
)

type Message struct{ ID string }

type Handler interface {
	HandleMessage(m Message)
	HandleError(err error)
}

func dispatch(h Handler, b []byte) {
	var out Message
	if json.Unmarshal(b, &out) != nil || out.ID == "" { // want `EP004`
		return
	}
	h.HandleMessage(out)
}

func dispatchBound(h Handler, b []byte) {
	var out Message
	if err := json.Unmarshal(b, &out); err != nil { // want `EP004`
		return
	}
	h.HandleMessage(out)
}

func dispatchStream(h Handler, r io.Reader) {
	var out Message
	if err := json.NewDecoder(r).Decode(&out); err != nil { // want `EP004`
		return
	}
	h.HandleMessage(out)
}

func dispatchReported(h Handler, b []byte) {
	var out Message
	if err := json.Unmarshal(b, &out); err != nil {
		h.HandleError(err)
		return
	}
	h.HandleMessage(out)
}

func decode(b []byte) (Message, error) {
	var out Message
	if err := json.Unmarshal(b, &out); err != nil {
		return out, err
	}
	return out, nil
}

func decodeOK(b []byte) bool {
	var out Message
	if json.Unmarshal(b, &out) != nil {
		return false
	}
	return true
}

func filterRows(h Handler, rows [][]byte) {
	for _, row := range rows {
		var out Message
		if json.Unmarshal(row, &out) != nil {
			continue
		}
		h.HandleMessage(out)
	}
}

func fallback(h Handler, b []byte) {
	var out Message
	if json.Unmarshal(b, &out) != nil {
		out = Message{ID: "unknown"}
	}
	h.HandleMessage(out)
}
