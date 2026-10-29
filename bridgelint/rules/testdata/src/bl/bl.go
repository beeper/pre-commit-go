// Package bl covers the hygiene of bridgelint:ignore comments (BL000).
package bl

import "errors"

func suppressed() error {
	//bridgelint:ignore MSS002 the framework treats this reason as permanent here
	return errors.New("fine")
}

func suppressedAll() error {
	//bridgelint:ignore all this whole helper is a test double
	return errors.New("fine")
}

func bareIgnore() error {
	//bridgelint:ignore because I said so // want `BL000: bridgelint:ignore must name the rules`
	return errors.New("no rules named")
}

// An ordinary comment mentioning bridgelint:ignore in prose isn't a directive.
func notADirective() error {
	// We used to bridgelint:ignore this, but the rule was fixed.
	return errors.New("fine")
}
