// Package memstore implements netlib.Store in memory.
package memstore

import (
	"context"
	"errors"
)

type Store struct{ m map[string]string }

func (s *Store) Load(ctx context.Context, key string) (string, error) {
	v, ok := s.m[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}
