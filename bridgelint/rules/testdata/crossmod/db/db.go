// Package db stands in for a bridge's database layer, which runs queries through a transaction helper.
package db

import "context"

type Store struct{}

func (s *Store) withTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (s *Store) Insert(ctx context.Context, x string) error {
	return s.withTx(ctx, func(ctx context.Context) error { return nil })
}
