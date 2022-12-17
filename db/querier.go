package db

import "context"

type Querier interface {
	GetUser(ctx context.Context, username string) (Access, error)
}

var _ Querier = (*Queries)(nil)
