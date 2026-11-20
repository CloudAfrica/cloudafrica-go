package cloudafrica

import (
	"context"
	"errors"
)

// TokenSource supplies the bearer credential for each request. The client
// asks again on every attempt, so a source that refreshes an expiring token
// takes effect mid-retry.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token calls f.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) {
	return f(ctx)
}

// StaticToken is a TokenSource for a fixed credential, such as a cak_ API token.
func StaticToken(token string) TokenSource {
	return TokenSourceFunc(func(context.Context) (string, error) {
		if token == "" {
			return "", errors.New("empty token")
		}
		return token, nil
	})
}
