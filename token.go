package cloudafrica

import (
	"context"
	"errors"
)

// TokenSource supplies the bearer credential for each request. The client
// asks again on every attempt, so a source that refreshes an expiring token
// takes effect mid-retry. Token may be called from several goroutines at once
// (up to the client's concurrency, plus WaitForOperation polls), so an
// implementation that caches must be safe for concurrent use.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token calls f.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) {
	return f(ctx)
}

// StaticToken is a TokenSource for a fixed credential, such as a cak_ API
// token. New refuses an empty one.
func StaticToken(token string) TokenSource {
	return staticToken(token)
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) {
	if s == "" {
		return "", errors.New("empty token")
	}
	return string(s), nil
}
