package sdk

import (
	"context"
	"time"
)

type TokenValue struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshedAt  int64  `json:"refreshed_at,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

func (t TokenValue) Valid() bool {
	return t.AccessToken != "" && t.RefreshToken != ""
}

func (t TokenValue) WithRefreshTime(now time.Time) TokenValue {
	if t.RefreshedAt == 0 {
		t.RefreshedAt = now.Unix()
	}
	if t.ExpiresAt == 0 && t.ExpiresIn > 0 {
		t.ExpiresAt = t.RefreshedAt + t.ExpiresIn
	}
	return t
}

type BeforeTokenRefreshFunc func(context.Context, TokenValue) (*TokenValue, error)
