package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestNewInviteToken(t *testing.T) {
	t.Parallel()
	token, digest, err := newInviteToken()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("the token is not unpadded base64url: %v", err)
	}
	if len(raw) != inviteTokenBytes {
		t.Errorf("the token carries %d bytes, expected %d", len(raw), inviteTokenBytes)
	}
	want := sha256.Sum256([]byte(token))
	if !bytes.Equal(digest, want[:]) {
		t.Error("the stored digest is not the SHA-256 of the token")
	}
	if bytes.Contains(digest, []byte(token)) {
		t.Error("the digest contains the token")
	}
	got, ok := inviteDigest(token)
	if !ok || !bytes.Equal(got, digest) {
		t.Error("a presented token does not hash to what was stored")
	}
	other, _, err := newInviteToken()
	if err != nil {
		t.Fatal(err)
	}
	if other == token {
		t.Error("two tokens are the same")
	}
}

func TestInviteDigestRejectsForeignTokens(t *testing.T) {
	t.Parallel()
	short := base64.RawURLEncoding.EncodeToString(make([]byte, inviteTokenBytes-1))
	long := base64.RawURLEncoding.EncodeToString(make([]byte, inviteTokenBytes+1))
	padded := base64.URLEncoding.EncodeToString(make([]byte, inviteTokenBytes))
	for name, token := range map[string]string{
		"empty":        "",
		"short":        short,
		"long":         long,
		"padded":       padded,
		"not base64":   "this is not a token at all, not even close!!",
		"api key-like": "smk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, ok := inviteDigest(token); ok {
				t.Errorf("%q was taken for a token", token)
			}
		})
	}
}

func TestInviteStatus(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	at := func(t time.Time) *time.Time { return &t }
	tests := []struct {
		name              string
		accepted, revoked *time.Time
		expires           time.Time
		want              string
	}{
		{"open", nil, nil, future, InvitePending},
		{"expired", nil, nil, past, InviteExpired},
		{"expires this instant", nil, nil, now, InviteExpired},
		{"accepted", at(past), nil, future, InviteAccepted},
		{"accepted then expired", at(past), nil, past, InviteAccepted},
		{"revoked", nil, at(past), future, InviteRevoked},
		{"revoked after expiry", nil, at(now), past, InviteRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inviteStatus(tt.accepted, tt.revoked, tt.expires, now); got != tt.want {
				t.Errorf("status %q, expected %q", got, tt.want)
			}
		})
	}
}

// TestCreateInviteValidates covers the refusals made before the database
// is reached, which is why the service has none.
func TestCreateInviteValidates(t *testing.T) {
	t.Parallel()
	s := &Service{now: time.Now, NewID: func() string { return "id" }}
	tests := []struct {
		name string
		in   InviteInput
		want error
	}{
		{"not an address", InviteInput{Email: "nobody", RoleID: "role_viewer"}, ErrInviteEmail},
		{"two ats", InviteInput{Email: "a@b@c.example", RoleID: "role_viewer"}, ErrInviteEmail},
		{"too long", InviteInput{Email: "a@b.example", RoleID: "role_viewer", TTL: MaxInviteTTL + time.Second}, ErrInviteTTL},
		{"negative", InviteInput{Email: "a@b.example", RoleID: "role_viewer", TTL: -time.Hour}, ErrInviteTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, token, err := s.CreateInvite(context.Background(), "org", "actor", tt.in)
			if !errors.Is(err, tt.want) {
				t.Errorf("error %v, expected %v", err, tt.want)
			}
			if token != "" {
				t.Error("a refused invite returned a token")
			}
		})
	}
}
