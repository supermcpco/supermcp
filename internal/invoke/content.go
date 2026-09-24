package invoke

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/engine"
)

// defaultBlobTTL is how long a link stays answerable. Long enough for the
// model to follow it in the same turn, short enough that a leaked URL is
// worth little by the time it is used.
const defaultBlobTTL = 15 * time.Minute

// defaultMaxHeldBytes is the ceiling on what is read out of an upstream at
// all. The inline threshold decides embed-or-link; this decides whether
// the gateway is willing to hold the bytes in the first place.
const defaultMaxHeldBytes = 64 << 20

// BlobOwner is the identity a stored blob answers to.
type BlobOwner struct {
	OrgID       string
	PrincipalID string
}

// Zero reports whether the owner names nobody, in which case nothing may
// be stored for it.
func (o BlobOwner) Zero() bool { return o.OrgID == "" || o.PrincipalID == "" }

// Equal compares two owners without leaking the position of the first
// difference through timing.
func (o BlobOwner) Equal(other BlobOwner) bool {
	org := subtle.ConstantTimeCompare([]byte(o.OrgID), []byte(other.OrgID))
	pri := subtle.ConstantTimeCompare([]byte(o.PrincipalID), []byte(other.PrincipalID))
	return org&pri == 1
}

// BlobOwnerFor is the owner a principal's results belong to, and the same
// function the blob route uses to decide who is asking. It lives in one
// place because a link is only as sound as the two sides agreeing on what
// an identity is.
//
// An anonymous or org-less principal owns nothing, and its results are
// therefore never stored.
func BlobOwnerFor(p *authz.Principal) BlobOwner {
	if p == nil {
		return BlobOwner{}
	}
	id := p.ID
	// An API key acts for its owner but is revoked on its own, so the key
	// is the narrower identity and the one a link should follow.
	if p.APIKeyID != "" {
		id = "key:" + p.APIKeyID
	}
	return BlobOwner{OrgID: p.OrgID, PrincipalID: id}
}

// Blob is one binary tool result held for collection.
type Blob struct {
	Owner     BlobOwner
	MediaType string
	// Name is a display name for the link, not a file system path.
	Name      string
	Data      []byte
	ExpiresAt time.Time
}

// BlobRef is where a stored blob can be collected.
type BlobRef struct {
	ID        string
	URL       string
	ExpiresAt time.Time
}

// BlobStore holds binary tool results that are too large to put in a
// transcript, and hands them back only to the principal they were stored
// for.
//
// Get takes the owner rather than returning one for the caller to check,
// so there is no way to read a blob without presenting an identity: the
// authorisation cannot be forgotten at a call site because there is no
// call site that omits it.
type BlobStore interface {
	Put(ctx context.Context, b Blob) (BlobRef, error)
	// Get reports found=false both when the blob does not exist and when it
	// belongs to someone else. The two are indistinguishable on purpose.
	Get(ctx context.Context, id string, owner BlobOwner) (Blob, bool, error)
}

// Content turns binary upstream bodies into MCP content.
type Content struct {
	// Blobs holds what is too large to embed. Nil means there is nowhere
	// to put it, and an oversized result is an error rather than a link.
	Blobs BlobStore
	// MaxHeldBytes is the hard ceiling on one body. Zero means 64 MiB.
	MaxHeldBytes int64
	Log          *slog.Logger
}

// Binary reads a binary response body and converts it to MCP content.
//
// maxInline is the embed-or-link threshold: at or below it the bytes
// travel in the transcript, above it they are stored and the model gets a
// link. The threshold applies to images and audio as well, because an
// eight megabyte PNG inlined as base64 costs the caller the same context
// window whatever the media type says.
//
// A nil Content embeds up to maxInline and refuses anything larger, which
// is the behaviour of a deployment with no blob store configured.
func (c *Content) Binary(ctx context.Context, call Call, resp *engine.Response, maxInline int64) ([]mcp.Content, error) {
	if resp.Stream == nil {
		return nil, errors.New("response has no binary body")
	}
	defer func() { _ = resp.Stream.Close() }()

	mediaType := normaliseMediaType(resp.MediaType)
	ceiling := maxInline
	store := c.store(call)
	if store != nil {
		ceiling = c.heldBytes()
	}
	if ceiling < maxInline {
		ceiling = maxInline
	}

	data, err := io.ReadAll(io.LimitReader(resp.Stream, ceiling+1))
	if err != nil {
		return nil, fmt.Errorf("read %s body: %w", mediaType, err)
	}
	if int64(len(data)) > ceiling {
		return nil, fmt.Errorf("upstream returned a %s body larger than %d bytes", mediaType, ceiling)
	}
	if int64(len(data)) <= maxInline {
		return []mcp.Content{inlineContent(mediaType, data)}, nil
	}

	ref, err := store.Put(ctx, Blob{
		Owner:     BlobOwnerFor(call.Principal),
		MediaType: mediaType,
		Name:      blobName(call.Tool.Name, mediaType),
		Data:      data,
	})
	if err != nil {
		return nil, fmt.Errorf("hold %s result: %w", mediaType, err)
	}
	size := int64(len(data))
	return []mcp.Content{&mcp.ResourceLink{
		URI:      ref.URL,
		Name:     blobName(call.Tool.Name, mediaType),
		MIMEType: mediaType,
		Size:     &size,
		Description: fmt.Sprintf("%s result of %s, %d bytes, available until %s",
			mediaType, call.Tool.Name, size, ref.ExpiresAt.UTC().Format(time.RFC3339)),
	}}, nil
}

// store reports where an oversized result would go, or nil when it can go
// nowhere: with no store configured, or with no principal to bind a link
// to. A link nobody owns is a link everybody owns.
func (c *Content) store(call Call) BlobStore {
	if c == nil || c.Blobs == nil {
		return nil
	}
	if BlobOwnerFor(call.Principal).Zero() {
		if c.Log != nil {
			c.Log.Warn("binary tool result has no principal to bind a link to", "tool", call.Tool.Name)
		}
		return nil
	}
	return c.Blobs
}

func (c *Content) heldBytes() int64 {
	if c == nil || c.MaxHeldBytes <= 0 {
		return defaultMaxHeldBytes
	}
	return c.MaxHeldBytes
}

// inlineContent picks the MCP content type that matches the media type.
func inlineContent(mediaType string, data []byte) mcp.Content {
	switch {
	case strings.HasPrefix(mediaType, "image/"):
		return &mcp.ImageContent{Data: data, MIMEType: mediaType}
	case strings.HasPrefix(mediaType, "audio/"):
		return &mcp.AudioContent{Data: data, MIMEType: mediaType}
	default:
		// The URI is derived from the content so two different results are
		// two different resources; a constant here would have every blob in
		// a session claim to be the same one.
		sum := sha256.Sum256(data)
		return &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
			URI:      "supermcp://blob/" + hex.EncodeToString(sum[:8]),
			MIMEType: mediaType,
			Blob:     data,
		}}
	}
}

// normaliseMediaType keeps only a media type that parses. The value comes
// from an upstream header, and it ends up in a Content-Type on our own
// origin, so a malformed one is replaced rather than passed on.
func normaliseMediaType(s string) string {
	parsed, _, err := mime.ParseMediaType(s)
	if err != nil || parsed == "" {
		return "application/octet-stream"
	}
	return parsed
}

// blobName is a display name for a link. It is built from the tool name
// and the media type, never from anything the upstream chose, because it
// reaches a Content-Disposition header.
func blobName(toolName, mediaType string) string {
	name := "result"
	if s := strings.Map(safeNameRune, toolName); s != "" {
		name = s
	}
	if exts, err := mime.ExtensionsByType(mediaType); err == nil && len(exts) > 0 {
		name += exts[0]
	}
	return name
}

func safeNameRune(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		return r
	}
	return -1
}

// --- memory blob store -----------------------------------------------------

// BlobOptions configure a MemoryBlobStore.
type BlobOptions struct {
	// BaseURL is the externally visible origin, without a trailing slash.
	// Empty yields a site-relative URL, which is of little use to a client
	// on another host.
	BaseURL string
	// TTL is how long a blob can be collected for. Defaults to 15m.
	TTL time.Duration
	// MaxEntries bounds the map. Defaults to 256.
	MaxEntries int
	// MaxBytes bounds the map by held size. Defaults to 256 MiB.
	MaxBytes int64
	// Now is the clock, injected by tests.
	Now func() time.Time
}

// MemoryBlobStore holds blobs in this process. It is bounded by entries
// and by bytes and evicts oldest-first, so a run of large results costs a
// fixed amount of memory and some early links that have already expired
// from the model's point of view.
type MemoryBlobStore struct {
	baseURL    string
	ttl        time.Duration
	maxEntries int
	maxBytes   int64
	now        func() time.Time

	mu      sync.Mutex
	order   *list.List
	entries map[string]*list.Element
	bytes   int64
}

type blobEntry struct {
	id   string
	blob Blob
}

// NewMemoryBlobStore builds an in-process blob store.
func NewMemoryBlobStore(o BlobOptions) *MemoryBlobStore {
	if o.TTL <= 0 {
		o.TTL = defaultBlobTTL
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 256
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 256 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &MemoryBlobStore{
		baseURL:    strings.TrimSuffix(o.BaseURL, "/"),
		ttl:        o.TTL,
		maxEntries: o.MaxEntries,
		maxBytes:   o.MaxBytes,
		now:        o.Now,
		order:      list.New(),
		entries:    make(map[string]*list.Element),
	}
}

// Put holds b until its TTL runs out and returns where to collect it.
func (s *MemoryBlobStore) Put(_ context.Context, b Blob) (BlobRef, error) {
	if b.Owner.Zero() {
		return BlobRef{}, errors.New("blob needs an owner")
	}
	id, err := blobID()
	if err != nil {
		return BlobRef{}, err
	}
	b.ExpiresAt = s.now().Add(s.ttl)
	size := int64(len(b.Data))

	s.mu.Lock()
	defer s.mu.Unlock()
	if size > s.maxBytes {
		return BlobRef{}, fmt.Errorf("blob of %d bytes exceeds the %d byte store", size, s.maxBytes)
	}
	s.expireLocked()
	for len(s.entries) >= s.maxEntries || s.bytes+size > s.maxBytes {
		oldest := s.order.Front()
		if oldest == nil {
			break
		}
		s.removeLocked(oldest)
	}
	s.entries[id] = s.order.PushBack(&blobEntry{id: id, blob: b})
	s.bytes += size

	return BlobRef{ID: id, URL: s.baseURL + "/api/v1/blobs/" + id, ExpiresAt: b.ExpiresAt}, nil
}

// Get returns the blob when it exists, has not expired and belongs to
// owner. Anything else is a plain not-found.
func (s *MemoryBlobStore) Get(_ context.Context, id string, owner BlobOwner) (Blob, bool, error) {
	if owner.Zero() {
		return Blob{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.entries[id]
	if !ok {
		return Blob{}, false, nil
	}
	e, _ := el.Value.(*blobEntry)
	if !s.now().Before(e.blob.ExpiresAt) {
		s.removeLocked(el)
		return Blob{}, false, nil
	}
	if !e.blob.Owner.Equal(owner) {
		return Blob{}, false, nil
	}
	return e.blob, true, nil
}

func (s *MemoryBlobStore) expireLocked() {
	now := s.now()
	for el := s.order.Front(); el != nil; {
		next := el.Next()
		e, _ := el.Value.(*blobEntry)
		if now.Before(e.blob.ExpiresAt) {
			// Insertion order is expiry order: everything after this is
			// younger and therefore also unexpired.
			break
		}
		s.removeLocked(el)
		el = next
	}
}

func (s *MemoryBlobStore) removeLocked(el *list.Element) {
	e, _ := el.Value.(*blobEntry)
	s.order.Remove(el)
	delete(s.entries, e.id)
	s.bytes -= int64(len(e.blob.Data))
}

// blobID mints an unguessable identifier. The owner check is what
// authorises a fetch, but an identifier nobody can enumerate means an
// attacker never gets as far as being refused.
func blobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate blob id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
