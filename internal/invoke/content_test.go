package invoke_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/invoke"
)

// countingCloser proves the upstream body is released on every path.
type countingCloser struct {
	io.Reader
	closed int
}

func (c *countingCloser) Close() error {
	c.closed++
	return nil
}

func binaryResponse(mediaType string, data []byte) (*engine.Response, *countingCloser) {
	body := &countingCloser{Reader: bytes.NewReader(data)}
	return &engine.Response{Stream: body, MediaType: mediaType}, body
}

func blobStore(t *testing.T, c *clock) *invoke.MemoryBlobStore {
	t.Helper()
	return invoke.NewMemoryBlobStore(invoke.BlobOptions{
		BaseURL: "https://gateway.test", TTL: 15 * time.Minute, Now: c.Now,
	})
}

func TestBinaryContentMediaTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		mediaType string
		want      string
		wantMIME  string
	}{
		{name: "png is image content", mediaType: "image/png", want: "image", wantMIME: "image/png"},
		{name: "jpeg is image content", mediaType: "image/jpeg", want: "image", wantMIME: "image/jpeg"},
		{name: "mpeg is audio content", mediaType: "audio/mpeg", want: "audio", wantMIME: "audio/mpeg"},
		{name: "pdf is an embedded resource", mediaType: "application/pdf", want: "resource", wantMIME: "application/pdf"},
		{name: "csv is an embedded resource", mediaType: "text/csv", want: "resource", wantMIME: "text/csv"},
		{
			name:      "parameters are dropped but the type survives",
			mediaType: "image/png; charset=binary",
			want:      "image", wantMIME: "image/png",
		},
		{
			name:      "an unparseable media type becomes octet-stream",
			mediaType: "not a media type at all",
			want:      "resource", wantMIME: "application/octet-stream",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			call := callSpec{}.build()
			resp, body := binaryResponse(tc.mediaType, []byte("the bytes"))

			content, err := (&invoke.Content{}).Binary(t.Context(), call, resp, 1<<20)
			if err != nil {
				t.Fatalf("Binary: %v", err)
			}
			if body.closed != 1 {
				t.Fatalf("upstream body closed %d times, want 1", body.closed)
			}
			if len(content) != 1 {
				t.Fatalf("got %d content items, want 1", len(content))
			}
			kind, mimeType := describe(t, content[0])
			if kind != tc.want || mimeType != tc.wantMIME {
				t.Fatalf("got %s/%s, want %s/%s", kind, mimeType, tc.want, tc.wantMIME)
			}
		})
	}
}

func describe(t *testing.T, c mcp.Content) (kind, mimeType string) {
	t.Helper()
	switch v := c.(type) {
	case *mcp.ImageContent:
		return "image", v.MIMEType
	case *mcp.AudioContent:
		return "audio", v.MIMEType
	case *mcp.EmbeddedResource:
		return "resource", v.Resource.MIMEType
	case *mcp.ResourceLink:
		return "link", v.MIMEType
	}
	t.Fatalf("unexpected content %#v", c)
	return "", ""
}

// TestBinaryContentThreshold walks either side of the embed-or-link line,
// with and without somewhere to put the bytes.
func TestBinaryContentThreshold(t *testing.T) {
	t.Parallel()
	const maxInline = 1024
	tests := []struct {
		name     string
		size     int
		withblob bool
		want     string
		wantErr  bool
	}{
		{name: "one byte under the line embeds", size: maxInline - 1, withblob: true, want: "resource"},
		{name: "exactly on the line embeds", size: maxInline, withblob: true, want: "resource"},
		{name: "one byte over the line links", size: maxInline + 1, withblob: true, want: "link"},
		{name: "well over the line links", size: 4 * maxInline, withblob: true, want: "link"},
		{name: "on the line with no store embeds", size: maxInline, want: "resource"},
		{name: "over the line with no store is refused", size: maxInline + 1, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clk := newClock()
			content := &invoke.Content{}
			if tc.withblob {
				content.Blobs = blobStore(t, clk)
			}
			resp, body := binaryResponse("application/pdf", bytes.Repeat([]byte{'x'}, tc.size))

			out, err := content.Binary(t.Context(), callSpec{}.build(), resp, maxInline)
			if body.closed != 1 {
				t.Fatalf("upstream body closed %d times, want 1", body.closed)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("wanted an error, got content")
				}
				return
			}
			if err != nil {
				t.Fatalf("Binary: %v", err)
			}
			if kind, _ := describe(t, out[0]); kind != tc.want {
				t.Fatalf("got %s content, want %s", kind, tc.want)
			}
		})
	}
}

func TestBinaryContentLinkShape(t *testing.T) {
	t.Parallel()
	clk := newClock()
	store := blobStore(t, clk)
	content := &invoke.Content{Blobs: store}
	data := bytes.Repeat([]byte{'x'}, 2048)
	resp, _ := binaryResponse("image/png", data)

	out, err := content.Binary(t.Context(), callSpec{toolName: "export_chart"}.build(), resp, 1024)
	if err != nil {
		t.Fatalf("Binary: %v", err)
	}
	link, ok := out[0].(*mcp.ResourceLink)
	if !ok {
		t.Fatalf("got %#v, want a resource link", out[0])
	}
	if !strings.HasPrefix(link.URI, "https://gateway.test/api/v1/blobs/") {
		t.Fatalf("link points at %q", link.URI)
	}
	if link.MIMEType != "image/png" {
		t.Fatalf("link declares %q", link.MIMEType)
	}
	if link.Size == nil || *link.Size != int64(len(data)) {
		t.Fatalf("link declares size %v, want %d", link.Size, len(data))
	}
	if link.Name != "export_chart.png" {
		t.Fatalf("link is named %q", link.Name)
	}
}

// TestBlobIsRefusedToADifferentPrincipal is the blob half of the tenancy
// argument: a link is bound to the identity that caused it, and everyone
// else is told the same thing they would be told about an identifier that
// never existed.
func TestBlobIsRefusedToADifferentPrincipal(t *testing.T) {
	t.Parallel()
	clk := newClock()
	store := blobStore(t, clk)
	content := &invoke.Content{Blobs: store}

	owner := &authz.Principal{Kind: authz.KindUser, ID: "user-1", OrgID: "org-a"}
	call := callSpec{principalID: "user-1", orgID: "org-a"}.build()
	resp, _ := binaryResponse("application/pdf", bytes.Repeat([]byte{'x'}, 2048))
	out, err := content.Binary(t.Context(), call, resp, 1024)
	if err != nil {
		t.Fatalf("Binary: %v", err)
	}
	link, _ := out[0].(*mcp.ResourceLink)
	id := link.URI[strings.LastIndex(link.URI, "/")+1:]

	tests := []struct {
		name      string
		principal *authz.Principal
		wantFound bool
	}{
		{name: "the principal it was stored for", principal: owner, wantFound: true},
		{
			name:      "another member of the same organisation",
			principal: &authz.Principal{Kind: authz.KindUser, ID: "user-2", OrgID: "org-a"},
		},
		{
			name:      "the same user id in another organisation",
			principal: &authz.Principal{Kind: authz.KindUser, ID: "user-1", OrgID: "org-b"},
		},
		{
			name:      "an api key acting for the same user",
			principal: &authz.Principal{Kind: authz.KindAPIKey, ID: "user-1", OrgID: "org-a", APIKeyID: "key-a"},
		},
		{
			name:      "nobody at all",
			principal: &authz.Principal{Kind: authz.KindAnonymous},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			blob, found, err := store.Get(t.Context(), id, invoke.BlobOwnerFor(tc.principal))
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if found != tc.wantFound {
				t.Fatalf("found=%v, want %v", found, tc.wantFound)
			}
			if tc.wantFound && len(blob.Data) != 2048 {
				t.Fatalf("got %d bytes, want 2048", len(blob.Data))
			}
		})
	}
}

func TestBlobExpires(t *testing.T) {
	t.Parallel()
	clk := newClock()
	store := invoke.NewMemoryBlobStore(invoke.BlobOptions{BaseURL: "https://gateway.test", TTL: time.Minute, Now: clk.Now})
	owner := invoke.BlobOwner{OrgID: "org-a", PrincipalID: "user-1"}

	ref, err := store.Put(t.Context(), invoke.Blob{Owner: owner, MediaType: "application/pdf", Data: []byte("bytes")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.advance(59 * time.Second)
	if _, found, _ := store.Get(t.Context(), ref.ID, owner); !found {
		t.Fatal("blob vanished inside its TTL")
	}
	clk.advance(2 * time.Second)
	if _, found, _ := store.Get(t.Context(), ref.ID, owner); found {
		t.Fatal("blob outlived its TTL")
	}
}

func TestBlobStoreEvictsOldestFirst(t *testing.T) {
	t.Parallel()
	clk := newClock()
	store := invoke.NewMemoryBlobStore(invoke.BlobOptions{
		BaseURL: "https://gateway.test", MaxBytes: 2500, MaxEntries: 100, Now: clk.Now,
	})
	owner := invoke.BlobOwner{OrgID: "org-a", PrincipalID: "user-1"}

	refs := make([]invoke.BlobRef, 3)
	for i := range refs {
		ref, err := store.Put(t.Context(), invoke.Blob{
			Owner: owner, MediaType: "application/pdf", Data: bytes.Repeat([]byte{'x'}, 1000),
		})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		refs[i] = ref
		clk.advance(time.Second)
	}

	if _, found, _ := store.Get(t.Context(), refs[0].ID, owner); found {
		t.Fatal("the oldest blob survived the byte bound")
	}
	for _, ref := range refs[1:] {
		if _, found, _ := store.Get(t.Context(), ref.ID, owner); !found {
			t.Fatalf("blob %s was evicted early", ref.ID)
		}
	}
}

func TestBlobStoreRefusesAnOwnerlessBlob(t *testing.T) {
	t.Parallel()
	store := invoke.NewMemoryBlobStore(invoke.BlobOptions{BaseURL: "https://gateway.test"})
	if _, err := store.Put(t.Context(), invoke.Blob{MediaType: "application/pdf", Data: []byte("x")}); err == nil {
		t.Fatal("Put accepted a blob with no owner")
	}
}

// TestBinaryContentWithoutAPrincipalNeverLinks covers the case where there
// is a store but nobody to bind a link to: the result is refused rather
// than made readable by whoever asks first.
func TestBinaryContentWithoutAPrincipalNeverLinks(t *testing.T) {
	t.Parallel()
	clk := newClock()
	content := &invoke.Content{Blobs: blobStore(t, clk)}
	call := callSpec{}.build()
	call.Principal = nil
	resp, _ := binaryResponse("application/pdf", bytes.Repeat([]byte{'x'}, 2048))

	if _, err := content.Binary(t.Context(), call, resp, 1024); err == nil {
		t.Fatal("an unowned oversized result produced content")
	}
}
