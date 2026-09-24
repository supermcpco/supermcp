package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/invoke"
)

type blobGetInput struct {
	ID string `path:"id" pattern:"^[A-Za-z0-9_-]{16,64}$" doc:"Blob identifier from a tool result link"`
}

// blobGetOutput carries the stored bytes with the media type they were
// stored under.
type blobGetOutput struct {
	ContentType string `header:"Content-Type"`
	// CacheControl is no-store because the bytes belong to one principal:
	// a shared cache holding them would answer the next person from the
	// last person's result.
	CacheControl string `header:"Cache-Control"`
	// ContentDisposition is always attachment. These are upstream bytes
	// with an upstream-chosen media type served from our own origin, so
	// the browser must download them and never render them as a document
	// in this site's context.
	ContentDisposition string `header:"Content-Disposition"`
	Body               []byte
}

// blobRoutes serves the binary tool results that were too large to embed
// in a transcript.
//
// A blob is readable by exactly the principal it was stored for, and by
// nobody else - not by another member of the same organisation, not by an
// administrator. Anyone else gets a 404 rather than a 403: the two answers
// differ in what they disclose, and "this identifier exists but is not
// yours" is a fact about someone else's tool call. The store is given the
// owner and decides, so the check cannot be skipped here.
//
// There is no role check beyond an authenticated principal with an
// organisation. A blob is bound to one identity, which is strictly
// narrower than any role could be; a permission test would refuse nobody a
// role would not already have refused at the tools:invoke that produced
// these bytes. The short TTL is what bounds the gap between a revoked role
// and a link that still answers.
func (d Deps) blobRoutes(api huma.API) {
	if d.Blobs == nil {
		return
	}
	huma.Register(api, huma.Operation{
		OperationID: "blob-get",
		Method:      http.MethodGet,
		Path:        "/api/v1/blobs/{id}",
		Summary:     "Fetch a large binary tool result",
		Tags:        []string{"tools"},
		Security:    []map[string][]string{{"session": {}}, {"apiKey": {}}},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "The stored bytes",
				Content: map[string]*huma.MediaType{
					"application/octet-stream": {Schema: &huma.Schema{Type: huma.TypeString, Format: "binary"}},
				},
			},
		},
	}, func(ctx context.Context, in *blobGetInput) (*blobGetOutput, error) {
		p, ok := authz.From(ctx)
		if !ok || p.OrgID == "" {
			return nil, huma.Error401Unauthorized("authentication required")
		}
		blob, found, err := d.Blobs.Get(ctx, in.ID, invoke.BlobOwnerFor(p))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, huma.Error404NotFound("no such blob")
		}
		return &blobGetOutput{
			ContentType:        blob.MediaType,
			CacheControl:       "private, no-store",
			ContentDisposition: "attachment",
			Body:               blob.Data,
		}, nil
	})
}
