// Package catalog serves the embedded adapter catalog.
package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sync"

	"github.com/supermcpco/supermcp/adapters"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Catalog is the embedded index plus lazily parsed adapters.
type Catalog struct {
	fsys  fs.FS
	Index *adapter.Index
	byID  map[string]adapter.IndexEntry
	mu    sync.Mutex
	cache map[string]*adapter.Adapter
}

// Load parses the embedded index. Adapter documents are parsed on first
// use.
func Load() (*Catalog, error) {
	return LoadFS(adapters.FS)
}

// LoadFS builds a catalog from any filesystem laid out like adapters/.
func LoadFS(fsys fs.FS) (*Catalog, error) {
	raw, err := fs.ReadFile(fsys, "index.gen.json")
	if err != nil {
		return nil, fmt.Errorf("catalog index: %w", err)
	}
	var idx adapter.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("catalog index: %w", err)
	}
	c := &Catalog{fsys: fsys, Index: &idx, byID: map[string]adapter.IndexEntry{}, cache: map[string]*adapter.Adapter{}}
	for _, e := range idx.Adapters {
		c.byID[e.Slug] = e
	}
	return c, nil
}

// Entry returns the index entry for a slug.
func (c *Catalog) Entry(slug string) (adapter.IndexEntry, bool) {
	e, ok := c.byID[slug]
	return e, ok
}

// Get parses and caches the full adapter document.
func (c *Catalog) Get(slug string) (*adapter.Adapter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.cache[slug]; ok {
		return a, nil
	}
	e, ok := c.byID[slug]
	if !ok {
		return nil, fs.ErrNotExist
	}
	data, err := fs.ReadFile(c.fsys, e.Dir+"/"+adapter.FileName)
	if err != nil {
		return nil, err
	}
	a, err := adapter.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", slug, err)
	}
	c.cache[slug] = a
	return a, nil
}

// Raw returns the adapter.yaml bytes.
func (c *Catalog) Raw(slug string) ([]byte, error) {
	e, ok := c.byID[slug]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fs.ReadFile(c.fsys, e.Dir+"/"+adapter.FileName)
}
