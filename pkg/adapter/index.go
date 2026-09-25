package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
)

// IndexEntry is the catalog-facing summary of one adapter. It is small
// enough to embed and serve without parsing the full document.
type IndexEntry struct {
	Slug        string        `json:"slug"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Region      string        `json:"region"`
	Category    string        `json:"category"`
	Icon        string        `json:"icon"`
	DocsURL     string        `json:"docsUrl"`
	Transport   TransportType `json:"transport"`
	Auth        AuthType      `json:"auth"`
	Keyless     bool          `json:"keyless"`
	ToolCount   int           `json:"toolCount"`
	ContentHash string        `json:"contentHash"`
	// PreviousHashes are the content hashes this slug had in earlier
	// catalogs, oldest first. A connector installed from one of them is
	// behind this catalog; a hash in neither list may be from a newer
	// catalog, and re-syncing to this one would move it backwards.
	PreviousHashes []string `json:"previousHashes,omitempty"`
	Priority       int      `json:"priority,omitempty"`
	Featured       bool     `json:"featured,omitempty"`
	SelfHostOnly   bool     `json:"selfHostOnly,omitempty"`
	Dir            string   `json:"dir"`
}

// Index is the generated catalog index.
type Index struct {
	CatalogHash string       `json:"catalogHash"`
	Count       int          `json:"count"`
	Adapters    []IndexEntry `json:"adapters"`
}

// BuildIndex summarises adapters, sorted by region then slug.
func BuildIndex(files []*File) (*Index, error) {
	idx := &Index{}
	h := sha256.New()
	sorted := make([]*File, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Adapter.Metadata.Region != sorted[j].Adapter.Metadata.Region {
			return sorted[i].Adapter.Metadata.Region < sorted[j].Adapter.Metadata.Region
		}
		return sorted[i].Adapter.Metadata.Slug < sorted[j].Adapter.Metadata.Slug
	})
	for _, f := range sorted {
		a := f.Adapter
		ch, err := ContentHash(a)
		if err != nil {
			return nil, err
		}
		keyless := true
		for _, k := range a.Credentials.Keys {
			if a.Credentials.Values[k].Required {
				keyless = false
			}
		}
		e := IndexEntry{
			Slug: a.Metadata.Slug, Name: a.Metadata.Name, Description: a.Metadata.Description,
			Region: a.Metadata.Region, Category: a.Metadata.Category, Icon: a.Metadata.Icon,
			DocsURL: a.Metadata.DocsURL, Transport: a.Transport.Type, Auth: a.Auth.Type,
			Keyless: keyless, ToolCount: len(a.Tools), ContentHash: ch,
			Priority: a.Metadata.Priority,
			Featured: a.Metadata.Featured, SelfHostOnly: a.Metadata.SelfHostOnly, Dir: f.Dir,
		}
		idx.Adapters = append(idx.Adapters, e)
		h.Write([]byte(e.Slug + ":" + ch + "\n"))
	}
	idx.Count = len(idx.Adapters)
	idx.CatalogHash = hex.EncodeToString(h.Sum(nil))[:16]
	return idx, nil
}

// CarryHistory copies each slug's hash history from the index it replaces
// into next: the previous index's history, then its hash when that
// changed. A hash equal to the current one is left out, so an adapter
// that returns to an earlier content does not list itself as behind.
func CarryHistory(prev, next *Index) {
	if prev == nil {
		return
	}
	old := make(map[string]IndexEntry, len(prev.Adapters))
	for _, e := range prev.Adapters {
		old[e.Slug] = e
	}
	for i := range next.Adapters {
		e := &next.Adapters[i]
		p, ok := old[e.Slug]
		if !ok {
			continue
		}
		var hist []string
		seen := map[string]bool{e.ContentHash: true}
		for _, h := range append(append([]string{}, p.PreviousHashes...), p.ContentHash) {
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			hist = append(hist, h)
		}
		e.PreviousHashes = hist
	}
}

// Precedes reports whether hash is one this slug had before the entry's
// current content: a connector installed from it is behind this catalog.
func (e IndexEntry) Precedes(hash string) bool {
	return hash != "" && hash != e.ContentHash && slices.Contains(e.PreviousHashes, hash)
}
