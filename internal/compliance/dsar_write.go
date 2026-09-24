package compliance

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WriteJSON writes the export's manifest as JSON. The files' contents are
// not in it: the manifest says what was collected, and the export says
// what it was.
func (ex *Export) WriteJSON(w io.Writer) error { return writeJSON(w, ex) }

// WriteText writes the manifest for a person to read.
func (ex *Export) WriteText(w io.Writer) error {
	p := &printer{w: w}
	p.printf("Subject access export\ngenerated %s\n", ts(ex.GeneratedAt))
	p.printf("\nsubject        %s\n", ex.Subject.Summary())
	p.printf("account since  %s\n", ts(ex.Subject.CreatedAt))
	if ex.Subject.DisabledAt != nil {
		p.printf("disabled       %s\n", stamp(ex.Subject.DisabledAt))
	}

	p.printf("\n%s\nWhat is in the export\n", strings.Repeat("=", 72))
	total := 0
	for _, f := range ex.Files {
		total += f.Records
		p.printf("  %-28s %5d record(s)\n", f.Name, f.Records)
		p.printf("      %s\n", wrap(f.About, 68, "      "))
	}
	p.printf("\n  %d records in %d files\n", total, len(ex.Files))

	p.printf("\n%s\nWhat is deliberately not in it\n", strings.Repeat("=", 72))
	for _, e := range ex.Excluded {
		p.printf("\n  %s\n    %s\n", e.Where, wrap(e.Why, 70, "    "))
	}
	return p.err
}

// readme is written beside the data so the person receiving the export
// can read it without the schema. It is plain text because a zip opened
// on somebody's laptop should not need anything to render it.
const readme = `This archive holds everything this system records about one person.

Each file is JSON: a list of records, one object per line group. The
manifest names every file and says what it holds. manifest.json also
lists what the system holds about this person that is deliberately not
here, and why — passwords and credentials are stored as digests that
cannot be reversed and are not handed over, and records that are as much
somebody else's as this person's are not either.

Times are UTC, written as RFC 3339.

If something here looks wrong, the account id in subject.json is what to
quote when asking about it.
`

// WriteTo writes the export to a directory or to a zip archive, chosen by
// whether the path ends in .zip. A directory is what somebody inspects; a
// zip is what somebody sends.
func (ex *Export) WriteTo(path string) (string, error) {
	files := ex.withManifest()
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return path, ex.writeZip(path, files)
	}
	return path, ex.writeDir(path, files)
}

// withManifest adds the two files that describe the rest. The manifest is
// built last so its counts are of what was actually written.
func (ex *Export) withManifest() []ExportFile {
	var manifest bytes.Buffer
	if err := ex.WriteJSON(&manifest); err != nil {
		// Encoding a struct of strings and ints into a buffer cannot fail
		// for any reason the caller could act on; an empty manifest would
		// be worse than an obvious marker.
		manifest.WriteString(`{"error":"the manifest could not be encoded"}`)
	}
	out := append([]ExportFile(nil), ex.Files...)
	return append(out,
		ExportFile{Name: "manifest.json", About: "what this export contains and what it leaves out",
			Records: len(ex.Files), Bytes: manifest.Bytes()},
		ExportFile{Name: "README.txt", About: "how to read the export", Records: 1, Bytes: []byte(readme)},
	)
}

func (ex *Export) writeDir(dir string, files []ExportFile) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for _, f := range files {
		// The names are this package's own constants, so the join cannot
		// escape the directory; Base is belt and braces against a future
		// caller that builds one from data.
		name := filepath.Join(dir, filepath.Base(f.Name))
		if err := os.WriteFile(name, f.Bytes, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// writeZip writes to a temporary file and renames it into place, so an
// interrupted run never leaves a half-written archive that looks like a
// complete answer to a statutory request.
func (ex *Export) writeZip(path string, files []ExportFile) error {
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	z := zip.NewWriter(f)
	for _, file := range files {
		w, err := z.Create(filepath.Base(file.Name))
		if err != nil {
			return err
		}
		if _, err := w.Write(file.Bytes); err != nil {
			return err
		}
	}
	if err := z.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	done = true
	return nil
}
