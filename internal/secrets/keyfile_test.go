package secrets

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The modes a key file arrives with decide whether the process boots. A
// Kubernetes Secret volume under an fsGroup is 0440, so that must load;
// a file any user can read, or a group can write, must not.
func TestLocalFromEnvKeyFileModes(t *testing.T) {
	material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	cases := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o400, true},
		{0o600, true},
		{0o440, true},
		{0o640, true},
		{0o460, false},
		{0o404, false},
		{0o644, false},
		{0o666, false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "kek")
		if err := os.WriteFile(path, []byte(material+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		get := func(k string) string {
			if k == "ENCRYPTION_KEK_FILE" {
				return path
			}
			return ""
		}
		k, err := LocalFromEnv(get)
		if c.ok {
			if err != nil {
				t.Errorf("mode %o: %v", c.mode, err)
				continue
			}
			if want := "local:file:" + path; k.Ref() != want {
				t.Errorf("mode %o: ref %q, want %q", c.mode, k.Ref(), want)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "world-readable or group-writable") {
			t.Errorf("mode %o: err %v, want a refusal naming the mode", c.mode, err)
		}
	}
}
