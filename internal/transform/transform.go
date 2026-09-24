// Package transform reshapes an upstream response before it reaches the
// model. JMESPath is the only expression language; a size cap and an
// explicit fail-open/fail-closed switch complete it.
package transform

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jmespath-community/go-jmespath"
)

// MaxExpressionLength bounds expressions so a pathological one cannot be
// stored.
const MaxExpressionLength = 4000

// Spec is a tool's response transform.
type Spec struct {
	JMESPath      string
	MaxBytes      int
	FallbackToRaw *bool // nil = true
}

// Outcome reports what happened.
type Outcome struct {
	Value     any
	Applied   bool
	Truncated bool
	Err       error // non-nil when the expression failed; Value is raw unless Fatal
	Fatal     bool  // FallbackToRaw was false: the call must fail
}

// Compile validates an expression up front (used by the validator and the
// admin API).
func Compile(expr string) (jmespath.JMESPath, error) {
	if len(expr) > MaxExpressionLength {
		return nil, fmt.Errorf("expression exceeds %d characters", MaxExpressionLength)
	}
	return jmespath.Compile(expr)
}

// Apply runs the transform. value must be a decoded JSON value (maps,
// slices, scalars).
func Apply(spec *Spec, value any) Outcome {
	if spec == nil || spec.JMESPath == "" {
		return cap(spec, Outcome{Value: value})
	}
	fallback := spec.FallbackToRaw == nil || *spec.FallbackToRaw
	compiled, err := Compile(spec.JMESPath)
	if err != nil {
		return failed(value, err, fallback)
	}
	out, err := compiled.Search(value)
	if err != nil {
		return failed(value, err, fallback)
	}
	return cap(spec, Outcome{Value: out, Applied: true})
}

func failed(value any, err error, fallback bool) Outcome {
	if fallback {
		return Outcome{Value: value, Err: err}
	}
	return Outcome{Err: err, Fatal: true}
}

// cap enforces MaxBytes by JSON size, replacing an oversized value with a
// marker object rather than a truncated document.
func cap(spec *Spec, o Outcome) Outcome {
	if spec == nil || spec.MaxBytes <= 0 || o.Fatal {
		return o
	}
	b, err := json.Marshal(o.Value)
	if err != nil {
		return o
	}
	if len(b) > spec.MaxBytes {
		o.Value = map[string]any{"_truncated": true, "_bytes": len(b), "_limit": spec.MaxBytes}
		o.Truncated = true
	}
	return o
}

// ErrFatal is wrapped when a fail-closed transform breaks.
var ErrFatal = errors.New("response transform failed and fallbackToRaw is false")
