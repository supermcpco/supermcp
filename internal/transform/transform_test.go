package transform

import (
	"reflect"
	"testing"
)

func TestApply(t *testing.T) {
	in := map[string]any{"results": map[string]any{"news": []any{map[string]any{"t": "a"}}}, "meta": "x"}
	o := Apply(&Spec{JMESPath: "{ news: results.news }"}, in)
	if o.Err != nil || !o.Applied {
		t.Fatalf("unexpected %+v", o)
	}
	want := map[string]any{"news": []any{map[string]any{"t": "a"}}}
	if !reflect.DeepEqual(o.Value, want) {
		t.Fatalf("got %#v", o.Value)
	}

	// No spec: passthrough.
	if o := Apply(nil, in); o.Applied || !reflect.DeepEqual(o.Value, in) {
		t.Fatal("nil spec should pass through")
	}

	// Broken expression, fail open (default).
	o = Apply(&Spec{JMESPath: "results.["}, in)
	if o.Err == nil || o.Fatal || !reflect.DeepEqual(o.Value, in) {
		t.Fatalf("expected raw fallback, got %+v", o)
	}

	// Broken expression, fail closed.
	f := false
	o = Apply(&Spec{JMESPath: "results.[", FallbackToRaw: &f}, in)
	if o.Err == nil || !o.Fatal || o.Value != nil {
		t.Fatalf("expected fatal, got %+v", o)
	}

	// Size cap.
	o = Apply(&Spec{JMESPath: "results", MaxBytes: 10}, in)
	if !o.Truncated {
		t.Fatalf("expected truncation, got %+v", o)
	}
}

func TestCompileBounds(t *testing.T) {
	if _, err := Compile(string(make([]byte, MaxExpressionLength+1))); err == nil {
		t.Fatal("expected length error")
	}
	if _, err := Compile("items[].{id: id}"); err != nil {
		t.Fatal(err)
	}
}
