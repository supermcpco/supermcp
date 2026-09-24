package parser

import (
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

const shopEndpoint = "https://shop.example.com/api/graphql"

func TestFromGraphQL(t *testing.T) {
	t.Parallel()

	a, findings, err := FromGraphQL(fixture(t, "shop-introspection.json"), GraphQLOptions{
		Options: Options{ServerURL: shopEndpoint, Slug: "shop"},
	})
	if err != nil {
		t.Fatalf("FromGraphQL: %v", err)
	}
	mustValidate(t, a)
	if HasBlockers(findings) {
		t.Fatalf("unexpected blockers: %v", findings)
	}
	if a.Transport.Type != adapter.TransportGraphQL || a.Transport.BaseURL != shopEndpoint {
		t.Errorf("transport = %+v", a.Transport)
	}

	want := []string{
		"shop_shop", "shop_product", "shop_products", "shop_search", "shop_legacy_products",
		"shop_create_order", "shop_mutation_product",
	}
	if got := toolNames(a); !equal(got, want) {
		t.Fatalf("tools = %v, want %v", got, want)
	}

	t.Run("a field returning an object gets a selection set", func(t *testing.T) {
		// This is the bug the format this replaces shipped: it emitted
		// `query product($id: ID!) { product(id: $id) }`, which no server
		// accepts.
		product := toolNamed(t, a, "shop_product")
		if product.Operation.Kind != "query" {
			t.Errorf("kind = %q", product.Operation.Kind)
		}
		doc := product.Operation.Document
		for _, want := range []string{
			"query product($id: ID!) {",
			"product(id: $id) {",
			"title",
			"price {",
			"amount",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("document is missing %q:\n%s", want, doc)
			}
		}
		// variants takes a required argument, so nothing here can choose
		// one for it.
		if strings.Contains(doc, "variants") {
			t.Errorf("a field needing arguments should not be selected:\n%s", doc)
		}
		if got := nodeJSON(t, product.Operation.Variables); got != `{"id":"{{params.id}}"}` {
			t.Errorf("variables = %s", got)
		}
		if product.Annotations == nil || product.Annotations.ReadOnlyHint == nil || !*product.Annotations.ReadOnlyHint {
			t.Errorf("a query should read only, got %+v", product.Annotations)
		}
	})

	t.Run("arguments carry their real types", func(t *testing.T) {
		products := toolNamed(t, a, "shop_products")
		props := inputMap(t, products)["properties"].(map[string]any)

		first := props["first"].(map[string]any)
		if first["type"] != "integer" || first["default"] != float64(10) {
			t.Errorf("first = %v", first)
		}
		status := props["status"].(map[string]any)
		if !equal(strs(status["enum"].([]any)), []string{"ACTIVE", "DRAFT", "ARCHIVED"}) {
			t.Errorf("an enum argument should carry its values, got %v", status)
		}
		// An input object is an object, not a string: that is the
		// difference between a model that can fill it in and one guessing.
		filter := props["filter"].(map[string]any)
		if filter["type"] != "object" {
			t.Fatalf("filter = %v", filter)
		}
		inner := filter["properties"].(map[string]any)
		if _, ok := inner["title"]; !ok {
			t.Errorf("the input object's fields are missing: %v", inner)
		}
		if !hasFinding(findings, Info, "nests itself") {
			t.Errorf("the recursive input should be reported: %v", findings)
		}

		// The declarations and the variables have to agree, brackets and
		// exclamation marks included.
		doc := products.Operation.Document
		if !strings.Contains(doc, "query products($first: Int, $status: ProductStatus, $filter: ProductFilter)") {
			t.Errorf("declarations are wrong:\n%s", doc)
		}
		// An argument with a default is not one a caller must supply.
		if _, ok := inputMap(t, products)["required"]; ok {
			t.Errorf("nothing here is required: %v", inputMap(t, products))
		}
	})

	t.Run("a nested input object keeps its shape", func(t *testing.T) {
		order := toolNamed(t, a, "shop_create_order")
		input := inputMap(t, order)["properties"].(map[string]any)["input"].(map[string]any)
		items := input["properties"].(map[string]any)["lineItems"].(map[string]any)
		if items["type"] != "array" {
			t.Fatalf("lineItems = %v", items)
		}
		line := items["items"].(map[string]any)
		if !equal(strs(line["required"].([]any)), []string{"variantId"}) {
			t.Errorf("a non-null field with a default is not required: %v", line)
		}
		if !strings.Contains(order.Operation.Document, "mutation createOrder($input: CreateOrderInput!)") {
			t.Errorf("document:\n%s", order.Operation.Document)
		}
	})

	t.Run("a union says so rather than guessing", func(t *testing.T) {
		search := toolNamed(t, a, "shop_search")
		if !strings.Contains(search.Operation.Document, "__typename") {
			t.Errorf("document:\n%s", search.Operation.Document)
		}
		if !hasFinding(findings, Review, "returns the union SearchResult") {
			t.Errorf("findings = %v", findings)
		}
	})

	t.Run("a query and a mutation of one name stay apart", func(t *testing.T) {
		mutation := toolNamed(t, a, "shop_mutation_product")
		if mutation.Operation.Kind != "mutation" {
			t.Errorf("kind = %q", mutation.Operation.Kind)
		}
		if mutation.Annotations != nil && mutation.Annotations.ReadOnlyHint != nil {
			t.Errorf("a mutation is not read-only: %+v", mutation.Annotations)
		}
	})

	t.Run("what was left out is said out loud", func(t *testing.T) {
		if !hasFinding(findings, Info, "the schema has subscriptions") {
			t.Errorf("findings = %v", findings)
		}
		if !hasFinding(findings, Info, "deprecated") {
			t.Errorf("findings = %v", findings)
		}
	})
}

func TestFromGraphQLAuthFromIntrospectionHeaders(t *testing.T) {
	t.Parallel()

	a, findings, err := FromGraphQL(fixture(t, "shop-introspection.json"), GraphQLOptions{
		Options: Options{ServerURL: shopEndpoint, Slug: "shop"},
		Headers: map[string]string{"Authorization": "Bearer shpat_EXAMPLE_NOT_A_REAL_TOKEN"},
	})
	if err != nil {
		t.Fatalf("FromGraphQL: %v", err)
	}
	mustValidate(t, a)
	if a.Auth.Type != adapter.AuthBearer || a.Auth.Token != "{{env."+credToken+"}}" {
		t.Errorf("auth = %+v", a.Auth)
	}
	// The header's own value was a live token; it belongs in a credential,
	// not in the stored connector.
	if body := marshal(t, a); strings.Contains(body, "shpat_") {
		t.Fatal("the introspection header's token was written into the adapter")
	}
	if !hasFinding(findings, Review, "introspected with an Authorization header") {
		t.Errorf("findings = %v", findings)
	}
}

func TestFromGraphQLRefusals(t *testing.T) {
	t.Parallel()

	t.Run("no endpoint is a decision to make", func(t *testing.T) {
		t.Parallel()
		a, findings, err := FromGraphQL(fixture(t, "shop-introspection.json"), GraphQLOptions{})
		if err != nil {
			t.Fatalf("FromGraphQL: %v", err)
		}
		if !hasFinding(findings, Blocker, "supply the endpoint URL") {
			t.Errorf("findings = %v", findings)
		}
		// The tools still fill the preview, so a caller can see what the
		// import would create while they go and find the URL.
		if len(a.Tools) == 0 {
			t.Error("the preview should still list the tools")
		}
	})

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "not an introspection response",
			doc:  `{"openapi":"3.0.0"}`,
			want: "no __schema",
		},
		{
			name: "the endpoint refused",
			doc:  `{"errors":[{"message":"GraphQL introspection is not allowed"}],"data":null}`,
			want: "introspection is not allowed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := FromGraphQL([]byte(tc.doc), GraphQLOptions{Options: Options{ServerURL: shopEndpoint}}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want something about %q", err, tc.want)
			}
		})
	}
}

func TestFromGraphQLIsDeterministic(t *testing.T) {
	t.Parallel()

	doc := fixture(t, "shop-introspection.json")
	opts := GraphQLOptions{Options: Options{ServerURL: shopEndpoint}}
	first, _, err := FromGraphQL(doc, opts)
	if err != nil {
		t.Fatalf("FromGraphQL: %v", err)
	}
	for i := 0; i < 5; i++ {
		next, _, err := FromGraphQL(doc, opts)
		if err != nil {
			t.Fatalf("FromGraphQL: %v", err)
		}
		if a, b := marshal(t, first), marshal(t, next); a != b {
			t.Fatalf("import %d differs:\n%s\n---\n%s", i, a, b)
		}
	}
}
