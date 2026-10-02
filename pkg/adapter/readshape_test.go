package adapter_test

import (
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

func TestReadShapedName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, slug string
		want       bool
	}{
		{"bexio_search_contacts", "bexio", true},
		{"teamleader_get_me", "teamleader", true},
		{"toggl_track_list_projects", "toggl-track", true},
		{"gr_search_trains", "georgian-railway", true},
		{"search_invoices", "", true},
		{"list", "", true},
		{"bexio_create_contact", "bexio", false},
		{"plaid_item_get", "plaid", false},
		{"getaway_book", "", false},
		{"crm_listing_publish", "crm", false},
	}
	for _, tc := range cases {
		if got := adapter.ReadShapedName(tc.name, tc.slug); got != tc.want {
			t.Errorf("ReadShapedName(%q, %q) = %v, want %v", tc.name, tc.slug, got, tc.want)
		}
	}
}
