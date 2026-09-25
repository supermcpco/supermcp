package connector

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRedactConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"auth secrets by key",
			`{"type":"oauth2","clientId":"c","clientSecret":"s","refreshToken":"r","tokenUrl":"https://a/token","grant":"refresh_token"}`,
			`{"type":"oauth2","clientId":"c","clientSecret":"***","refreshToken":"***","tokenUrl":"https://a/token","grant":"refresh_token"}`},
		{"api key value, header name kept",
			`{"type":"apiKey","in":"header","name":"X-Api-Key","value":"{{env.KEY}}"}`,
			`{"type":"apiKey","in":"header","name":"X-Api-Key","value":"***"}`},
		{"basic and bearer",
			`{"username":"u","password":"p","token":"t","prefix":"Bearer","header":"Authorization"}`,
			`{"username":"u","password":"***","token":"***","prefix":"Bearer","header":"Authorization"}`},
		{"empty secret stays empty",
			`{"password":""}`,
			`{"password":""}`},
		{"headers at any depth",
			`{"request":{"headers":{"Authorization":"Basic abc","Accept":"json","X-Auth-Token":"t","Cookie":"c=1"}}}`,
			`{"request":{"headers":{"Authorization":"***","Accept":"json","X-Auth-Token":"***","Cookie":"***"}}}`},
		{"login body password and credentials map",
			`{"request":{"body":{"user":"u","password":"{{auth.password}}"}},"credentials":{"user":"u","pin":1234}}`,
			`{"request":{"body":{"user":"u","password":"***"}},"credentials":{"user":"***","pin":"***"}}`},
		{"secret in a list and a number",
			`{"accessToken":["a","b"],"apiKey":42,"scopes":["read"]}`,
			`{"accessToken":["***","***"],"apiKey":"***","scopes":["read"]}`},
		{"hmac, oauth1 and mtls",
			`{"secret":"h","consumerKey":"ck","consumerSecret":"cs","tokenSecret":"ts","key":"PEM","cert":"CERT"}`,
			`{"secret":"***","consumerKey":"ck","consumerSecret":"***","tokenSecret":"***","key":"***","cert":"CERT"}`},
		{"dsn userinfo",
			`{"type":"database","dsn":"postgres://app:hunter2@db:5432/x?sslmode=disable"}`,
			`{"type":"database","dsn":"postgres://app:***@db:5432/x?sslmode=disable"}`},
		{"url userinfo with a slash in the password",
			`{"baseUrl":"https://u:pa/ss@api.example/v1"}`,
			`{"baseUrl":"https://u:***@api.example/v1"}`},
		{"url without userinfo untouched",
			`{"baseUrl":"https://api.example:8443/v1?region=eu"}`,
			`{"baseUrl":"https://api.example:8443/v1?region=eu"}`},
		{"user without password untouched",
			`{"dsn":"postgres://app@db/x"}`,
			`{"dsn":"postgres://app@db/x"}`},
		{"mysql form",
			`{"dsn":"app:hunter2@tcp(db:3306)/x"}`,
			`{"dsn":"app:***@tcp(db:3306)/x"}`},
		{"keyword connection string",
			`{"dsn":"Server=db;User Id=app;Password=hunter2;Database=x"}`,
			`{"dsn":"Server=db;User Id=app;Password=***;Database=x"}`},
		{"libpq keyword form",
			`{"dsn":"host=db user=app password='hun ter2' dbname=x"}`,
			`{"dsn":"host=db user=app password=*** dbname=x"}`},
		{"secret query parameter",
			`{"baseUrl":"https://api.example/v1?api_key=abc&region=eu&access_token=xyz"}`,
			`{"baseUrl":"https://api.example/v1?api_key=***&region=eu&access_token=***"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var in, want any
			if err := json.Unmarshal([]byte(tc.in), &in); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			got := RedactConfig(in)
			if !reflect.DeepEqual(got, want) {
				g, _ := json.Marshal(got)
				t.Errorf("RedactConfig(%s)\n got %s\nwant %s", tc.in, g, tc.want)
			}
			// The input is left alone.
			var again any
			_ = json.Unmarshal([]byte(tc.in), &again)
			if !reflect.DeepEqual(in, again) {
				t.Errorf("RedactConfig changed its input")
			}
		})
	}
}
