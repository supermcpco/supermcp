// Package reqid words what a client is told about an error the server has
// no answer for. The admin API, SCIM, the MCP endpoint and the OAuth
// endpoints all say the same thing, so an operator can search the log for
// one shape.
package reqid

// Message is all a client learns about an unmapped error. Driver and
// upstream errors name hosts, DSN fragments and SQL; the request id is how
// an operator finds them in the log, where the error is logged once under
// req_id.
func Message(id string) string {
	return "something went wrong; the request id is " + id
}
