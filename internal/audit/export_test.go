package audit

import "time"

// WithRetry sets how a refused batch is retried, so a test does not wait
// out the production back-off.
func WithRetry(o Options, attempts int, base time.Duration) Options {
	o.retryAttempts = attempts
	o.retryBase = base
	return o
}

// ListSearchSQL is the statement List sends for a search, for the test
// that checks how Postgres runs it under the application role.
const ListSearchSQL = listSearchSQL
