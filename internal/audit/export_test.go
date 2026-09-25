package audit

import "time"

// WithRetry sets how a refused batch is retried, so a test does not wait
// out the production back-off.
func WithRetry(o Options, attempts int, base time.Duration) Options {
	o.retryAttempts = attempts
	o.retryBase = base
	return o
}

// SearchDocument is the expression a search matches, for the test that
// checks the index migration 00027 builds is the one the list reads.
const SearchDocument = searchDocument
