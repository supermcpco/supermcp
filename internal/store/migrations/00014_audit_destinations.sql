-- +goose Up
-- +goose StatementBegin

-- A destination is no longer only a signed webhook. The trail can now also
-- go to a syslog collector (RFC 5424 framing, with a CEF payload option),
-- a Splunk HEC endpoint, or an OTLP logs endpoint.
--
-- Nothing about the row changes: what differs between the kinds lives
-- inside the sealed configuration, and the cursor, the filter and the
-- failure counters mean the same thing whatever is at the other end. All
-- that has to move is the constraint that says which kinds exist.
ALTER TABLE audit_exporters DROP CONSTRAINT IF EXISTS audit_exporters_kind_check;
ALTER TABLE audit_exporters ADD CONSTRAINT audit_exporters_kind_check
    CHECK (kind IN ('webhook', 'syslog', 'splunk', 'otlp'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Going back means the kinds that did not exist before cannot stay: a row
-- the old constraint would refuse is removed rather than left behind a
-- constraint that no longer describes it. The events themselves are
-- untouched; what is lost is where a copy of them was being sent, which
-- the administrator who downgrades has to set up again.
DELETE FROM audit_exporters WHERE kind <> 'webhook';
ALTER TABLE audit_exporters DROP CONSTRAINT IF EXISTS audit_exporters_kind_check;
ALTER TABLE audit_exporters ADD CONSTRAINT audit_exporters_kind_check
    CHECK (kind IN ('webhook'));

-- +goose StatementEnd
