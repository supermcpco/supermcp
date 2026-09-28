import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  auditExportersCreateMutation,
  auditExportersDeleteMutation,
  auditExportersListOptions,
  auditExportersListQueryKey,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";
import { toast } from "../components/shell/toast";
import { Help, HeadingWithHelp } from "../components/help";

/** Where a copy of the trail is delivered as it is written. */
export const Route = createFileRoute("/_app/settings/audit/shipping")({
  component: AuditShipping,
});

function AuditShipping() {
  const { can } = useSession();
  if (!can("audit:export")) {
    return <Text>You do not have permission to see where the audit trail is shipped.</Text>;
  }
  return <Destinations />;
}

/** Where a copy of the trail is delivered, so a SIEM can hold it too. */
function Destinations() {
  const { can } = useSession();
  const canSee = can("audit:export");
  const canManage = can("org:settings:manage");
  const qc = useQueryClient();
  const list = useQuery({ ...auditExportersListOptions(), enabled: canSee, retry: false });
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: auditExportersListQueryKey() });
  const onError = (e: unknown) => setError(message(e));
  const add = useMutation({
    ...auditExportersCreateMutation(),
    onSuccess: async (_, vars) => {
      toast(`The trail now ships to ${vars.body.url}`);
      setUrl("");
      setSecret("");
      setError(null);
      await refresh();
    },
    onError,
  });
  const remove = useMutation({
    ...auditExportersDeleteMutation(),
    onSuccess: async (_, vars) => {
      const url = list.data?.exporters?.find((e) => e.id === vars.path.id)?.url;
      toast(url ? `Stopped shipping the trail to ${url}` : "Stopped shipping the trail there");
      setError(null);
      await refresh();
    },
    onError,
  });

  if (!canSee) return null;
  const rows = list.data?.exporters ?? [];

  return (
    <section className="grid gap-3">
      <div className="grid gap-1.5">
        <HeadingWithHelp
          heading={
            <Text as="h3" variant="heading3">
              Where it is shipped
            </Text>
          }
          help={
            <Help about="shipping">
              <Text>
                Each batch is POSTed and signed with HMAC-SHA256 in X-Supermcp-Signature, so a receiver can tell a
                delivery from anything else that reaches the same address.
              </Text>
              <Text>Delivery resumes where it stopped.</Text>
            </Help>
          }
        />
        <Text variant="secondary">A copy of the trail, delivered to your SIEM as it is written.</Text>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      <ul className="grid gap-2">
        {rows.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2">
                <Text as="span" bold>
                  {e.url || "(unreadable configuration)"}
                </Text>
                {!e.enabled && <Badge>off</Badge>}
                {e.consecutiveFailures > 0 && <Badge>{e.consecutiveFailures} failures</Badge>}
              </div>
              <Text as="span" variant="secondary">
                delivered up to #{e.cursorSeq}
                {e.lastOkAt ? ` · last succeeded ${new Date(e.lastOkAt).toLocaleString()}` : " · nothing delivered yet"}
                {e.lastError ? ` · ${e.lastError}` : ""}
              </Text>
            </div>
            {canManage && (
              <Button variant="secondary" onClick={() => remove.mutate({ path: { id: e.id } })} disabled={remove.isPending}>
                Stop
              </Button>
            )}
          </li>
        ))}
      </ul>
      {rows.length === 0 && <Text variant="secondary">The trail is not being shipped anywhere.</Text>}
      {canManage && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate({ body: { url, secret, enabled: true } });
          }}
        >
          <label className="grid gap-1">
            <Text as="span">Destination</Text>
            <Input value={url} onChange={(e) => setUrl(e.currentTarget.value)} placeholder="https://siem.example/ingest" required />
          </label>
          <label className="grid gap-1">
            <Text as="span">Signing secret (never shown again)</Text>
            <Input value={secret} onChange={(e) => setSecret(e.currentTarget.value)} minLength={16} required type="password" />
          </label>
          <Button type="submit" disabled={add.isPending}>
            Ship the trail here
          </Button>
        </form>
      )}
    </section>
  );
}

