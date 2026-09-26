import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  getPasswordPolicyOptions,
  getPasswordPolicyQueryKey,
  listSessionsOptions,
  listSessionsQueryKey,
  revokeSessionMutation,
  setPasswordPolicyMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";
import { ChangePassword } from "../components/change-password";

export const Route = createFileRoute("/_app/settings/security")({
  component: Security,
});

function Security() {
  return (
    <div className="grid gap-8">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Security
        </Text>
        <Text>Your password, the devices you are signed in on, and the rules this workspace sets for everyone.</Text>
      </div>
      <ChangePassword onChanged={(qc) => qc.invalidateQueries({ queryKey: listSessionsQueryKey() })} />
      <Sessions />
      <PasswordPolicy />
    </div>
  );
}

function Sessions() {
  const qc = useQueryClient();
  const sessions = useQuery({ ...listSessionsOptions(), retry: false });
  const revoke = useMutation({
    ...revokeSessionMutation(),
    onSuccess: () => qc.invalidateQueries({ queryKey: listSessionsQueryKey() }),
  });

  return (
    <section className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h2" variant="heading3">
          Where you are signed in
        </Text>
        <Text variant="secondary">End a session you do not recognise. The device has to sign in again.</Text>
      </div>
      <ul className="grid gap-2">
        {sessions.data?.sessions?.map((s) => {
          const current = s.id === sessions.data?.current;
          return (
            <li
              key={s.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
            >
              <div className="grid gap-1">
                <div className="flex items-center gap-2">
                  <Text as="span" bold>
                    {describeAgent(s.userAgent)}
                  </Text>
                  {current && <Badge>this device</Badge>}
                  <Badge>{s.authMethod === "sso" ? "single sign-on" : s.authMethod}</Badge>
                </div>
                <Text as="span" variant="secondary">
                  {s.ip ? `${s.ip} · ` : ""}
                  last used {new Date(s.lastSeenAt).toLocaleString()}
                </Text>
              </div>
              {!current && (
                <Button onClick={() => revoke.mutate({ path: { id: s.id } })} disabled={revoke.isPending}>
                  Sign out
                </Button>
              )}
            </li>
          );
        })}
        {sessions.data?.sessions?.length === 0 && (
          <li>
            <Text variant="secondary">No other sessions.</Text>
          </li>
        )}
      </ul>
    </section>
  );
}

interface PolicyForm {
  minLength: number;
  requireClasses: number;
  history: number;
  maxAgeDays: number;
}

const defaultPolicy: PolicyForm = { minLength: 12, requireClasses: 2, history: 5, maxAgeDays: 0 };

function PasswordPolicy() {
  const { can } = useSession();
  const qc = useQueryClient();
  const policy = useQuery({ ...getPasswordPolicyOptions(), retry: false });
  // The form shows what the server said until someone edits it; an edit
  // takes over from there. Copying the query into state in an effect would
  // render twice and fight the next refetch.
  const [edited, setEdited] = useState<PolicyForm | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const form: PolicyForm = edited ?? { ...defaultPolicy, ...policy.data };
  const setForm = (next: PolicyForm) => {
    setEdited(next);
    setSaved(false);
  };

  const save = useMutation({
    ...setPasswordPolicyMutation(),
    onSuccess: async () => {
      setSaved(true);
      setError(null);
      await qc.invalidateQueries({ queryKey: getPasswordPolicyQueryKey() });
    },
    onError: (e) => {
      setSaved(false);
      setError(message(e));
    },
  });

  const editable = can("org:settings:manage");

  return (
    <section className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h2" variant="heading3">
          Password rules for this workspace
        </Text>
        <Text variant="secondary">
          These apply when a password is set. People who sign in through an identity provider never set one here.
        </Text>
      </div>
      <form
        className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ body: form });
        }}
      >
        <div className="flex flex-wrap gap-3">
          <label className="grid gap-1.5">
            <Text as="span">Minimum length</Text>
            <Input
              type="number"
              min={8}
              max={256}
              disabled={!editable}
              value={form.minLength}
              onChange={(e) => setForm({ ...form, minLength: Number(e.target.value) })}
            />
          </label>
          <label className="grid gap-1.5">
            <Text as="span">Character classes</Text>
            <Input
              type="number"
              min={1}
              max={4}
              disabled={!editable}
              value={form.requireClasses}
              onChange={(e) => setForm({ ...form, requireClasses: Number(e.target.value) })}
            />
          </label>
          <label className="grid gap-1.5">
            <Text as="span">Passwords remembered</Text>
            <Input
              type="number"
              min={0}
              max={24}
              disabled={!editable}
              value={form.history}
              onChange={(e) => setForm({ ...form, history: Number(e.target.value) })}
            />
          </label>
          <label className="grid gap-1.5">
            <Text as="span">Expires after (days)</Text>
            <Input
              type="number"
              min={0}
              max={3650}
              disabled={!editable}
              value={form.maxAgeDays}
              onChange={(e) => setForm({ ...form, maxAgeDays: Number(e.target.value) })}
            />
          </label>
        </div>
        <Text variant="secondary">
          Of lower case, upper case, digits and symbols, a password must use this many. Zero days never expires.
        </Text>
        {editable && (
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" disabled={save.isPending}>
              Save rules
            </Button>
            {saved && <Text variant="secondary">Saved.</Text>}
          </div>
        )}
      </form>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}

/** Turns a user agent into something a person recognises. */
function describeAgent(ua?: string): string {
  if (!ua) return "Unknown device";
  const browser = /Firefox\/|Edg\/|Chrome\/|Safari\//.exec(ua)?.[0]?.replace(/[/].*$/, "") ?? "Browser";
  const os = /Mac OS X|Windows|Linux|Android|iPhone|iPad/.exec(ua)?.[0] ?? "";
  const name = browser === "Edg" ? "Edge" : browser;
  return os ? `${name} on ${os.replace("Mac OS X", "macOS")}` : name;
}
