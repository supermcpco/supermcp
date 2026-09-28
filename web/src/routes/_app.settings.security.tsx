import { useId, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import {
  getPasswordPolicyOptions,
  getPasswordPolicyQueryKey,
  listSessionsOptions,
  listSessionsQueryKey,
  meUpdateMutation,
  revokeSessionMutation,
  sessionQueryKey,
  setPasswordPolicyMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { asSentence, details, message } from "../lib/errors";
import { ChangePassword } from "../components/change-password";
import { toast } from "../components/shell/toast";
import { LabelledInput } from "../components/labelled-input";

/**
 * Account: who you are here, your password, the devices you are signed in
 * on, and the password rules this workspace sets for everyone. It keeps
 * the address it had when it held only the security parts, so links to it
 * (the account menu's among them) still land here.
 */
export const Route = createFileRoute("/_app/settings/security")({
  component: Account,
});

function Account() {
  return (
    <div className="grid gap-8">
      <div className="grid gap-1.5">
        <Text as="h2" variant="heading">
          Account
        </Text>
        <Text>
          Your name, your password, the devices you are signed in on, and the password rules this workspace sets for
          everyone.
        </Text>
      </div>
      <Profile />
      <ChangePassword level="h3" onChanged={(qc) => qc.invalidateQueries({ queryKey: listSessionsQueryKey() })} />
      <Sessions />
      <PasswordPolicy />
    </div>
  );
}

/** How a session signed in, in words. */
function signInMethod(method?: string, provider?: string): string {
  switch (method) {
    case "password":
      return "Password";
    case "sso":
    case "saml":
      return provider ? `Single sign-on through ${provider}` : "Single sign-on";
    default:
      return "Unknown";
  }
}

/**
 * The person's own email and display name. The email is how they sign in
 * and is not theirs to change here; the name is what other people see in
 * the members list and what the sidebar shows instead of the address.
 */
function Profile() {
  const { session } = useSession();
  const qc = useQueryClient();
  const errorId = useId();
  const saved = session?.user?.name ?? "";
  // What the server holds until somebody types; the typing takes over from
  // there, and a save hands it back to the server's answer.
  const [edited, setEdited] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const name = edited ?? saved;

  const save = useMutation({
    ...meUpdateMutation(),
    onSuccess: (body) => {
      // The answer is the session itself, so the sidebar shows the new
      // name without asking again.
      qc.setQueryData(sessionQueryKey(), body);
      setEdited(null);
      setError(null);
      toast("Name saved");
    },
    onError: (e) => {
      const field = details(e).find((d) => d.location === "body.name")?.message;
      setError(asSentence(field || message(e)));
    },
  });

  const changed = name.trim() !== saved.trim();

  return (
    <section className="grid gap-3" aria-labelledby="profile-heading">
      <div className="grid gap-1">
        <Text as="h3" variant="heading" id="profile-heading">
          Profile
        </Text>
        <Text variant="secondary">Your name is what other people in this workspace see, and what the sidebar shows.</Text>
      </div>
      <div className="grid max-w-3xl gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
        <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-[max-content_1fr]">
          <dt>
            <Text as="span" variant="secondary">
              Email
            </Text>
          </dt>
          <dd>
            <Text as="span">{session?.user?.email}</Text>
          </dd>
          <dt>
            <Text as="span" variant="secondary">
              Signed in with
            </Text>
          </dt>
          <dd>
            <Text as="span">{signInMethod(session?.signIn?.method, session?.signIn?.providerName)}</Text>
          </dd>
        </dl>
        <form
          className="grid gap-2"
          aria-label="Your name"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            save.mutate({ body: { name } });
          }}
        >
          <div className="flex flex-wrap items-end gap-3">
            <LabelledInput
              labelClassName="grid flex-1 gap-1.5"
              label="Name"
              autoComplete="name"
              placeholder="How you want to be shown"
              value={name}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? errorId : undefined}
              onChange={(e) => {
                setEdited(e.currentTarget.value);
                setError(null);
              }}
            />
            <Button type="submit" variant="primary" disabled={save.isPending || !changed}>
              Save name
            </Button>
          </div>
          {error && (
            <div role="alert" id={errorId}>
              <Text>{error}</Text>
            </div>
          )}
        </form>
      </div>
    </section>
  );
}

function Sessions() {
  const qc = useQueryClient();
  const sessions = useQuery({ ...listSessionsOptions(), retry: false });
  const revoke = useMutation({
    ...revokeSessionMutation(),
    onSuccess: async (_, vars) => {
      const s = sessions.data?.sessions?.find((x) => x.id === vars.path.id);
      toast(s ? `${describeAgent(s.userAgent)} signed out` : "Session signed out");
      await qc.invalidateQueries({ queryKey: listSessionsQueryKey() });
    },
    onError: (e) => toast(message(e), { kind: "error" }),
  });

  return (
    <section className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h3" variant="heading">
          Where you are signed in
        </Text>
        <Text variant="secondary">End a session you do not recognise, and that device has to sign in again.</Text>
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
  const [error, setError] = useState<string | null>(null);
  const form: PolicyForm = edited ?? { ...defaultPolicy, ...policy.data };
  const setForm = (next: PolicyForm) => setEdited(next);

  const save = useMutation({
    ...setPasswordPolicyMutation(),
    onSuccess: async () => {
      toast("Password rules saved");
      setError(null);
      await qc.invalidateQueries({ queryKey: getPasswordPolicyQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });

  const editable = can("org:settings:manage");

  return (
    <section className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h3" variant="heading">
          Password rules for this workspace
        </Text>
        <Text variant="secondary">
          They apply whenever a password is set here; people who sign in through your identity provider never set one.
        </Text>
      </div>
      <form
        className="grid max-w-3xl gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ body: form });
        }}
      >
        <div className="flex flex-wrap gap-3">
          <LabelledInput
            label="Minimum length"
            type="number"
            min={8}
            max={256}
            disabled={!editable}
            value={form.minLength}
            onChange={(e) => setForm({ ...form, minLength: Number(e.target.value) })}
          />
          <LabelledInput
            label="Character classes"
            type="number"
            min={1}
            max={4}
            disabled={!editable}
            value={form.requireClasses}
            onChange={(e) => setForm({ ...form, requireClasses: Number(e.target.value) })}
          />
          <LabelledInput
            label="Passwords remembered"
            type="number"
            min={0}
            max={24}
            disabled={!editable}
            value={form.history}
            onChange={(e) => setForm({ ...form, history: Number(e.target.value) })}
          />
          <LabelledInput
            label="Expires after (days)"
            type="number"
            min={0}
            max={3650}
            disabled={!editable}
            value={form.maxAgeDays}
            onChange={(e) => setForm({ ...form, maxAgeDays: Number(e.target.value) })}
          />
        </div>
        <Text variant="secondary">
          Of lower case, upper case, digits and symbols, a password must use this many. Zero days never expires.
        </Text>
        {editable && (
          <div>
            <Button type="submit" variant="primary" disabled={save.isPending}>
              Save rules
            </Button>
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
