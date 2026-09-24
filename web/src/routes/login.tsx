import { useState } from "react";
import { createFileRoute, useNavigate, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import { listSsoProvidersOptions, loginMutation, registerMutation } from "../api/@tanstack/react-query.gen";
import { message } from "../lib/errors";
import { useRefreshSession, useSession } from "../lib/session";

export const Route = createFileRoute("/login")({
  component: Login,
  validateSearch: (search: Record<string, unknown>): { sso_error?: string; next?: string } => ({
    ...(typeof search.sso_error === "string" ? { sso_error: search.sso_error } : {}),
    ...(typeof search.next === "string" ? { next: search.next } : {}),
  }),
});

/** What went wrong out at the provider, said in terms a person can act on. */
const ssoErrors: Record<string, string> = {
  domain_not_allowed: "That account's email domain is not allowed to sign in to this workspace.",
  no_account: "There is no account here for that identity, and this provider does not create them.",
  expired: "That sign-in link had expired. Try again.",
  no_verified_email: "The provider did not give us a verified email address for that account.",
  unavailable: "That sign-in method is not available right now.",
  sso_failed: "The sign-in did not complete. Try again, or use your password.",
};

function Login() {
  const navigate = useNavigate();
  const search = useSearch({ from: "/login" });
  const providers = useQuery({ ...listSsoProvidersOptions(), retry: false });
  const refresh = useRefreshSession();
  const { session } = useSession();
  // With no account yet the server tells us registration is open, so the
  // first visit is a sign-up rather than a dead end.
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const openRegistration = session?.registrationOpen ?? false;
  const active = openRegistration && mode === "signup" ? "signup" : "signin";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onDone = async () => {
    await refresh();
    await navigate({ to: "/" });
  };
  const signIn = useMutation({ ...loginMutation(), onSuccess: onDone, onError: (e) => setError(message(e)) });
  const signUp = useMutation({ ...registerMutation(), onSuccess: onDone, onError: (e) => setError(message(e)) });
  const pending = signIn.isPending || signUp.isPending;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (active === "signup") {
      signUp.mutate({ body: { email, password, orgName: orgName || undefined } });
    } else {
      signIn.mutate({ body: { email, password } });
    }
  };

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-10">
      <form onSubmit={submit} className="grid w-full max-w-sm gap-6">
        <div className="grid gap-1.5">
          <Text as="h1" variant="heading2">
            {active === "signup" ? "Create your workspace" : "Sign in"}
          </Text>
          <Text variant="secondary">
            {active === "signup"
              ? "The first account owns the workspace."
              : "Use the email and password for this instance."}
          </Text>
        </div>

        <div className="grid gap-3">
          <label className="grid gap-1.5">
            <Text as="span">Email</Text>
            <Input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="grid gap-1.5">
            <Text as="span">Password</Text>
            <Input
              type="password"
              autoComplete={active === "signup" ? "new-password" : "current-password"}
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            {active === "signup" && (
              <Text as="span" variant="secondary">
                At least 12 characters, mixing letters with digits or symbols.
              </Text>
            )}
          </label>
          {active === "signup" && (
            <label className="grid gap-1.5">
              <Text as="span">Workspace name</Text>
              <Input value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme" />
            </label>
          )}
        </div>

        {(error || search.sso_error) && (
          <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
            <Text>{error ?? ssoErrors[search.sso_error ?? ""] ?? ssoErrors.sso_failed}</Text>
          </div>
        )}

        <Button type="submit" variant="primary" disabled={pending}>
          {pending ? "Working…" : active === "signup" ? "Create workspace" : "Sign in"}
        </Button>

        {(providers.data?.providers?.length ?? 0) > 0 && (
          <div className="grid gap-3">
            <div className="flex items-center gap-3" aria-hidden>
              <span className="h-px flex-1 bg-kumo-line" />
              <Text as="span" variant="secondary">
                or
              </Text>
              <span className="h-px flex-1 bg-kumo-line" />
            </div>
            {providers.data?.providers?.map((p) => (
              <a
                key={p.id}
                href={`/auth/sso/${p.id}/start${search.next ? `?next=${encodeURIComponent(search.next)}` : ""}`}
                className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint"
              >
                <Text as="span">Continue with {p.name}</Text>
              </a>
            ))}
          </div>
        )}

        {openRegistration && (
          <button type="button" className="justify-self-center underline" onClick={() => setMode(active === "signup" ? "signin" : "signup")}>
            <Text as="span" variant="secondary">
              {active === "signup" ? "I already have an account" : "Create a new workspace"}
            </Text>
          </button>
        )}
      </form>
    </div>
  );
}

