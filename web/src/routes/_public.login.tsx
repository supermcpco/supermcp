import { useId, useState } from "react";
import { createFileRoute, useRouter, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Banner, Button, Input, Text } from "@cloudflare/kumo";
import { listSsoProvidersOptions, loginMutation, registerMutation } from "../api/@tanstack/react-query.gen";
import { asSentence, message } from "../lib/errors";
import { useRefreshSession, useSession } from "../lib/session";
import { safeNext } from "../lib/members";

type LoginSearch = { sso_error?: string; saml_error?: string; next?: string };

export const Route = createFileRoute("/_public/login")({
  component: Login,
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    ...(typeof search.sso_error === "string" ? { sso_error: search.sso_error } : {}),
    ...(typeof search.saml_error === "string" ? { saml_error: search.saml_error } : {}),
    ...(typeof search.next === "string" ? { next: search.next } : {}),
  }),
});

/**
 * What went wrong out at the provider, said in terms a person can act on.
 * The server sends one word (internal/httpapi/sso.go and saml.go); the
 * detail stays in its log.
 */
const providerErrors: Record<string, string> = {
  domain_not_allowed: "That account's email domain is not allowed to sign in to this workspace.",
  no_account: "There is no account here for that identity, and this provider does not create them.",
  expired: "That sign-in link had expired. Try again.",
  already_used: "That sign-in had already been used. Start it again from here.",
  no_verified_email: "The provider did not give us a verified email address for that account.",
  assertion_refused: "The identity provider's answer could not be verified. Try again, or ask an administrator to check the provider's settings.",
  unavailable: "That sign-in method is not available right now.",
  sso_failed: "The sign-in did not complete. Try again, or use your password.",
};

function providerError(search: LoginSearch): string | null {
  const reason = search.sso_error ?? search.saml_error;
  if (reason === undefined) return null;
  return providerErrors[reason] ?? providerErrors.sso_failed;
}

function Login() {
  const router = useRouter();
  const search = useSearch({ from: "/_public/login" });
  const refresh = useRefreshSession();
  const { session } = useSession();
  // Sign-in is what most visits are for. Creating a workspace is offered
  // only while the server says it would accept one: on an instance nobody
  // has claimed yet, or one configured for open registration. The session
  // does not say which of the two, so both are worded the same way.
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const registrationOpen = session?.registrationOpen ?? false;
  const active = registrationOpen && mode === "signup" ? "signup" : "signin";

  // `next` brings somebody back to where they were sent from, such as an
  // invitation they have to sign in to accept. Only paths on this site.
  const onDone = async () => {
    await refresh();
    router.history.push(safeNext(search.next));
  };

  return (
    <div className="grid gap-6">
      {active === "signup" ? (
        <SignUp onDone={onDone} />
      ) : (
        <SignIn onDone={onDone} problem={providerError(search)} next={search.next} />
      )}

      {registrationOpen && (
        <div className="grid gap-3">
          <div className="flex items-center gap-3">
            <span className="h-px flex-1 bg-kumo-line" aria-hidden />
            <Text as="span" variant="secondary">
              {active === "signup" ? "Already have an account?" : "New here?"}
            </Text>
            <span className="h-px flex-1 bg-kumo-line" aria-hidden />
          </div>
          <Button variant="secondary" onClick={() => setMode(active === "signup" ? "signin" : "signup")}>
            {active === "signup" ? "Sign in instead" : "Create a workspace"}
          </Button>
        </div>
      )}
    </div>
  );
}

/**
 * The server's refusal, next to the form that caused it and announced when
 * it appears. The form points at it so a screen reader moving through the
 * fields hears why the last attempt failed.
 */
function FormError({ id, text }: { id: string; text: string | null }) {
  if (!text) return null;
  return <Banner id={id} role="alert" variant="error" description={asSentence(text)} />;
}

function SignIn({
  onDone,
  problem,
  next,
}: {
  onDone: () => Promise<void>;
  problem: string | null;
  next: string | undefined;
}) {
  const errorId = useId();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const providers = useQuery({ ...listSsoProvidersOptions(), retry: false });
  const signIn = useMutation({ ...loginMutation(), onSuccess: onDone, onError: (e) => setError(message(e)) });
  // A provider's refusal is shown until the person tries something else.
  const shown = error ?? (signIn.isIdle ? problem : null);

  return (
    <form
      aria-labelledby={`${errorId}-title`}
      aria-describedby={shown ? errorId : undefined}
      className="grid gap-6"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        signIn.mutate({ body: { email, password } });
      }}
    >
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2" id={`${errorId}-title`}>
          Sign in
        </Text>
        <Text variant="secondary">Use the email and password for this instance.</Text>
      </div>

      <div className="grid gap-3">
        <label className="grid gap-1.5">
          <Text as="span">Email</Text>
          <Input
            type="email"
            name="username"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label className="grid gap-1.5">
          <Text as="span">Password</Text>
          <Input
            type="password"
            name="current-password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
      </div>

      <FormError id={errorId} text={shown} />

      <Button type="submit" variant="primary" disabled={signIn.isPending}>
        {signIn.isPending ? "Signing in…" : "Sign in"}
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
              href={`/auth/sso/${p.id}/start${next ? `?next=${encodeURIComponent(next)}` : ""}`}
              className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint"
            >
              <Text as="span">Continue with {p.name}</Text>
            </a>
          ))}
        </div>
      )}
    </form>
  );
}

/**
 * A form of its own, with inputs of its own, so a password manager that
 * fills the sign-in form has nothing here to fill: its password field asks
 * for a new password, and nothing typed into sign-in carries over.
 */
function SignUp({ onDone }: { onDone: () => Promise<void> }) {
  const errorId = useId();
  const hintId = useId();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const signUp = useMutation({ ...registerMutation(), onSuccess: onDone, onError: (e) => setError(message(e)) });

  return (
    <form
      aria-labelledby={`${errorId}-title`}
      aria-describedby={error ? errorId : undefined}
      className="grid gap-6"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        signUp.mutate({ body: { email, password, orgName: orgName || undefined } });
      }}
    >
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2" id={`${errorId}-title`}>
          Create your workspace
        </Text>
        <Text variant="secondary">The account you create here owns the new workspace.</Text>
      </div>

      <div className="grid gap-3">
        <label className="grid gap-1.5">
          <Text as="span">Email</Text>
          <Input
            type="email"
            name="new-username"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label className="grid gap-1.5">
          <Text as="span">Password</Text>
          <Input
            type="password"
            name="new-password"
            autoComplete="new-password"
            required
            minLength={12}
            aria-describedby={hintId}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Text as="span" variant="secondary" id={hintId}>
            At least 12 characters, mixing letters with digits or symbols.
          </Text>
        </label>
        <label className="grid gap-1.5">
          <Text as="span">Workspace name</Text>
          <Input
            name="organization"
            autoComplete="organization"
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
            placeholder="Acme"
          />
        </label>
      </div>

      <FormError id={errorId} text={error} />

      <Button type="submit" variant="primary" disabled={signUp.isPending}>
        {signUp.isPending ? "Creating…" : "Create workspace"}
      </Button>
    </form>
  );
}
