import { useCallback, useEffect, useId, useRef, useState } from "react";
import { createFileRoute, useRouter, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Banner, Button, Text, buttonVariants, cn } from "@cloudflare/kumo";
import { listSsoProvidersOptions, loginMutation, registerMutation } from "../api/@tanstack/react-query.gen";
import { asSentence, message } from "../lib/errors";
import { isSignedIn, sessionQuery, useRefreshSession } from "../lib/session";
import { nextDestination } from "../lib/members";
import { Loading } from "../lib/ui";
import { LabelledInput } from "../components/labelled-input";
import { OrDivider, PublicCard, headingClass, textButton } from "../components/public-card";

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
  // Asked afresh whenever this page opens, whatever the cache holds:
  // signing out comes here before the ended session is asked about again,
  // and the cached answer would still say somebody is signed in.
  const current = useQuery({ ...sessionQuery(), refetchOnMount: "always" });
  const session = current.data;

  // `next` brings somebody back to where they were sent from, such as an
  // invitation they have to sign in to accept. Only paths on this site;
  // one the server renders rather than this interface (the OAuth consent
  // page) is loaded from the server.
  const left = useRef(false);
  const leave = useCallback(() => {
    if (left.current) return;
    left.current = true;
    const to = nextDestination(search.next, (pathname) => {
      const [, params, found] = router.getMatchedRoutes(pathname);
      return found !== undefined && params["**"] === undefined;
    });
    if (to.load) window.location.assign(to.href);
    else router.history.push(to.href);
  }, [router, search.next]);

  // Somebody already signed in has nothing to do here, and goes on as if
  // they had just signed in. Only on an answer given since this page
  // opened, for the reason above.
  const settled = current.isFetchedAfterMount && !current.isFetching;
  const signedIn = settled && isSignedIn(session);
  useEffect(() => {
    if (signedIn) leave();
  }, [signedIn, leave]);

  const onDone = async () => {
    await refresh();
    leave();
  };

  // Sign-in is what most visits are for. Creating a workspace is offered
  // only while the server says it would accept one: on an instance nobody
  // has claimed yet, or one configured for open registration. The session
  // does not say which of the two, so both are worded the same way.
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const registrationOpen = session?.registrationOpen ?? false;
  const active = registrationOpen && mode === "signup" ? "signup" : "signin";

  // While a signed-in answer is being checked, or acted on, the forms
  // would only be in the way.
  if (isSignedIn(session) && !current.isError) return <Loading />;

  // The way over to the other form sits under the card, as a link: the
  // card itself holds one form and one thing to press.
  const other = registrationOpen && (
    <>
      <Text as="span" variant="secondary">
        {active === "signup" ? "Already have an account?" : "New here?"}
      </Text>
      <button type="button" className={textButton} onClick={() => setMode(active === "signup" ? "signin" : "signup")}>
        {active === "signup" ? "Sign in instead" : "Create a workspace"}
      </button>
    </>
  );

  return (
    <PublicCard after={other}>
      {active === "signup" ? (
        <SignUp onDone={onDone} />
      ) : (
        <SignIn onDone={onDone} problem={providerError(search)} next={search.next} />
      )}
    </PublicCard>
  );
}

/**
 * The server's refusal, at the top of the form that caused it, above the
 * fields a person will correct, and announced when it appears. The form points at it so a screen reader moving through the
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
        <h1 className={headingClass} id={`${errorId}-title`}>
          Sign in to supermcp
        </h1>
        <Text variant="secondary">Use the email and password you have on this instance.</Text>
      </div>

      <FormError id={errorId} text={shown} />

      <div className="grid gap-4">
        <LabelledInput
          label="Email"
          type="email"
          name="username"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <LabelledInput
          label="Password"
          type="password"
          name="current-password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>

      <Button type="submit" variant="primary" size="lg" className="w-full justify-center" disabled={signIn.isPending}>
        {signIn.isPending ? "Signing in…" : "Sign in"}
      </Button>

      {(providers.data?.providers?.length ?? 0) > 0 && (
        <div className="grid gap-3">
          <OrDivider />
          {providers.data?.providers?.map((p) => (
            // A page load, not a move inside the interface: the server
            // sends the browser on to the provider.
            <a
              key={p.id}
              href={`/auth/sso/${p.id}/start${next ? `?next=${encodeURIComponent(next)}` : ""}`}
              className={cn(buttonVariants({ variant: "secondary", size: "lg" }), "w-full justify-center")}
            >
              Continue with {p.name}
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
        <h1 className={headingClass} id={`${errorId}-title`}>
          Create your workspace
        </h1>
        <Text variant="secondary">The account you create here owns the new workspace.</Text>
      </div>

      <FormError id={errorId} text={error} />

      <div className="grid gap-4">
        <LabelledInput
          label="Email"
          type="email"
          name="new-username"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <LabelledInput
          label="Password"
          type="password"
          name="new-password"
          autoComplete="new-password"
          required
          minLength={12}
          aria-describedby={hintId}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        >
          <Text as="span" variant="secondary" size="sm" id={hintId}>
            At least 12 characters, mixing letters with digits or symbols.
          </Text>
        </LabelledInput>
        <LabelledInput
          label="Workspace name"
          name="organization"
          autoComplete="organization"
          value={orgName}
          onChange={(e) => setOrgName(e.target.value)}
          placeholder="Acme"
        />
      </div>

      <Button type="submit" variant="primary" size="lg" className="w-full justify-center" disabled={signUp.isPending}>
        {signUp.isPending ? "Creating…" : "Create workspace"}
      </Button>
    </form>
  );
}
