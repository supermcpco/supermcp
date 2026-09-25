import { useEffect, useRef, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  inviteAcceptMutation,
  inviteLookupMutation,
  listSsoProvidersOptions,
  logoutMutation,
  sessionQueryKey,
} from "../api/@tanstack/react-query.gen";
import type { InviteLookupDto } from "../api/types.gen";
import { status } from "../lib/errors";
import { acceptError, inviteInvalid, sameEmail } from "../lib/members";
import { useRefreshSession, useSession } from "../lib/session";
import { Loading } from "../lib/ui";

// Public, like /login: the person opening an invite link may have no
// account yet. The token stays in the page URL only; the API receives it in
// a POST body.
export const Route = createFileRoute("/invite/$token")({
  component: Invite,
});

function Invite() {
  const { token } = Route.useParams();
  const lookup = useMutation({ ...inviteLookupMutation(), retry: false });
  const { mutate } = lookup;
  // Looked up once per token. React runs effects twice in development, and
  // every lookup counts against the caller's budget.
  const asked = useRef<string | null>(null);
  useEffect(() => {
    if (asked.current === token) return;
    asked.current = token;
    mutate({ body: { token } });
  }, [token, mutate]);

  const { loading } = useSession();

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-10">
      <div className="grid w-full max-w-sm gap-6">
        {lookup.isError ? (
          <Invalid unavailable={status(lookup.error) === 501} />
        ) : lookup.data && !loading ? (
          <Found token={token} invite={lookup.data} />
        ) : (
          <>
            <Text as="h1" variant="heading2">
              Invitation
            </Text>
            <Loading />
          </>
        )}
      </div>
    </div>
  );
}

function Invalid({ unavailable }: { unavailable: boolean }) {
  return (
    <div className="grid gap-1.5">
      <Text as="h1" variant="heading2">
        Invitation
      </Text>
      <div role="alert">
        <Text>{unavailable ? "Invitations are not available on this server yet." : inviteInvalid}</Text>
      </div>
      <Text variant="secondary">
        Ask whoever sent it for a new link, or{" "}
        <Link to="/login" search={{}} className="underline">
          sign in
        </Link>{" "}
        if you already have an account.
      </Text>
    </div>
  );
}

function Found({ token, invite }: { token: string; invite: InviteLookupDto }) {
  const { session, signedIn } = useSession();
  const navigate = useNavigate();
  const refresh = useRefreshSession();
  const [error, setError] = useState<{ text: string; signInFirst: boolean } | null>(null);
  const [joined, setJoined] = useState(false);

  const accept = useMutation({
    ...inviteAcceptMutation(),
    onSuccess: async () => {
      setJoined(true);
      await refresh();
      await navigate({ to: "/" });
    },
    onError: (e) => setError(acceptError(e)),
  });

  const intro = (
    <div className="grid gap-1.5">
      <Text as="h1" variant="heading2">
        Join {invite.orgName}
      </Text>
      <Text>
        You have been invited to {invite.orgName} as {article(invite.roleName)} <strong>{invite.roleName}</strong>.
      </Text>
      <Text variant="secondary">
        The invitation is for {invite.email} and works until {new Date(invite.expiresAt).toLocaleString()}.
      </Text>
    </div>
  );

  const alert = error && (
    <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
      <Text>{error.text}</Text>
      {error.signInFirst && (
        <Text>
          {" "}
          <Link to="/login" search={{ next: `/invite/${token}` }} className="underline">
            Sign in to accept
          </Link>
        </Text>
      )}
    </div>
  );

  if (joined) {
    return (
      <>
        {intro}
        <Loading />
      </>
    );
  }

  if (signedIn) {
    if (!sameEmail(session?.user?.email, invite.email)) {
      return (
        <>
          {intro}
          <WrongAccount signedInAs={session?.user?.email ?? ""} invitedEmail={invite.email} />
        </>
      );
    }
    return (
      <>
        {intro}
        {alert}
        <Button variant="primary" disabled={accept.isPending} onClick={() => accept.mutate({ body: { token } })}>
          {accept.isPending ? "Joining…" : `Join ${invite.orgName}`}
        </Button>
      </>
    );
  }

  if (invite.registrationRequired) {
    return (
      <>
        {intro}
        <Register
          email={invite.email}
          pending={accept.isPending}
          onSubmit={(name, password) => {
            setError(null);
            accept.mutate({ body: { token, name: name || undefined, password } });
          }}
        />
        {alert}
        <Providers token={token} />
      </>
    );
  }

  return (
    <>
      {intro}
      {alert}
      <Text>There is already an account for {invite.email}. Sign in with it to accept the invitation.</Text>
      <Link
        to="/login"
        search={{ next: `/invite/${token}` }}
        className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint"
      >
        <Text as="span">Sign in to accept</Text>
      </Link>
      <Providers token={token} />
    </>
  );
}

/** The new account's details: the email is fixed by the invitation. */
function Register({
  email,
  pending,
  onSubmit,
}: {
  email: string;
  pending: boolean;
  onSubmit: (name: string, password: string) => void;
}) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  return (
    <form
      className="grid gap-3"
      aria-label="Create your account"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(name.trim(), password);
      }}
    >
      <Text as="h2" variant="heading3">
        Create your account
      </Text>
      <label className="grid gap-1.5">
        <Text as="span">Email</Text>
        <Input type="email" autoComplete="username" value={email} readOnly />
      </label>
      <label className="grid gap-1.5">
        <Text as="span">Name</Text>
        <Input autoComplete="name" maxLength={200} value={name} onChange={(e) => setName(e.currentTarget.value)} />
      </label>
      <label className="grid gap-1.5">
        <Text as="span">Password</Text>
        <Input
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
          value={password}
          aria-describedby="invite-password-hint"
          onChange={(e) => setPassword(e.currentTarget.value)}
        />
        <Text as="span" variant="secondary" id="invite-password-hint">
          At least 12 characters, mixing letters with digits or symbols.
        </Text>
      </label>
      <Button type="submit" variant="primary" disabled={pending}>
        {pending ? "Working…" : "Create account and join"}
      </Button>
    </form>
  );
}

/** Signed in as somebody else: the invitation cannot move to them. */
function WrongAccount({ signedInAs, invitedEmail }: { signedInAs: string; invitedEmail: string }) {
  const qc = useQueryClient();
  const signOut = useMutation({
    ...logoutMutation(),
    // Stays on this page, which then offers the invited person's way in.
    onSuccess: () => qc.invalidateQueries({ queryKey: sessionQueryKey() }),
  });
  return (
    <div role="alert" className="grid gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
      <Text>
        You are signed in as {signedInAs}, but this invitation is for {invitedEmail}. Only that account can accept it.
      </Text>
      <Text variant="secondary">Sign out, then open the link again as {invitedEmail}.</Text>
      <div>
        <Button onClick={() => signOut.mutate({})} disabled={signOut.isPending}>
          Sign out
        </Button>
      </div>
    </div>
  );
}

/** Single sign-on, returning to this page to accept once signed in. */
function Providers({ token }: { token: string }) {
  const providers = useQuery({ ...listSsoProvidersOptions(), retry: false });
  const list = providers.data?.providers ?? [];
  if (list.length === 0) return null;
  const next = encodeURIComponent(`/invite/${token}`);
  return (
    <div className="grid gap-3">
      <div className="flex items-center gap-3" aria-hidden>
        <span className="h-px flex-1 bg-kumo-line" />
        <Text as="span" variant="secondary">
          or
        </Text>
        <span className="h-px flex-1 bg-kumo-line" />
      </div>
      {list.map((p) => (
        <a
          key={p.id}
          href={`/auth/sso/${p.id}/start?next=${next}`}
          className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint"
        >
          <Text as="span">Continue with {p.name}</Text>
        </a>
      ))}
    </div>
  );
}

function article(word: string) {
  return /^[aeiou]/i.test(word) ? "an" : "a";
}
