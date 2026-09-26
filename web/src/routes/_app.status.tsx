import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { CheckCircle, Question, WarningCircle } from "@phosphor-icons/react";
import { auditVerifyOptions, catalogListOptions } from "../api/@tanstack/react-query.gen";
import { client } from "../api/client.gen";
import { useSession } from "../lib/session";

export const Route = createFileRoute("/_app/status")({
  component: Status,
});

// Short enough that someone watching this during a deploy sees the
// instance come back without reaching for the reload key, long enough
// that a screen left open overnight is not a load generator.
const every = 15_000;

/** What one line of this screen says, and whether it is good news. */
interface Check {
  ok: boolean | null;
  text: string;
}

/**
 * The version and readiness endpoints are served outside the OpenAPI
 * document, so the generator produces no hook for them. The generated
 * client is still what carries the base URL and the session cookie, which
 * is why the request goes through it rather than through fetch.
 */
function useVersion() {
  return useQuery({
    queryKey: ["instance", "version"],
    queryFn: async () => {
      const { data, response } = await client.get<{ 200: { version: string } }>({ url: "/api/v1/version" });
      if (!response?.ok || !data?.version) throw new Error("the instance did not report a version");
      return data.version;
    },
    refetchInterval: every,
    retry: false,
  });
}

function useReadiness() {
  return useQuery({
    queryKey: ["instance", "readiness"],
    queryFn: async () => {
      const { error, response } = await client.get<{ 200: string }, string>({ url: "/readyz", parseAs: "text" });
      return { ready: !!response?.ok, detail: typeof error === "string" ? error.trim() : "" };
    },
    refetchInterval: every,
    retry: false,
  });
}

function Status() {
  const { signedIn, can } = useSession();
  const version = useVersion();
  const readiness = useReadiness();
  const mayVerify = can("audit:read");
  const chain = useQuery({
    ...auditVerifyOptions(),
    enabled: signedIn && mayVerify,
    retry: false,
    refetchInterval: every,
  });
  const catalog = useQuery({ ...catalogListOptions(), retry: false, refetchInterval: every });

  const checks: Check[] = [
    versionCheck(version.isPending, version.isSuccess, version.data),
    readinessCheck(readiness.isPending, readiness.data),
    chainCheck(mayVerify, chain.isPending, chain.isSuccess, chain.data),
    catalogCheck(catalog.isPending, catalog.isSuccess, catalog.data?.count),
  ];
  const checked = Math.max(version.dataUpdatedAt, readiness.dataUpdatedAt, chain.dataUpdatedAt, catalog.dataUpdatedAt);

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Status
        </Text>
        <Text>
          What this instance can and cannot do at the moment. It rechecks itself every few seconds, so you can leave it
          open through a deploy.
        </Text>
      </div>

      {/* A live region, so a verdict that changes reaches someone who is not watching the screen. */}
      <div role="status">
        <ul className="grid gap-2">
          {checks.map((c) => (
            <Line key={c.text} ok={c.ok}>
              {c.text}
            </Line>
          ))}
        </ul>
      </div>

      {checked > 0 && <Text variant="secondary">Last checked at {new Date(checked).toLocaleTimeString()}.</Text>}
    </div>
  );
}

function versionCheck(pending: boolean, ok: boolean, version?: string): Check {
  if (pending) return { ok: null, text: "Asking this instance which version it is running…" };
  if (!ok) {
    return {
      ok: false,
      text: "This instance did not say which version it is running. If the lines below are failing too, the process is most likely down; if they are not, something in front of it is answering in its place.",
    };
  }
  return { ok: true, text: `This instance is running version ${version}.` };
}

function readinessCheck(pending: boolean, state?: { ready: boolean; detail: string }): Check {
  if (pending || !state) return { ok: null, text: "Checking whether the database is reachable…" };
  if (state.ready) {
    return {
      ok: true,
      text: "The database is reachable and its tables are up to date, so this instance is ready to serve requests.",
    };
  }
  return {
    ok: false,
    text: `This instance is not ready to serve requests${state.detail ? `: ${state.detail}` : ""}. Check that the database is running and that the last deploy finished applying its migrations.`,
  };
}

function chainCheck(
  mayVerify: boolean,
  pending: boolean,
  ok: boolean,
  result?: { valid: boolean; checked: number; brokenAt?: number; explanation?: string },
): Check {
  if (!mayVerify) {
    return {
      ok: null,
      text: "You have not been given permission to read the audit trail, so this page cannot check it for you. Ask an administrator of this workspace for it.",
    };
  }
  if (pending || !result) {
    if (!pending && !ok) {
      return {
        ok: false,
        text: "The audit trail could not be checked just now. Try again in a moment, and if it keeps failing look at whether the database is keeping up.",
      };
    }
    return { ok: null, text: "Checking that the audit trail has not been tampered with…" };
  }
  if (result.valid) {
    return {
      ok: true,
      text: `The audit trail verifies across ${count(result.checked, "event")}, so nothing in it has been removed or altered since it was written.`,
    };
  }
  return {
    ok: false,
    text: `The audit trail stops verifying at entry ${result.brokenAt}. ${result.explanation ?? "An entry does not follow the one before it."} Take a copy of the database before anything else writes to it, and tell whoever runs this instance.`,
  };
}

function catalogCheck(pending: boolean, ok: boolean, adapters?: number): Check {
  if (pending) return { ok: null, text: "Counting the adapters this build ships with…" };
  if (!ok || adapters === undefined) {
    return {
      ok: false,
      text: "The adapter catalog could not be read, so nothing can be installed from it until that is put right.",
    };
  }
  if (adapters === 0) {
    return {
      ok: false,
      text: "The catalog is empty, so there is nothing to install from it. This build was most likely packaged without its adapter files.",
    };
  }
  return { ok: true, text: `The catalog holds ${count(adapters, "adapter")} ready to install.` };
}

/**
 * One thing an operator wants to know, said as a sentence. `ok` is null
 * while the answer is still unknown, because a mark saying all is well
 * before anything has been checked is worse than no mark at all.
 */
function Line({ ok, children }: { ok: boolean | null; children: React.ReactNode }) {
  const Icon = ok === null ? Question : ok ? CheckCircle : WarningCircle;
  return (
    <li className="flex items-start gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
      <span className="h-lh flex shrink-0 items-center">
        <Icon size={18} aria-hidden />
      </span>
      <Text>{children}</Text>
    </li>
  );
}

function count(n: number, noun: string): string {
  return n === 1 ? `1 ${noun}` : `${n} ${noun}s`;
}
