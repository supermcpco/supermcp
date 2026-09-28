import { useCallback, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, DeleteResource, Text } from "@cloudflare/kumo";
import type { ConnectorDto, InvocationDto } from "../api";
import {
  catalogGetOptions,
  connectorsCredentialsMutation,
  connectorsDeleteMutation,
  connectorsGetOptions,
  connectorsGetQueryKey,
  connectorsListQueryKey,
  connectorsOauthAuthorizeMutation,
  connectorsOauthRedirectUriOptions,
  invocationsListOptions,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { message, status as httpStatus } from "../lib/errors";
import {
  authLabel,
  authorizationLabel,
  authorizesInBrowser,
  connectorCredentialFields,
  consentResult,
  consentSearch,
  credentialDescriptions,
  filled,
  stillNeeded,
  targetHost,
  type ConsentSearch,
} from "../lib/connector";
import { resyncSummary } from "../lib/resync";
import { CredentialFields } from "../components/credential-fields";
import { ResyncReview } from "../components/resync-review";
import { toast } from "../components/shell/toast";
import { About } from "../components/about";
import { ConsentReturn } from "../components/consent-return";

/**
 * Where a vendor's consent screen sends a person back to: `oauth` is "ok"
 * or the server's code for why the connection was not made.
 */
export const Route = createFileRoute("/_app/connectors/$id/_detail/")({
  validateSearch: (search: Record<string, unknown>): ConsentSearch => consentSearch(search),
  component: Overview,
});

/** How many of the connector's latest calls the page reads. */
const recentWindow = 20;
/** How many of them it lists. */
const recentShown = 5;

function Overview() {
  const { id } = Route.useParams();
  const { signedIn } = useSession();
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), enabled: signedIn, retry: false });

  const c = connector.data;
  // The layout above says why there is no connector; here there is simply
  // nothing to show yet.
  if (!c) return connector.isPending ? <Loading /> : null;

  return (
    <>
      <ConsentNotice id={c.id} />
      {c.catalogOutdated && <CatalogNotice connector={c} />}
      <Status connector={c} />
      <Credentials connector={c} />
      <DangerZone connector={c} />
    </>
  );
}

/** What the vendor's consent screen came back with, if it just did. */
function ConsentNotice({ id }: { id: string }) {
  const search = Route.useSearch();
  const navigate = useNavigate();
  const clear = useCallback(
    () => void navigate({ to: "/connectors/$id", params: { id }, search: {}, replace: true }),
    [navigate, id],
  );
  return <ConsentReturn result={consentResult(search)} onRead={clear} />;
}

/**
 * The server carries a newer adapter than the one this connector came
 * from. What re-syncing would change is shown before anything changes.
 */
function CatalogNotice({ connector }: { connector: ConnectorDto }) {
  const { can } = useSession();
  // Re-syncing rewrites the connector's settings and its tools.
  const canResync = can("connectors:update") && can("tools:update");
  const [comparing, setComparing] = useState(false);

  if (comparing) {
    return (
      <ResyncReview
        connectorId={connector.id}
        onApplied={(data) => {
          setComparing(false);
          toast(`${connector.name} re-synced with the catalog: ${resyncSummary(data.applied)}`);
        }}
        onClose={() => setComparing(false)}
      />
    );
  }
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
      <Text>This server carries a newer version of the catalog adapter this connector was installed from.</Text>
      {canResync && <Button onClick={() => setComparing(true)}>Compare</Button>}
    </div>
  );
}

/** Whether the connector can be called, where it goes, and how its calls went. */
function Status({ connector: c }: { connector: ConnectorDto }) {
  const { signedIn } = useSession();
  // The server finds the connector's own calls; a filtered list is held
  // to the analytics limits, so it can be refused while two others run.
  const recent = useQuery({
    ...invocationsListOptions({ query: { limit: recentWindow, connectorId: c.id } }),
    enabled: signedIn,
    retry: false,
  });

  const fields = connectorCredentialFields(c);
  const needed = stillNeeded(fields, {});
  const host = targetHost(c.transport);
  const authorization = authorizationLabel(c);
  const calls = (recent.data ?? []).slice(0, recentShown);
  const failure = recent.data?.find((i) => i.status !== "success");
  const busy = recent.isError && httpStatus(recent.error) === 429;
  // "…" while the calls are read, a dash when they could not be.
  const unknown = recent.isPending ? "…" : recent.isError ? "–" : undefined;

  return (
    <section aria-labelledby="status-heading" className="grid gap-3">
      <Text as="h2" variant="heading" id="status-heading">
        Status
      </Text>
      <dl className="grid gap-x-6 gap-y-2 rounded-lg px-5 py-4 ring ring-kumo-line sm:grid-cols-[max-content_1fr]">
        <dt>
          <Text as="span" variant="secondary">
            Credentials
          </Text>
        </dt>
        <dd>
          <Text as="span">
            {fields.length === 0
              ? "None needed."
              : needed.length > 0
                ? `Still needed: ${needed.join(", ")}.`
                : `All set: ${fields.map((f) => f.name).join(", ")}.`}
          </Text>
        </dd>
        <dt>
          <Text as="span" variant="secondary">
            Sign-in
          </Text>
        </dt>
        <dd>
          <Text as="span">{authLabel(c.auth)}</Text>
        </dd>
        {authorization && (
          <>
            <dt>
              <Text as="span" variant="secondary">
                Authorization
              </Text>
            </dt>
            <dd>
              <Text as="span">{authorization}</Text>
            </dd>
          </>
        )}
        <dt>
          <Text as="span" variant="secondary">
            Reaches
          </Text>
        </dt>
        <dd>
          <Text as="span">
            {String(c.transport.type ?? "")}
            {host ? ` · ${host}` : ""}
          </Text>
        </dd>
        <dt>
          <Text as="span" variant="secondary">
            Tools
          </Text>
        </dt>
        <dd>
          <Text as="span">{c.toolCount === 1 ? "1 offered" : `${c.toolCount} offered`}</Text>
        </dd>
        <dt>
          <Text as="span" variant="secondary">
            Last call
          </Text>
        </dt>
        <dd>
          <Text as="span">{unknown ?? (calls[0] ? callLine(calls[0]) : "None yet.")}</Text>
        </dd>
        <dt>
          <Text as="span" variant="secondary">
            Last failure
          </Text>
        </dt>
        <dd>
          <Text as="span">
            {unknown ??
              (failure
                ? `${callLine(failure)}${failure.error ? `: ${failure.error}` : ""}`
                : "None among the recent calls.")}
          </Text>
        </dd>
      </dl>
      {busy ? (
        <div role="status" className="flex flex-wrap items-center gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>Another search is still running, try again in a moment.</Text>
          <Button onClick={() => void recent.refetch()}>Try again</Button>
        </div>
      ) : (
        recent.error && (
          <div role="alert">
            <Text>{message(recent.error)}</Text>
          </div>
        )
      )}

      {calls.length > 0 && (
        <div className="grid gap-2">
          <Text as="h3" bold>
            Recent calls
          </Text>
          <table className="w-full">
            <thead className="border-b border-kumo-line text-left">
              <tr>
                <th className="py-2">
                  <Text as="span" variant="secondary">
                    Tool
                  </Text>
                </th>
                <th className="py-2">
                  <Text as="span" variant="secondary">
                    Status
                  </Text>
                </th>
                <th className="py-2">
                  <Text as="span" variant="secondary">
                    Duration
                  </Text>
                </th>
                <th className="py-2">
                  <Text as="span" variant="secondary">
                    When
                  </Text>
                </th>
              </tr>
            </thead>
            <tbody>
              {calls.map((i) => (
                <tr key={i.id} className="border-b border-kumo-line">
                  <td className="py-2 font-mono text-[0.9em]">{i.toolName}</td>
                  <td className="py-2">
                    {i.status === "success" ? <Text as="span">ok</Text> : <Badge>{i.status}</Badge>}
                  </td>
                  <td className="py-2">
                    <Text as="span">{i.durationMs} ms</Text>
                  </td>
                  <td className="py-2">
                    <Text as="span" variant="secondary">
                      {new Date(i.createdAt).toLocaleString()}
                    </Text>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function callLine(i: InvocationDto): string {
  const outcome = i.status === "success" ? "ok" : i.status;
  return `${i.toolName}, ${outcome}, ${new Date(i.createdAt).toLocaleString()}`;
}

/**
 * The values the connector signs in with. They are sealed on the way into
 * the database and never come back out, so a field here only ever sets a
 * value, and an empty one leaves the stored value alone.
 */
function Credentials({ connector: c }: { connector: ConnectorDto }) {
  const qc = useQueryClient();
  const { signedIn, can } = useSession();
  const allowed = can("connectors:auth:update");
  const consent = authorizesInBrowser(c.auth);
  // The adapter's own words on where to find each value, when it has any.
  const adapter = useQuery({
    ...catalogGetOptions({ path: { slug: c.catalogSlug ?? "" } }),
    enabled: signedIn && !!c.catalogSlug,
    retry: false,
  });
  const redirect = useQuery({ ...connectorsOauthRedirectUriOptions(), enabled: signedIn && consent, retry: false });
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    ...connectorsCredentialsMutation(),
    onSuccess: async (updated) => {
      setError(null);
      setValues({});
      qc.setQueryData(connectorsGetQueryKey({ path: { id: c.id } }), updated);
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
      toast(`Credentials saved for ${updated.name}`);
    },
    onError: async (e) => {
      setError(message(e));
      await qc.invalidateQueries({ queryKey: connectorsGetQueryKey({ path: { id: c.id } }) });
    },
  });

  const authorize = useMutation({
    ...connectorsOauthAuthorizeMutation(),
    // The vendor's consent screen is another site; the server sends the
    // browser back to this connector when it is done.
    onSuccess: (start) => window.location.assign(start.authorizationUrl),
    onError: (e) => setError(message(e)),
  });

  const fields = connectorCredentialFields(c, credentialDescriptions(adapter.data));
  if (fields.length === 0 && !consent) return null;
  const typed = filled(values);

  return (
    <section aria-labelledby="credentials-heading" className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h2" variant="heading" id="credentials-heading">
          Credentials
        </Text>
        <Text variant="secondary">Each value is stored encrypted and never shown again.</Text>
      </div>

      {!allowed && <Text>You do not have permission to change this connector's credentials.</Text>}

      {fields.length > 0 && (
        <form
          className="grid gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            save.mutate({ path: { id: c.id }, body: { credentials: typed, expectedVersion: c.version } });
          }}
        >
          <CredentialFields fields={fields} values={values} onChange={setValues} disabled={!allowed || save.isPending} />
          <div>
            <Button
              type="submit"
              variant="primary"
              disabled={!allowed || save.isPending || Object.keys(typed).length === 0}
            >
              {save.isPending ? "Saving…" : "Save credentials"}
            </Button>
          </div>
        </form>
      )}

      {consent && (
        <div className="grid gap-2 rounded-lg px-5 py-4 ring ring-kumo-line">
          <div className="flex flex-wrap items-center gap-1">
            <Text>Set the client ID and secret, then authorize on the vendor&rsquo;s consent screen.</Text>
            <About label="About signing in with OAuth">
              <p>
                Someone approves access on the vendor&rsquo;s consent screen, and the workspace keeps the tokens the
                vendor hands back, encrypted like any other credential.
              </p>
              <p>The vendor has to know the redirect address below before it will send anyone back here.</p>
            </About>
          </div>
          {redirect.data && (
            <Text variant="secondary">
              Register this redirect address with the vendor:{" "}
              <span className="font-mono break-all">{redirect.data.redirectUri}</span>
            </Text>
          )}
          <div>
            <Button
              variant={c.oauthAuthorized ? "secondary" : "primary"}
              disabled={!allowed || authorize.isPending}
              onClick={() => {
                setError(null);
                authorize.mutate({ path: { id: c.id } });
              }}
            >
              {authorize.isPending ? "Opening the consent screen…" : c.oauthAuthorized ? "Re-authorize" : "Authorize"}
            </Button>
          </div>
        </div>
      )}

      {error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}

/** Removing the connector, asked about first and set apart from the rest. */
function DangerZone({ connector: c }: { connector: ConnectorDto }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { can } = useSession();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | undefined>();

  const remove = useMutation({
    ...connectorsDeleteMutation(),
    onSuccess: async () => {
      toast(`${c.name} removed`);
      // Leave first: the page would otherwise read the connector again and
      // find it gone.
      await navigate({ to: "/connectors" });
      qc.removeQueries({ queryKey: connectorsGetQueryKey({ path: { id: c.id } }) });
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });

  if (!can("connectors:delete")) return null;
  return (
    <section aria-labelledby="danger-heading" className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-danger">
      <Text as="h2" variant="heading" id="danger-heading">
        Danger zone
      </Text>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Text>Removing it deletes its tools and credentials for good, and every MCP server stops offering them.</Text>
        <Button
          variant="destructive"
          onClick={() => {
            setError(undefined);
            setOpen(true);
          }}
        >
          Remove
        </Button>
      </div>
      <DeleteResource
        open={open}
        onOpenChange={(next) => !remove.isPending && setOpen(next)}
        resourceType="Connector"
        resourceName={c.name}
        deleteButtonText="Remove connector"
        isDeleting={remove.isPending}
        errorMessage={error}
        onDelete={() => remove.mutate({ path: { id: c.id } })}
      />
    </section>
  );
}
