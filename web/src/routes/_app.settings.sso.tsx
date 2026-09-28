import { useId, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Checkbox, Text, Textarea } from "@cloudflare/kumo";
import {
  createIdpMutation,
  deleteIdpMutation,
  idpsRevisionsListOptions,
  idpsRevisionsListQueryKey,
  idpsRevisionsRestoreMutation,
  listIdpsOptions,
  listIdpsQueryKey,
  probeIdpMutation,
  updateIdpMfaMutation,
  samlProvidersRevisionsListOptions,
  samlProvidersRevisionsListQueryKey,
  samlProvidersRevisionsRestoreMutation,
} from "../api/@tanstack/react-query.gen";
import { client } from "../api/client.gen";
import type { IdpDto, IdpInput } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";
import { HistoryPanel } from "../components/revisions";
import { toast } from "../components/shell/toast";
import { EmptyState, FormDialog, HeaderWithAction } from "../components/form-dialog";
import { ConfirmDialog } from "../components/confirm-dialog";
import { Help, HeadingWithHelp } from "../components/help";
import { LabelledInput } from "../components/labelled-input";
import { LabelledSelect } from "../components/select";

export const Route = createFileRoute("/_app/settings/sso")({
  component: SingleSignOn,
});

// The SAML operations are reached through the generated fetch client
// rather than through generated hooks: the client is regenerated from the
// OpenAPI document the server produces, and these routes are registered
// by wiring that lives outside this screen. The shapes below are the
// server's DTOs, written out here until the generator has seen them.

interface SamlProvider {
  id: string;
  name: string;
  entityId: string;
  certificatePem: string;
  idpEntityId: string;
  idpSsoUrl: string;
  metadataUrl?: string;
  allowedDomains?: string[];
  jitProvisioning: boolean;
  enabled: boolean;
  acsUrl: string;
  spMetadataUrl: string;
  loginUrl: string;
}

interface SamlInput {
  name: string;
  metadataUrl?: string;
  metadataXml?: string;
  emailAttribute?: string;
  groupsAttribute?: string;
  allowedDomains: string[];
  jitProvisioning: boolean;
  enabled: boolean;
}

/** Unwraps the fetch client's result so react-query sees a rejection. */
async function unwrap<T>(p: Promise<{ data?: unknown; error?: unknown }>): Promise<T> {
  const { data, error } = await p;
  if (error) throw error;
  return data as T;
}

const listSaml = () => unwrap<{ providers: SamlProvider[] }>(client.get({ url: "/api/v1/saml-providers" }));

const createSaml = (body: SamlInput) => unwrap<SamlProvider>(client.post({ url: "/api/v1/saml-providers", body }));

const deleteSaml = (id: string) => unwrap<void>(client.delete({ url: `/api/v1/saml-providers/${id}` }));

const probeSaml = (body: { metadataUrl?: string; metadataXml?: string }) =>
  unwrap<{ idpEntityId: string; idpSsoUrl: string; certificates: number }>(
    client.post({ url: "/api/v1/saml-providers/probe", body }),
  );

const samlQueryKey = ["saml-providers"];

const blankSaml = {
  name: "",
  metadataUrl: "",
  metadataXml: "",
  emailAttribute: "",
  groupsAttribute: "",
  allowedDomains: "",
  jitProvisioning: true,
  enabled: true,
};

// What a new OpenID Connect provider counts as a second factor unless the
// form says otherwise; the server gives the same default to a provider
// created without a rule.
const defaultAmr = "mfa, otp, hwk, sc";

const blank = {
  name: "",
  preset: "entra",
  issuer: "",
  clientId: "",
  clientSecret: "",
  allowedDomains: "",
  groupsClaim: "",
  jitProvisioning: true,
  enabled: true,
  mfaAmr: defaultAmr,
  mfaAcr: "",
};

/** Splits a comma-separated field into its non-empty values. */
function list(value: string): string[] {
  return value
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

type Preset = IdpInput["preset"];

function SingleSignOn() {
  const { signedIn, can } = useSession();
  const qc = useQueryClient();
  const idps = useQuery({ ...listIdpsOptions(), enabled: signedIn && can("idp:manage"), retry: false });
  const [form, setForm] = useState(blank);
  const [error, setError] = useState<string | null>(null);
  const [probe, setProbe] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  // The provider whose second-factor rule is being edited, kept while its
  // dialog closes. Each opening counts, so the dialog starts from the rule
  // as it is now.
  const [edited, setEdited] = useState<IdpDto | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [editRound, setEditRound] = useState(0);
  const [adding, setAdding] = useState(false);
  // The provider whose removal is being asked about; kept while the dialog closes.
  const [removing, setRemoving] = useState<IdpDto | null>(null);
  const [asking, setAsking] = useState(false);
  const canRestore = can("revisions:rollback");

  const create = useMutation({
    ...createIdpMutation(),
    onSuccess: async (_, vars) => {
      toast(`Provider ${vars.body.name || "without a name"} added`);
      setForm(blank);
      setError(null);
      setProbe(null);
      setAdding(false);
      await qc.invalidateQueries({ queryKey: listIdpsQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });
  const remove = useMutation({
    ...deleteIdpMutation(),
    onSuccess: async (_, vars) => {
      const name = idps.data?.providers?.find((p) => p.id === vars.path.id)?.name;
      toast(name ? `Provider ${name} removed` : "Provider removed");
      setAsking(false);
      await qc.invalidateQueries({ queryKey: listIdpsQueryKey() });
    },
  });
  const check = useMutation({
    ...probeIdpMutation(),
    onSuccess: (doc, vars) => {
      toast(`Issuer ${vars.body.issuer} answered`);
      setProbe(`Found ${doc.authorizationEndpoint ?? "an authorization endpoint"}`);
      setError(null);
    },
    onError: (e) => {
      setProbe(null);
      setError(message(e));
    },
  });

  if (!can("idp:manage")) {
    return (
      <Text>You do not have permission to manage how people sign in. Ask an administrator of this workspace.</Text>
    );
  }

  // The presets come back as a loose map from the API; this is the shape
  // the form actually uses.
  const presets = (idps.data?.presets ?? []) as Array<{ id: string; label: string; needsIssuer?: boolean }>;
  const chosen = presets.find((p) => p.id === form.preset);
  const needsIssuer = chosen?.needsIssuer !== false && form.preset !== "github";

  const addOidc = (
    <Button variant="primary" onClick={() => setAdding(true)}>
      New OpenID Connect provider
    </Button>
  );

  return (
    <div className="grid gap-8">
      <div className="grid gap-1.5">
        <Text as="h2" variant="heading">
          Single sign-on
        </Text>
        <Text>People sign in to this workspace with your own identity provider.</Text>
      </div>

      <section className="grid gap-3" aria-labelledby="oidc-heading">
        <HeaderWithAction action={addOidc}>
          <Text as="h3" variant="heading" id="oidc-heading">
            Providers
          </Text>
          <Text variant="secondary">OpenID Connect providers, such as Entra ID, Okta or Google.</Text>
        </HeaderWithAction>
        <ul className="grid gap-2">
          {idps.data?.providers?.map((p) => (
            <li key={p.id} className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="grid gap-1">
                  <div className="flex items-center gap-2">
                    <Text as="span" bold>
                      {p.name}
                    </Text>
                    <Badge>{p.preset}</Badge>
                    {!p.enabled && <Badge>off</Badge>}
                    {p.jitProvisioning && <Badge>creates accounts</Badge>}
                  </div>
                  <Text as="span" variant="secondary">
                    {p.issuer || "no issuer"}
                    {p.allowedDomains?.length ? ` · ${p.allowedDomains.join(", ")} only` : " · any email domain"}
                  </Text>
                  <Text as="span" variant="secondary">
                    {describeRule(p)}
                  </Text>
                </div>
                <div className="flex flex-wrap gap-2">
                  {p.protocol === "oidc" && (
                    <Button
                      onClick={() => {
                        setEdited(p);
                        setEditRound((n) => n + 1);
                        setEditOpen(true);
                      }}
                      aria-label={`Edit the second-factor rule of ${p.name}`}
                    >
                      Edit
                    </Button>
                  )}
                  <Button
                    onClick={() => setHistory((current) => (current === p.id ? null : p.id))}
                    aria-expanded={history === p.id}
                    aria-label={`${history === p.id ? "Hide the history of" : "History of"} ${p.name}`}
                  >
                    {history === p.id ? "Hide history" : "History"}
                  </Button>
                  <Button
                    variant="secondary-destructive"
                    onClick={() => {
                      remove.reset();
                      setRemoving(p);
                      setAsking(true);
                    }}
                    aria-label={`Remove ${p.name}`}
                  >
                    Remove
                  </Button>
                </div>
              </div>
              {history === p.id && <ProviderHistory id={p.id} name={p.name} canRestore={canRestore} />}
            </li>
          ))}
        </ul>
        {idps.data?.providers?.length === 0 && <EmptyState>No providers yet.</EmptyState>}
      </section>

      {edited && (
        <SecondFactorEditor
          key={editRound}
          open={editOpen}
          onOpenChange={setEditOpen}
          provider={edited}
          onSaved={() => setEditOpen(false)}
        />
      )}

      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        resourceType="Provider"
        resourceName={removing?.name ?? ""}
        confirmLabel="Remove provider"
        pending={remove.isPending}
        error={remove.error ? message(remove.error) : null}
        onConfirm={() => removing && remove.mutate({ path: { id: removing.id } })}
      />

      <FormDialog
        open={adding}
        onOpenChange={(open) => {
          setAdding(open);
          setError(null);
        }}
        title="Add a provider"
        description={
          <>
            Register <span className="font-mono">{idps.data?.redirectUri ?? ""}</span> with your provider as the
            application&apos;s redirect URI.
          </>
        }
        submitLabel="Add provider"
        pending={create.isPending}
        canSubmit={form.clientId !== ""}
        error={error}
        size="xl"
        onSubmit={() =>
          create.mutate({
            body: {
              name: form.name,
              preset: form.preset as Preset,
              issuer: form.issuer,
              clientId: form.clientId,
              clientSecret: form.clientSecret,
              groupsClaim: form.groupsClaim,
              jitProvisioning: form.jitProvisioning,
              enabled: form.enabled,
              allowedDomains: list(form.allowedDomains),
              // GitHub issues no ID token, so it has no rule to send.
              ...(form.preset !== "github" && { mfa: { amr: list(form.mfaAmr), acr: list(form.mfaAcr) } }),
            },
          })
        }
      >
        <div className="flex flex-wrap gap-3">
          <LabelledSelect
            label="Provider"
            value={form.preset}
            onChange={(preset) => setForm({ ...form, preset })}
            options={presets.map((p) => ({ value: p.id, label: p.label }))}
          />
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="Company sign-in"
          />
        </div>

        {needsIssuer && (
          <LabelledInput
            label="Issuer URL"
            required
            value={form.issuer}
            onChange={(e) => setForm({ ...form, issuer: e.target.value })}
            placeholder="https://login.microsoftonline.com/<tenant>/v2.0"
          >
            <div className="flex items-center gap-3">
              <Button
                type="button"
                disabled={!form.issuer || check.isPending}
                onClick={() => check.mutate({ body: { issuer: form.issuer } })}
              >
                Test this issuer
              </Button>
              {probe && <Text variant="secondary">{probe}</Text>}
            </div>
          </LabelledInput>
        )}

        <div className="flex flex-wrap gap-3">
          <LabelledInput labelClassName="grid flex-1 gap-1.5" label="Client ID" required value={form.clientId} onChange={(e) => setForm({ ...form, clientId: e.target.value })} />
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Client secret"
            type="password"
            value={form.clientSecret}
            onChange={(e) => setForm({ ...form, clientSecret: e.target.value })}
          />
        </div>

        <div className="flex flex-wrap gap-3">
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Allowed email domains"
            value={form.allowedDomains}
            onChange={(e) => setForm({ ...form, allowedDomains: e.target.value })}
            placeholder="example.com, example.co.uk"
          />
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Groups claim"
            value={form.groupsClaim}
            onChange={(e) => setForm({ ...form, groupsClaim: e.target.value })}
            placeholder="groups"
          />
        </div>
        <div className="flex items-center gap-1">
          <Text variant="secondary">Leave the domains empty to accept anyone the provider admits.</Text>
          <Help about="the groups claim">
            <Text>
              A group named in that claim grants whatever roles are bound to it here, for as long as the provider keeps
              naming it at sign-in.
            </Text>
          </Help>
        </div>

        {form.preset !== "github" && (
          <SecondFactorFields
            amr={form.mfaAmr}
            acr={form.mfaAcr}
            onChange={(amr, acr) => setForm({ ...form, mfaAmr: amr, mfaAcr: acr })}
          />
        )}

        <div className="flex flex-wrap items-center gap-4">
          <Checkbox
            label="Create an account on first sign-in"
            checked={form.jitProvisioning}
            onCheckedChange={(jitProvisioning) => setForm({ ...form, jitProvisioning })}
          />
          <Checkbox
            label="Offer it on the sign-in page"
            checked={form.enabled}
            onCheckedChange={(enabled) => setForm({ ...form, enabled })}
          />
        </div>
      </FormDialog>

      <SamlSection />

      <section className="grid gap-3">
        <Text as="h3" variant="heading">
          Redirect URI
        </Text>
        <Text variant="secondary">Register this with your provider as the application's redirect URI.</Text>
        <code className="overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]">
          {idps.data?.redirectUri ?? ""}
        </code>
      </section>

      <section className="grid gap-3">
        <HeadingWithHelp
          heading={
            <Text as="h3" variant="heading">
              Provisioning
            </Text>
          }
          help={
            <Help about="provisioning">
              <Text>
                Authenticate your provider&rsquo;s SCIM 2.0 connector with an API key created for SCIM provisioning.
                That key can create and deactivate people and nothing else.
              </Text>
              <Text>Deactivating a person there ends their sessions and revokes their keys here.</Text>
            </Help>
          }
        />
        <Text variant="secondary">Point your provider&rsquo;s SCIM 2.0 connector at this address.</Text>
        <code className="overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]">
          {new URL("/scim/v2", window.location.origin).toString()}
        </code>
      </section>
    </div>
  );
}

/** Says in words what a provider counts as a second factor. */
function describeRule(p: IdpDto): string {
  if (p.protocol !== "oidc") return "Second factor: never reported (no ID token)";
  const amr = p.mfa.amr ?? [];
  const acr = p.mfa.acr ?? [];
  if (amr.length === 0 && acr.length === 0) return "Second factor: no rule, so no sign-in counts as one";
  const parts = [];
  if (amr.length) parts.push(`amr ${amr.join(", ")}`);
  if (acr.length) parts.push(`acr ${acr.join(", ")}`);
  return `Second factor: ${parts.join(" or ")}`;
}

/** The two fields of a second-factor rule, as comma-separated lists. */
function SecondFactorFields({
  amr,
  acr,
  onChange,
}: {
  amr: string;
  acr: string;
  onChange: (amr: string, acr: string) => void;
}) {
  return (
    <div className="grid gap-1.5">
      <div className="flex flex-wrap gap-3">
        <LabelledInput labelClassName="grid flex-1 gap-1.5" label="Second factor: amr values that count" value={amr} onChange={(e) => onChange(e.target.value, acr)} placeholder={defaultAmr} />
        <LabelledInput labelClassName="grid flex-1 gap-1.5" label="Second factor: acr values that count" value={acr} onChange={(e) => onChange(amr, e.target.value)} placeholder="phr" />
      </div>
      <Text variant="secondary">
        A sign-in has a second factor when the provider's signed ID token names one of these amr values, or its acr is
        one of these. Leave both empty and no sign-in through this provider counts as having one. Google sends
        neither.
      </Text>
    </div>
  );
}

/**
 * Changes one provider's second-factor rule, through the route that changes
 * nothing else: a copy of the whole provider sent back from the list read
 * earlier would undo whatever an administrator changed since.
 */
function SecondFactorEditor({
  open,
  onOpenChange,
  provider: p,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  provider: IdpDto;
  onSaved: () => void;
}) {
  const qc = useQueryClient();
  const [amr, setAmr] = useState((p.mfa.amr ?? []).join(", "));
  const [acr, setAcr] = useState((p.mfa.acr ?? []).join(", "));
  const save = useMutation({
    ...updateIdpMfaMutation(),
    onSuccess: async () => {
      toast(`Second-factor rule of ${p.name} saved`);
      await qc.invalidateQueries({ queryKey: listIdpsQueryKey() });
      onSaved();
    },
  });
  return (
    <FormDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Edit the second-factor rule of ${p.name}`}
      description="It applies from the next sign-in."
      submitLabel="Save second-factor rule"
      pending={save.isPending}
      error={save.error ? message(save.error) : null}
      onSubmit={() => save.mutate({ path: { id: p.id }, body: { amr: list(amr), acr: list(acr) } })}
    >
      <SecondFactorFields
        amr={amr}
        acr={acr}
        onChange={(a, c) => {
          setAmr(a);
          setAcr(c);
        }}
      />
    </FormDialog>
  );
}

/**
 * The SAML half of the screen. It is a separate component because the two
 * protocols share nothing but the heading: SAML has no client secret, and
 * an administrator has to copy three of our URLs and our certificate into
 * their identity provider before anything works.
 */
function SamlSection() {
  const qc = useQueryClient();
  const xmlLabelId = useId();
  const { can } = useSession();
  const canRestore = can("revisions:rollback");
  const [history, setHistory] = useState<string | null>(null);
  const providers = useQuery({ queryKey: samlQueryKey, queryFn: listSaml, retry: false });
  const [form, setForm] = useState(blankSaml);
  const [error, setError] = useState<string | null>(null);
  const [found, setFound] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  // The provider whose removal is being asked about; kept while the dialog closes.
  const [removing, setRemoving] = useState<SamlProvider | null>(null);
  const [asking, setAsking] = useState(false);

  const create = useMutation({
    mutationFn: createSaml,
    onSuccess: async (created) => {
      toast(`SAML provider ${created.name} added`);
      setForm(blankSaml);
      setError(null);
      setFound(null);
      setAdding(false);
      await qc.invalidateQueries({ queryKey: samlQueryKey });
    },
    onError: (e) => setError(message(e)),
  });
  const remove = useMutation({
    mutationFn: deleteSaml,
    onSuccess: async (_, id) => {
      const name = providers.data?.providers?.find((p) => p.id === id)?.name;
      toast(name ? `SAML provider ${name} removed` : "SAML provider removed");
      setAsking(false);
      await qc.invalidateQueries({ queryKey: samlQueryKey });
    },
  });
  const check = useMutation({
    mutationFn: probeSaml,
    onSuccess: (doc) => {
      toast(`Metadata for ${doc.idpEntityId} read`);
      setFound(`Found ${doc.idpEntityId} with ${doc.certificates} signing certificate(s).`);
      setError(null);
    },
    onError: (e) => {
      setFound(null);
      setError(message(e));
    },
  });

  const described = form.metadataUrl.trim() !== "" || form.metadataXml.trim() !== "";
  const addSaml = (
    <Button variant="primary" onClick={() => setAdding(true)}>
      New SAML provider
    </Button>
  );

  return (
    <section className="grid gap-3" aria-labelledby="saml-heading">
      <HeaderWithAction action={addSaml}>
        <HeadingWithHelp
          heading={
            <Text as="h3" variant="heading" id="saml-heading">
              SAML 2.0
            </Text>
          }
          help={
            <Help about="SAML 2.0">
              <Text>Add the provider, then give your identity provider the addresses it shows you.</Text>
              <Text>
                Each provider gets its own signing key, so one workspace&rsquo;s federation cannot be used to sign in to
                another.
              </Text>
            </Help>
          }
        />
        <Text variant="secondary">For providers that speak SAML rather than OpenID Connect.</Text>
      </HeaderWithAction>

      <ul className="grid gap-2">
        {providers.data?.providers?.map((p) => (
          <li key={p.id} className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="grid gap-1">
                <div className="flex items-center gap-2">
                  <Text as="span" bold>
                    {p.name}
                  </Text>
                  <Badge>saml</Badge>
                  {!p.enabled && <Badge>off</Badge>}
                  {p.jitProvisioning && <Badge>creates accounts</Badge>}
                </div>
                <Text as="span" variant="secondary">
                  {p.idpEntityId}
                  {p.allowedDomains?.length ? ` · ${p.allowedDomains.join(", ")} only` : " · any email domain"}
                </Text>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => setHistory((current) => (current === p.id ? null : p.id))}
                  aria-expanded={history === p.id}
                  aria-label={`${history === p.id ? "Hide the history of" : "History of"} ${p.name}`}
                >
                  {history === p.id ? "Hide history" : "History"}
                </Button>
                <Button
                  variant="secondary-destructive"
                  onClick={() => {
                    remove.reset();
                    setRemoving(p);
                    setAsking(true);
                  }}
                  aria-label={`Remove ${p.name}`}
                >
                  Remove
                </Button>
              </div>
            </div>
            {history === p.id && <SamlHistory id={p.id} name={p.name} canRestore={canRestore} />}
            <dl className="grid gap-1.5 text-[0.9em]">
              {[
                ["Entity ID (audience)", p.entityId],
                ["Assertion consumer service (ACS)", p.acsUrl],
                ["Our metadata", p.spMetadataUrl],
                ["Sign-in link", p.loginUrl],
              ].map(([label, value]) => (
                <div key={label} className="grid gap-0.5">
                  <dt>
                    <Text as="span" variant="secondary">
                      {label}
                    </Text>
                  </dt>
                  <dd>
                    <code className="block overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono">{value}</code>
                  </dd>
                </div>
              ))}
            </dl>
            <details>
              <summary>
                <Text as="span">Signing certificate</Text>
              </summary>
              <pre className="mt-2 overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.8em]">
                {p.certificatePem}
              </pre>
            </details>
          </li>
        ))}
      </ul>
      {providers.data?.providers?.length === 0 && <EmptyState>No SAML providers yet.</EmptyState>}

      <FormDialog
        open={adding}
        onOpenChange={(open) => {
          setAdding(open);
          setError(null);
        }}
        title="Add a SAML provider"
        submitLabel="Add SAML provider"
        pending={create.isPending}
        canSubmit={described}
        error={error}
        size="xl"
        onSubmit={() =>
          create.mutate({
            name: form.name,
            metadataUrl: form.metadataUrl.trim() || undefined,
            metadataXml: form.metadataXml.trim() || undefined,
            emailAttribute: form.emailAttribute.trim() || undefined,
            groupsAttribute: form.groupsAttribute.trim() || undefined,
            jitProvisioning: form.jitProvisioning,
            enabled: form.enabled,
            allowedDomains: form.allowedDomains
              .split(",")
              .map((d) => d.trim())
              .filter(Boolean),
          })
        }
      >
        <LabelledInput
          label="Name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="Company SAML"
        />

        <LabelledInput
          label="Identity provider metadata URL"
          value={form.metadataUrl}
          onChange={(e) => setForm({ ...form, metadataUrl: e.target.value })}
          placeholder="https://login.example.com/app/exk1234/sso/saml/metadata"
        />

        <label className="grid gap-1.5">
          <Text as="span" id={xmlLabelId}>
            …or paste the metadata XML
          </Text>
          <Textarea
            aria-labelledby={xmlLabelId}
            className="min-h-32 font-mono text-[0.85em]"
            value={form.metadataXml}
            onChange={(e) => setForm({ ...form, metadataXml: e.target.value })}
            placeholder="<EntityDescriptor …>"
          />
        </label>
        <div className="flex items-center gap-3">
          <Button
            type="button"
            disabled={!described || check.isPending}
            onClick={() =>
              check.mutate({
                metadataUrl: form.metadataUrl.trim() || undefined,
                metadataXml: form.metadataXml.trim() || undefined,
              })
            }
          >
            Test this metadata
          </Button>
          {found && <Text variant="secondary">{found}</Text>}
        </div>

        <div className="flex flex-wrap gap-3">
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Allowed email domains"
            value={form.allowedDomains}
            onChange={(e) => setForm({ ...form, allowedDomains: e.target.value })}
            placeholder="example.com, example.co.uk"
          />
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Email attribute"
            value={form.emailAttribute}
            onChange={(e) => setForm({ ...form, emailAttribute: e.target.value })}
            placeholder="leave empty to try the usual names"
          />
          <LabelledInput
            labelClassName="grid flex-1 gap-1.5"
            label="Groups attribute"
            value={form.groupsAttribute}
            onChange={(e) => setForm({ ...form, groupsAttribute: e.target.value })}
            placeholder="groups"
          />
        </div>
        <div className="flex items-center gap-1">
          <Text variant="secondary">Leave the attributes empty to read the usual names.</Text>
          <Help about="the groups attribute">
            <Text>A group named in that attribute grants whatever roles are bound to it here.</Text>
            <Text>Naming an attribute means that one only: nothing else is read in its place.</Text>
          </Help>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          <Checkbox
            label="Create an account on first sign-in"
            checked={form.jitProvisioning}
            onCheckedChange={(jitProvisioning) => setForm({ ...form, jitProvisioning })}
          />
          <Checkbox
            label="Offer it on the sign-in page"
            checked={form.enabled}
            onCheckedChange={(enabled) => setForm({ ...form, enabled })}
          />
        </div>
      </FormDialog>

      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        resourceType="SAML provider"
        resourceName={removing?.name ?? ""}
        confirmLabel="Remove SAML provider"
        pending={remove.isPending}
        error={remove.error ? message(remove.error) : null}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </section>
  );
}

/**
 * Every change to one OpenID Connect or OAuth 2.0 provider. The history
 * never holds the client secret, so a restore keeps the one stored now.
 */
function ProviderHistory({ id, name, canRestore }: { id: string; name: string; canRestore: boolean }) {
  const qc = useQueryClient();
  const key = { path: { id } };
  const revisions = useQuery({ ...idpsRevisionsListOptions(key), retry: false });
  const restore = useMutation({
    ...idpsRevisionsRestoreMutation(),
    onSuccess: async (_, vars) => {
      toast(`${name} restored to version ${vars.path.revision}`);
      await qc.invalidateQueries({ queryKey: idpsRevisionsListQueryKey(key) });
      await qc.invalidateQueries({ queryKey: listIdpsQueryKey() });
    },
  });
  return (
    <HistoryPanel
      label={`History of ${name}`}
      intro="Every change to this provider, newest first. Restoring an earlier version is recorded as a further change. It never puts back a client secret: the one stored now is kept."
      loading={revisions.isPending}
      revisions={revisions.data?.revisions ?? []}
      error={restore.error ? message(restore.error) : revisions.error ? message(revisions.error) : null}
      canRestore={canRestore}
      restoring={restore.isPending}
      onRestore={(revision) => restore.mutate({ path: { id, revision } })}
      empty="Nothing has changed about this provider since the history began."
    />
  );
}

/**
 * Every change to one SAML provider. A restore puts back the identity
 * provider it trusted, from the history rather than by fetching the
 * metadata again, and keeps our signing key as it is.
 */
function SamlHistory({ id, name, canRestore }: { id: string; name: string; canRestore: boolean }) {
  const qc = useQueryClient();
  const key = { path: { id } };
  const revisions = useQuery({ ...samlProvidersRevisionsListOptions(key), retry: false });
  const restore = useMutation({
    ...samlProvidersRevisionsRestoreMutation(),
    onSuccess: async (_, vars) => {
      toast(`${name} restored to version ${vars.path.revision}`);
      await qc.invalidateQueries({ queryKey: samlProvidersRevisionsListQueryKey(key) });
      await qc.invalidateQueries({ queryKey: samlQueryKey });
    },
  });
  return (
    <HistoryPanel
      label={`History of ${name}`}
      intro="Every change to this provider, newest first. Restoring an earlier version is recorded as a further change. It keeps the signing key in use now, so your identity provider does not need the certificate again."
      loading={revisions.isPending}
      revisions={revisions.data?.revisions ?? []}
      error={restore.error ? message(restore.error) : revisions.error ? message(revisions.error) : null}
      canRestore={canRestore}
      restoring={restore.isPending}
      onRestore={(revision) => restore.mutate({ path: { id, revision } })}
      empty="Nothing has changed about this provider since the history began."
    />
  );
}
