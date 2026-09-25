# supermcp

Give Claude, ChatGPT and Copilot governed access to the systems your company already runs. One static Go binary turns REST, GraphQL, SQL, SOAP and other MCP servers into MCP tools, with enterprise controls built in rather than bolted on.

> Status: pre-release. M0 (skeleton, adapter format, tooling) is in progress. See `docs/plan.md` for the roadmap.

## Why

supermcp keeps what worked in the first generation of MCP gateways (255 pre-built adapters, OAuth 2.1 for MCP clients, SSRF-guarded upstream calls, response shaping) and rebuilds what enterprises could not deploy: row-level tenant isolation on from day one, envelope encryption with KMS providers, a hash-chained audit stream with SIEM export, fail-closed permissions, per-server token audiences, Helm as the primary deployment.

## Run it

Quickstart with Docker Compose (single host):

```bash
cd deploy/compose
cp .env.example .env            # set ENCRYPTION_KEK (openssl rand -base64 32) and POSTGRES_PASSWORD
docker compose up -d            # http://localhost:8080
```

Kubernetes with Helm:

```bash
kubectl create secret generic supermcp-db --from-literal=DATABASE_URL=postgres://...
kubectl create secret generic supermcp-kek --from-literal=ENCRYPTION_KEK=$(openssl rand -base64 32)
helm install supermcp charts/supermcp \
  --set publicUrl=https://mcp.example.com \
  --set database.existingSecret=supermcp-db \
  --set encryption.local.existingSecret=supermcp-kek \
  --set ingress.enabled=true --set ingress.host=mcp.example.com --set ingress.tls.enabled=true
```

Migrations run as a Helm hook under a Postgres advisory lock; pods pass `/readyz` only once the schema matches the binary.

Both of these are abbreviated. `docs/install.md` has the full sequence, including the settings that must be decided before the first start.

## Documentation

| Document | Who it is for |
|---|---|
| [docs/install.md](docs/install.md) | An engineer deploying this for the first time: Docker Compose and Helm end to end, every setting, and the first-run sequence from migration to a connected client. |
| [docs/operations.md](docs/operations.md) | Whoever is on call: which settings matter, what the alerts mean, how to rotate the master key, and what to do when something is wrong. |
| [docs/UPGRADING.md](docs/UPGRADING.md) | An operator before an upgrade: the releases that need something beyond running the migrations. |
| [docs/api.md](docs/api.md) | An engineer integrating with the API or connecting an MCP client: how authentication works for a person, an API key and a service account, what the MCP endpoint expects, and how errors are reported. |
| [docs/adapters.md](docs/adapters.md) | An engineer writing an adapter: the v2 format field by field, the placeholder syntax, what the validator enforces, and the record-and-replay workflow. |
| [docs/compliance/data-flow.md](docs/compliance/data-flow.md) | A reviewer deciding whether their company's data may pass through this: what enters, where each kind is stored, what leaves and to whom. |
| [docs/compliance/retention.md](docs/compliance/retention.md) | The same reviewer: what is kept, for how long, what removes it, and what a customer can change. |
| [docs/compliance/shared-responsibility.md](docs/compliance/shared-responsibility.md) | A buyer's engineer and their operations team: what this software does, and what the operator must do about keys, backups, egress and upgrades. |
| [docs/compliance/controls.md](docs/compliance/controls.md) | An assessor: common control expectations mapped to the mechanism here, with the partial ones marked as partial. |
| [docs/plan.md](docs/plan.md) | Contributors: the roadmap and the decisions behind it. It describes what is intended, not what is built. |

## Adapters

An adapter is one YAML file describing an upstream and its tools:

```
adapters/<region>/<slug>/adapter.yaml
```

The format is `apiVersion: supermcp.dev/v2`, validated by the JSON Schema at `/schema/adapter/v2.json` and by `supermcp adapter validate --strict`. The 255 adapters were converted from the v1 format with `supermcp adapter convert` and are checked in; `make adapters` regenerates them from the vendored v1 corpus and CI fails if the tree drifts. The corpus holds 257; the two whose authentication is not implemented (`immobilienscout24`, OAuth 1.0a, and `sorare`, a bcrypt-salted login) stay in it for the converter tests and are left out of the catalog.

```bash
supermcp adapter validate --strict adapters
supermcp adapter index -out adapters/index.gen.json
```

## Develop

```bash
make build            # bin/supermcp
make test
docker run -d --name pg -e POSTGRES_PASSWORD=supermcp -e POSTGRES_USER=supermcp -e POSTGRES_DB=supermcp -p 5432:5432 postgres:17-alpine
export DATABASE_URL=postgres://supermcp:supermcp@localhost:5432/supermcp SUPERMCP_DEV=1
bin/supermcp migrate
bin/supermcp serve    # /healthz /readyz /api/v1/catalog /api/openapi.json /api/docs
```

## Licence

MIT. See [LICENSE](LICENSE).
