# Installing without a network

This bundle is everything supermcp needs, in one file: the image, the
Helm chart, the adapter catalogue, the licence and these instructions.
Nothing in it reaches out. The catalogue is compiled into the binary, so
browsing and installing an adapter works with no egress at all; only a
tool call needs to reach the system it was installed for.

## What is in the tarball

| Path | What it is |
|---|---|
| `image/supermcp-image.tar` | The container image, as `docker save` writes it. `image/IMAGE` names the tag it was saved under. |
| `chart/supermcp-<version>.tgz` | The Helm chart, its version pinned to this build. |
| `adapters/index.gen.json` | Every adapter in the catalogue, with its tools, so the contents can be reviewed before anything runs. |
| `adapters/adapters.tar.gz` | The adapter definitions themselves. |
| `sbom.spdx.json` | The software bill of materials, when the build host had `syft`. A bundle built without it carries `sbom.MISSING` saying so. |
| `SHA256SUMS` | Every file above. |

## Checking it before you trust it

```bash
tar xzf supermcp-airgap-<version>.tar.gz
cd supermcp-airgap-<version>
shasum -a 256 -c SHA256SUMS
```

The tarball's own digest is beside it in `.sha256`, and the release is
signed: verify that on the connected side, before the tarball crosses.

## Installing

```bash
# 1. Put the image where your cluster can pull it.
docker load -i image/supermcp-image.tar
docker tag "$(cat image/IMAGE)" registry.internal/supermcp:<version>
docker push registry.internal/supermcp:<version>

# 2. A master key. 32 bytes, base64. Keep it as long as you keep backups:
#    a restored dump is unreadable without it.
kubectl create secret generic supermcp-kek \
  --from-literal=ENCRYPTION_KEK="$(openssl rand -base64 32)"

# 3. The database connection string.
kubectl create secret generic supermcp-db \
  --from-literal=DATABASE_URL='postgres://supermcp:...@postgres.internal:5432/supermcp?sslmode=require'

# 4. The chart, pointed at your registry.
helm install supermcp chart/supermcp-<version>.tgz \
  --set image.repository=registry.internal/supermcp \
  --set publicUrl=https://mcp.internal \
  --set database.existingSecret=supermcp-db \
  --set encryption.local.existingSecret=supermcp-kek
```

The chart applies the migrations in a hook before the new pods start, so
there is no separate step.

## What does not work without a network, and what to do instead

- **Single sign-on** needs to reach your identity provider. It is on the
  internal side of most networks, so this usually works; the provider's
  signing keys are fetched over HTTP and cached for ten minutes.
- **The nightly upstream probe** and anything else that calls a vendor
  will fail, which is correct: those systems are not reachable.
- **Image and chart updates** arrive as the next bundle. There is no
  update check in the binary and nothing phones home; `supermcp version`
  is the only thing that knows what you are running.
- **Vulnerability scanning** happens on the connected side, against the
  SBOM in this bundle.

## Upgrading

Load the next bundle's image, then `helm upgrade` with the new chart.
Read `UPGRADING.md` in the repository for the releases between the two:
the schema policy is expand-only within a major version, so a rollback of
the application is safe, and a rollback of the schema is not offered.
