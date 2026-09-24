#!/usr/bin/env bash
# Builds the tarball an operator installs from a network that cannot reach
# a registry: the image, the chart, the adapter catalogue, the checksums
# and the instructions, in one file.
#
# What it will not do is pretend. A missing tool or a missing image stops
# the build with the command that fixes it, because a bundle that is
# quietly incomplete is discovered on the disconnected side, which is the
# worst place to discover it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-$(git -C "$here" describe --tags --always --dirty 2>/dev/null || echo dev)}"
image="${IMAGE:-ghcr.io/supermcpco/supermcp:${version}}"
out="${OUT:-$here/dist/airgap}"
name="supermcp-airgap-${version}"
work="$out/$name"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "airgap: $1 is needed to build the bundle ($2)" >&2
    exit 1
  }
}
need helm "brew install helm"
need docker "the image is exported with docker save"
need shasum "it ships with macOS and coreutils"

rm -rf "$work"
mkdir -p "$work"/{image,chart,adapters}

# The image. `docker save` writes the OCI layout the air-gapped registry
# (or `docker load`) reads back.
if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "airgap: $image is not present locally." >&2
  echo "  build it:  docker build -t $image --build-arg VERSION=$version $here" >&2
  echo "  or pull it: docker pull $image" >&2
  exit 1
fi
docker save "$image" -o "$work/image/supermcp-image.tar"
echo "$image" > "$work/image/IMAGE"

# The chart, with its version pinned to this build so an upgrade on the
# disconnected side cannot silently move.
helm package "$here/charts/supermcp" --destination "$work/chart" >/dev/null

# The catalogue is compiled into the binary; what ships here is the index
# and the definitions, so an operator can see what they are installing
# without running it.
cp "$here/adapters/index.gen.json" "$work/adapters/" 2>/dev/null || {
  echo "airgap: adapters/index.gen.json is missing; run 'make adapters' first" >&2
  exit 1
}
tar -C "$here" -czf "$work/adapters/adapters.tar.gz" \
  --exclude='cassettes' --exclude='tests' adapters

# A software bill of materials when the tool is here, and an honest note
# when it is not: an assessor reads the absence, not a silent gap.
if command -v syft >/dev/null 2>&1; then
  syft "$here" -o spdx-json > "$work/sbom.spdx.json"
else
  echo "syft was not installed when this bundle was built, so it carries no SBOM." > "$work/sbom.MISSING"
fi

cp "$here/LICENSE" "$work/"
cp "$here/docs/install-airgap.md" "$work/INSTALL.md"

( cd "$work" && find . -type f ! -name SHA256SUMS -exec shasum -a 256 {} \; | sort -k2 > SHA256SUMS )

tar -C "$out" -czf "$out/$name.tar.gz" "$name"
rm -rf "$work"
shasum -a 256 "$out/$name.tar.gz" | tee "$out/$name.tar.gz.sha256"
echo "airgap: $out/$name.tar.gz"
