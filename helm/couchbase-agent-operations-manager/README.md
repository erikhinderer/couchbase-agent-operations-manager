# Couchbase Agent Operations Manager - Helm chart

Deploys the same five-piece topology as the repository's
[`docker-compose.yml`](../../docker-compose.yml) onto Kubernetes: Couchbase
Server, a one-time provisioning step, the bundled sample MCP servers, the
operations-manager API, and the nginx-served dashboard. Read this whole
file before your first `helm install` - a couple of things necessarily work
differently here than they do under Docker Compose.

## Before you install

**You must build and push three images first.** `docker-compose.yml` builds
`operations-manager`, `sample-mcp-servers`, and `ui` locally from their
Dockerfiles on every `docker compose up --build`. Kubernetes has no
equivalent of that - it can only pull a pre-built image from a registry.
Without this step, every Pod for these three services will sit in
`ImagePullBackOff` forever.

```bash
# from the repository root, pick a registry you can push to and your cluster can pull from
REGISTRY=ghcr.io/your-org   # example - could also be Docker Hub, ECR, GCR, ACR, etc.

docker build -t $REGISTRY/operations-manager:latest ./operations-manager
docker build -t $REGISTRY/sample-mcp-servers:latest ./sample-mcp-servers
docker build -t $REGISTRY/ui:latest ./ui

docker push $REGISTRY/operations-manager:latest
docker push $REGISTRY/sample-mcp-servers:latest
docker push $REGISTRY/ui:latest
```

Then either set `global.imageRegistry` to `$REGISTRY` (leaving the three
`image.repository` values as their short names), or set each
`*.image.repository` to the full `$REGISTRY/<name>` path yourself - see
`values.yaml`. Couchbase's own image (`couchbase:enterprise-7.6.2`) is
public and needs no build/push step.

## Install

```bash
helm install agent-ops ./helm/couchbase-agent-operations-manager \
  --set global.imageRegistry=ghcr.io/your-org \
  --set operationsManager.couchbase.password=<something-not-the-demo-default> \
  --namespace agent-ops --create-namespace
```

Or point `-f` at a values file with your registry, credentials, and API
keys filled in - see every `# CHANGE THIS` / demo-default comment in
`values.yaml`. `helm install` prints connection instructions (`NOTES.txt`)
once it completes.

`helm uninstall agent-ops -n agent-ops` tears it down; add `--set
couchbase.persistence.size=...` etc. up front if you want more than the
20Gi/5Gi defaults for Couchbase data / the embedding-model cache.

## What's identical to docker-compose.yml

- Every environment variable operations-manager reads (`config.py`) is
  wired the same way, with the same demo defaults as `.env.example`.
- The same non-root UID (10001), dropped Linux capabilities, and
  `allowPrivilegeEscalation: false` on operations-manager and
  sample-mcp-servers; the same four capabilities
  (`NET_BIND_SERVICE, CHOWN, SETUID, SETGID`) added back on `ui` for the
  same reason (nginx's root master process needs them to chown its cache
  dirs and setuid/setgid into the unprivileged `nginx` user before
  forking workers).
- Couchbase's admin console/data ports are not exposed outside the
  cluster (the headless Service has no external ClusterIP) - use
  `kubectl port-forward` for admin console access, same tradeoff as
  compose's `127.0.0.1`-only port publishing.
- init.sh's actual provisioning logic (cluster init, bucket/scope/
  collection/index creation) is unchanged and just as idempotent.

## What's deliberately different, and why

**Provisioning runs as a Job, not an always-on idling container.**
`docker-compose.yml`'s `couchbase-init` service touches a sentinel file and
idles forever after provisioning finishes, purely so Docker Desktop's UI
doesn't show it as a stopped/unhealthy-looking container. That workaround
doesn't apply to Kubernetes: a Job that reaches `Completed` is already the
normal, expected-green state in every Kubernetes dashboard. This chart runs
init.sh as a `post-install,post-upgrade` Helm hook Job instead, with
`hook-delete-policy: before-hook-creation,hook-succeeded` so a fresh Job
replaces the old one on every `helm upgrade` (safe - init.sh is fully
idempotent).

**Dependency ordering uses an initContainer, not `depends_on` conditions.**
Kubernetes has no direct equivalent of compose's `depends_on: condition:
service_healthy` / `service_completed_successfully`. Left alone, a
Deployment starts its container the moment the Pod is scheduled - exactly
the race that made operations-manager crash with `ScopeNotFoundException`
before those conditions existed in compose. `operations-manager`'s Pod
carries an `initContainer` that polls the same readiness signals directly
(Couchbase's web console, then authenticated access, then the actual
scope existing; then sample-mcp-servers' health endpoint) before the main
container starts, using the operations-manager image itself (it already
has `curl` for its own Docker `HEALTHCHECK`) rather than adding a
Kubernetes-API-polling sidecar with its own RBAC.

**The shared TLS certificate is a generated Secret, not a shared volume.**
`docker-compose.yml` shares one certificate between `operations-manager`
and `ui` via a single named volume mounted read-write into both
containers. Kubernetes has no built-in equivalent of "one volume,
read-write, mounted into two different Pods" unless your cluster's default
StorageClass supports `ReadWriteMany` (NFS, EFS, Azure Files, Longhorn,
...) - most single-node/dev clusters (kind, minikube, Docker Desktop's own
Kubernetes) do **not** support this out of the box, so this chart doesn't
default to it. Instead (`tls.mode` in `values.yaml`):

- `generated` (default): the chart creates a self-signed certificate once
  on first install and stores it in a Kubernetes Secret, mounted
  **read-only** into both `operations-manager` and `ui`. Stable across
  `helm upgrade` (it reads the existing Secret back via Helm's `lookup`
  function instead of regenerating). Works on every cluster, no storage
  requirements.
- `existingSecret`: bring your own `kubernetes.io/tls` Secret (e.g. from
  cert-manager) via `tls.existingSecret`.

**Trade-off of both modes:** the in-app Settings → HTTPS Certificate
upload page (`operations-manager/app/user_auth.py`'s
`install_server_certificate()`) writes a new cert/key to its mount at
runtime, and a Secret-backed mount is read-only from inside the Pod, so
that upload flow will fail there with a permission/read-only-filesystem
error. For a Kubernetes deployment, install a real certificate by updating
the Secret (or your cert-manager `Certificate` resource) and rolling both
Deployments, instead of using the in-app upload page.

*If you specifically need the in-app upload page to work exactly like
compose's does*, and your cluster's StorageClass supports
`ReadWriteMany`: replace the Secret volumes in
`templates/operations-manager-deployment.yaml` and
`templates/ui-deployment.yaml` with a `ReadWriteMany` PVC mounted
read-write at `/app/tls` and `/etc/nginx/tls` respectively (drop the
`readOnly: true` and the `items` key-remapping, since real
`server.crt`/`server.key` files are expected at those paths rather than a
Secret's standard `tls.crt`/`tls.key` keys) - this wasn't built in by
default specifically because it would silently fail to schedule on the
common dev-cluster case above.

**operations-manager is not yet safe to scale beyond 1 replica.** Login
lockout tracking (`app/user_auth.py`) is in-process memory, not stored in
Couchbase, so multiple replicas would each track failed-login counts
independently instead of sharing state - a real gap, already called out in
the main repo's `SECURITY_HARDENING.md`. `operationsManager.replicaCount`
exists for future use once that's moved into Couchbase, not to be raised
today.

## A note on how this was validated

This chart's templates were checked for balanced/correctly-nested
`{{ }}` template blocks and valid YAML in the non-templated files
(`Chart.yaml`, `values.yaml`), but `helm lint` / `helm template` could not
be run against a real Helm binary while building this (no network path to
`get.helm.sh`, GitHub releases, or the Go module proxy from the sandbox
this was built in). **Run `helm lint . && helm template .` yourself before
your first real install** - if anything doesn't render, the template files
are plain text and every `{{ }}` block is commented with what it's doing,
so should be straightforward to fix.

## Values reference

See the comments directly in `values.yaml` - every setting is documented
there, including which ones have insecure demo defaults you should
override (`operationsManager.couchbase.password`, the three
`operationsManager.apiKeys.*`, and anything under
`operationsManager.providerApiKeys` you intend to use).
