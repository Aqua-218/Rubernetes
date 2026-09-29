# M2 Kubernetes lifecycle oracle

This directory contains the immutable request fixture, the external-runner
contract, and the privileged harness for the M2 Pod lifecycle differential
test. The request is executed on an independent Kubernetes v1.36.2 node; the
Rubernetes probe never implements or fabricates the oracle observations.

## Components

| File | Role |
|---|---|
| `fixtures/lifecycle.json` | Pod fixtures and operation timeline for the four required cases. Digested into every request (`fixture_sha256`, `timeline_sha256`). |
| `runner_contract.json` | Environment variables, lock paths, isolation requirements, and the **observable schema** (version 2) that both sides of the comparison must emit. |
| `runner.rb` | Fail-closed entrypoint invoked by `tools/milestones/m2_kubernetes_lifecycle_oracle.rb` (stdin request, stdout response). Verifies the CNI lock, the Kubernetes source checkout, the privileged backend, the node image, and the runtime identities before invoking the harness, and re-checks every identity the harness reports. |
| `node_image.rb` | Self-contained node image tool. Runner mode verifies the locked image is present and extracts containerd/runc for host-side hashing. `--write-lock` builds the image with the locked kind release from the pinned checkout and writes the node-image and CNI locks. |
| `harness.rb` | Privileged harness: creates the isolated single-node cluster, imports the workload image by digest, applies the fixture Pods, streams the API watch and Events, captures CRI timestamps, derives the observables, and tears everything down. |
| `registry_image.rb` | Digest-preserving OCI layout fetcher for the busybox workload image (Docker's graph driver rewrites manifests, so the image never goes through the host daemon). |

## Node image and locks

`kindest/node:v1.36.2` is not published, so the node image is built from the
pinned source checkout (`/tmp/kubernetes-v1.36.2`, tag `v1.36.2`, commit
`24e2b02a…`) with kind v0.33.0:

```
build/tools/kind-v0.33.0-linux-amd64 build node-image --image rubernetes/kind-node:v1.36.2 \
  --base-image docker.io/kindest/base:v20260820-69b56db7 /tmp/kubernetes-v1.36.2
RUBERNETES_M2_KUBERNETES_SOURCE=/tmp/kubernetes-v1.36.2 \
  ruby test/conformance/kubernetes/m2_lifecycle_oracle/node_image.rb --write-lock --reuse-existing-image
```

The second command pushes the image through an ephemeral local registry
(localhost, port ≥ 25000) so Docker records a content digest that resolves
offline, inspects the image with containerd running, boots a throwaway cluster
to observe the rendered CNI config, and writes:

- `third_party/locks/kind-v0.33.0.json` — kind release binary (sha256), tag commit, default base image digest
- `third_party/locks/m2-lifecycle-node-image.json` — digest-pinned node image, build inputs, containerd/runc/kubelet binary sha256, image digests of kube-apiserver/etcd/kindnetd/pause, alias container image
- `third_party/locks/m2-lifecycle-cni.json` — kindnetd plugin, version, kind source commit, image reference/digest, rendered `10-kindnet.conflist` sha256, chained plugin binary sha256

Every lock carries `lock_sha256` over its canonical content.

## Running the oracle

The oracle command stays the built-in runner (the M2 gate binds
`provenance.command` to `[ruby, runner.rb]`):

```
RUBERNETES_M2_KUBERNETES_SOURCE=/tmp/kubernetes-v1.36.2 \
  ruby tools/milestones/m2_kubernetes_lifecycle_oracle.rb [--actual lifecycle-report.json]
```

Environment (all optional except the source checkout):

| Variable | Meaning |
|---|---|
| `RUBERNETES_M2_KUBERNETES_SOURCE` | pinned checkout; must be at the locked commit, tagged, and clean |
| `RUBERNETES_M2_LIFECYCLE_ORACLE_COMMAND` | leave unset (built-in runner); an external argv requires `third_party/locks/m2-lifecycle-oracle-runner.json` |
| `RUBERNETES_M2_SELF_CONTAINED_IMAGE_COMMAND` | defaults to `ruby node_image.rb` |
| `RUBERNETES_M2_LIFECYCLE_HARNESS_COMMAND` | defaults to `ruby harness.rb`; recorded with its file sha256 |
| `RUBERNETES_M2_LIFECYCLE_BACKEND` | defaults to `docker` (must answer `docker info`) |
| `RUBERNETES_M2_CONTAINERD_PATH` / `RUBERNETES_M2_RUNC_PATH` | explicit host runtime reuse; refused unless the bytes equal the node image's runtime |
| `RUBERNETES_M2_LIFECYCLE_SCRATCH` | directory for the harness's temporary kind config/kubeconfig |

The harness needs root, Docker, and the locked node image in the local image
store. It creates `docker network create --internal`, a pause container aliased
`host.docker.internal` (kind's entrypoint needs the name on a gateway-less
network), and `kind create cluster --retain` (kind's host-port export fails on
an internal network by design; the cluster is then verified directly through
`docker exec`). It proves egress is unreachable from the node, verifies the
apiserver `gitCommit`, kubelet version, containerd/runc sha256, kindnetd image
and rendered CNI config against the locks, imports busybox under its upstream
digest, and only then applies the fixture Pods. A full run takes about two to
three minutes; nothing is left behind (cluster, containers, network, scratch).

## Observables (schema version 2)

The comparison digests canonical JSON, so both the Kubernetes harness and the
Rubernetes production probe must emit exactly these shapes. Timestamps, UIDs,
node names and IPs never appear in an observable; raw timestamps are in the
trace.

- `init_sidecar_app_order`: `operations` (create/start/wait ordering from CRI
  timestamps), `phase`, `status.initContainerStatuses[]` and
  `status.containerStatuses[]` as `{name, state, restartCount, ready, started[, exitCode]}`.
- `startup_liveness_readiness_thresholds`: `startup`, `readiness`, `liveness`
  objects carrying the probe definition and the observed outcome
  (`started`, `ready`, `ready_before_liveness_kill`, `failures_before_kill`,
  `kill_reason`, `kill_message`, `restartCount_after_kill`).
- `restart_policy_and_backoff`: per-variant maps `restartPolicy`,
  `restartCount`, `phase`, `status` (`{state, reason, exitCode, lastState,
  lastReason, lastExitCode}`) and `backoff_seconds` (distinct CrashLoopBackOff
  waiting-message durations, e.g. `["10s", "20s"]`).
- `graceful_termination_oracle`: `operations` (`exec:preStop`, `signal:TERM`,
  `wait:<grace>`, `signal:KILL` from the termination message and exit code),
  `events` (distinct Event reasons after the delete request), `phase`,
  `status` (`{state, exitCode, reason, message}`),
  `terminationGracePeriodSeconds`, `killed_after_grace_period`.

`runner_contract.json` → `observable_schema` is the normative description.

## Result semantics

`m2_kubernetes_lifecycle_oracle.rb` reports `executed: true` whenever the
external oracle produced verified observations for every case. `status` is
`PASS` when every comparison matches, `FAIL` when the oracle executed but a
comparison differs or the Rubernetes side is missing/unattributed, and
`INCOMPLETE` when the oracle itself could not be verified (missing checkout,
identity mismatch, harness failure). `BLOCKED` is reserved for a missing CNI
lock and no longer occurs in this repository.
