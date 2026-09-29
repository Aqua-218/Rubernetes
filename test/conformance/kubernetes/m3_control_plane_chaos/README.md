# M3 external control-plane chaos harness

`runner.rb` is an independent process runner for the controller-manager and
scheduler leader/queue evidence lanes. By default it starts the project-owned
`rubernetes-apiserver` as one shared HTTP API/store process, then starts two
real instances of each service against it. The API process remains alive while
workers are killed, so Lease resource versions, replayable watch history, and
effect IDs survive worker restart. The runner sends watch and effect-boundary
faults through project-owned controls, kills leaders with `SIGKILL`, restarts
them, and records process namespaces, effect IDs, and raw and canonical trace
digests. After each worker SIGKILL it records the shared API PID and kernel
start-time observation; the final storage contract is true only when those
observations show the API/store process remained alive.

The built-in backend is worker-restart durable only: it is not the M5
disk-durable Raft store or an API-server HA deployment. The harness remains
fail-closed if an explicitly configured API/store override is incomplete or
does not claim the required worker-restart capabilities. Its blocker is:

`M3 external-process evidence is blocked: no worker-restart shared API/store with replayable watch history, compare-and-swap leases, and effect IDs is configured; M3 requires the shared API/store process to survive worker SIGKILL, but does not require M5 disk-durable Raft or API-server HA. Provide a project-owned shared API/store or set RUBERNETES_M3_DURABLE_API_COMMAND, RUBERNETES_M3_DURABLE_API_ENDPOINT, and RUBERNETES_M3_DURABLE_API_CAPABILITIES before running the controller/scheduler chaos harness`

The capability schema and process/fault contract are in
[`runner_contract.json`](runner_contract.json). The milestone probes invoke the
runner by default and allow explicit command overrides through the environment
variables listed there.

`effect_control.rb` and `watch_control.rb` are the default project-owned
controls. They use the same HTTP endpoint and production Watch pipeline; an
override is accepted only when it returns the structured observations and
counters defined by the contract before any run can be marked PASS.
