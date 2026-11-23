# External Cloud Controller Manager Service integration

Run from the repository root with Go 1.26 or newer:

```sh
ruby test/conformance/kubernetes/load_balancer_ccm/run.rb
```

The runner starts an isolated Rubernetes API server with TLS and RBAC. The
Kubernetes v1.36.2 external CCM command uses the upstream
`kube-system/service-controller` identity plus the route controller's role.
It runs the following checks against the upstream fake provider:

- The Service controller publishes ingress and a cleanup finalizer, passes
  the cloud node's provider ID to the provider, and deletes the load balancer.
  A Service with an explicit class stays outside this controller's ownership.
- With `CloudControllerManagerWatchBasedRoutesReconciliation` enabled, a Node
  added after startup produces a route and its deletion removes that route.
  The periodic reconciliation interval is set to an hour.
- With `CloudControllerManagerWebhook` enabled, the Rubernetes API server
  sends TLS AdmissionReviews to the CCM webhook listener and
  applies both allow and deny results.
