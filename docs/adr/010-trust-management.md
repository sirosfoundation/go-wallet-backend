# Decision

All trust evaluation MUST be delegated to a remote trust endpoint (AuthZEN PDP). No local trust evaluation is performed to avoid the risk of false positive trust decisions.

The trust endpoint is configured globally via `trust.default_endpoint` in the configuration. Tenants may optionally override the default endpoint via their tenant configuration, which is propagated to the engine via the JWT `trust_endpoint` claim.

# Reason

Trust evaluation is complex and requires a centralized policy engine to handle customer requirement variability and ensure consistency across deployments. Local trust evaluation (e.g., validating X.509 certificates against system roots) risks introducing false positives where credentials appear trusted but should not be according to the deployment's trust policy.

The go-trust trust engine (github.com/sirosfoundation/go-trust) provides a clean AuthZEN-based abstraction layer for trust evaluation that supports:
- ETSI TSL validation
- OpenID Federation
- DID resolution
- Custom policy rules

By delegating all trust decisions to the remote endpoint, deployments maintain full control over their trust policy without risk of local code bypassing that policy.