# Decision

Any trust evaluation routine will be plugin-based and two plugins will be provided: 1. a basic certificate trust evaluator based on builtin support for X509 certificats. 2. a plugin that uses authzen using the client from github.com/sirosfoundation/go-trust

# Reason

Trust evaluation is either extremely simple and uses a single PKI root or it is very complex and needs a separate policy engine to deal with customer requirement variability. The go-trust trust engine is a clean abstraction layer for trust evaluation.