# Decision

WebAuthn is the only mechanism for end user authentication and is also used for other cryptographic functions such as data encryption via the FIDO PRF extension. This wallet is going to use the FIDO/WebAuthn raw signature extensionas it becomes available. 

This ADR applies also to the wallet-frontend implementation.

# Reason

FIDO/WebAuthn/Passkeys are the most widely deployed phishing resistant user authentication mechanism available. It provides a perfect balance of cost vs security vs privacy vs ease of use.