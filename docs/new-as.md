# Design for a new go-wallet-backend AS

## Requirements

The new AS must support all existing features in the current AS and should also adopt a more standard security model for tokens where refresh tokens are used to represent a service and access tokens are used to represent authorization for entity A (a user or a service) to access service B.

The new AS should also be able to handle both user-level access and services as well as admin-level access. The new AS should be based on a unified token format using JWTs signed by assymetric keys.

The new AS should properly extend the current AS and should be integrated into the mode-based URL routing to allow the AS to be operated both as part of an all-in-one deployment or standalong. 

The new AS must to the extent possible use the same db models as the current AS.

## Authentication

The user authenticates to the AS either using passkeys or via the ODIC RP. The result of the authentication is a https only cookie 
that represents the authentication session of the user. This cookie is implemented as a high-entropy string that indexes the session DB in the AS. The session object is a JWT and the jti is the session cookie value.

The cookie is set in the response to the final step of the authentication flow. In order to support legacy clients a simplified access token that has the same format as we currently implement may be returned along with the cookie and the "200 OK" response.

Legacy clients use this access token JWT directly just as today.

Modern clients ignore any JWT returned in the authentiation flow and instead request access tokens when they are needed to call APIs on behalf of the user. This is covered in the next section:

## Token format

{
    # standard claims
    jti: <id>,
    exp: <ttl>,
    sub: <user>,
    aud: <target service>,
    iss: <AS url>,
    iat: <time>,
    acr: <type of auth>,
    # siros claims
    tenant_id: <tenanat> | '*',
    tac: <rwlidka>, # cf below,
    rev: <revocation reason>
}

### sub

Either the user OR $iss if the token gives permissions to the service itself. This is used for "anonymous" tokens, eg for situations where the $aud should not know who the real subject is. This can for instance be used when resolving issuer metadata via the backend; the resolver service should be authenticated to avoid abuse but it doesn't have to know which user wants to resolve the issuer.

### tenant_id

This is the tenant. The string "*" means that the token applies to all tenants - aka god tokens.

### tac

tac or token access control is the permissions that apply to the token. This is a bit-field represented as these individual permissions:

- (r)ead
- (w)rite
- (l)ist
- (i)insert
- (d)elete
- (k)issue tokens - aka delegation
- (a)administrate

Read and write means just that on an per-object basis. List means read access on directory-like structures. Insert allows addition in directory-like structures, Delete means remove object. issue means the right to issue delegation tokens and admin is full admin rights.

These rights apply across all services but they may not all make sense for every service.

### rev

Revocation reason. If present the token is revoked

### acr 

The authentication context class reference represents the type of authentication that was done to create the original refresh token.

## Authentication

The user authenticates to the AS in one of several ways. Passkey authentication and registration is the default authentication method for end users and an OpenID RP is used for other users (admins). 

## Authorization

When a client (wallet or SDK) needs to call an API on behalf of a user it will try to obtain an access token with the appropriate tac, audience and other fields. This is done by doing a POST to the /token endpoint of the AS and including a template token JSON in the request. The template token may include tenant_id and tac.

If the AS finds a session cookie in the request the corresponding JWT is unpacked and checked for expiration and revocation. If the JWT is still valid (no signature validation is really necessary) a response token is created by:

1. create an empty JSON
2. add claims from the template JSON token
3. add claims from the refresh JWT
4. generate new jti, iat and exp (now+2 minutes) (nbf=now-1 sec)

The resulting JSON is converted to an s-expression using the structure (token (claim value)())

The s-expression is evaluated against a configured list of rules in a spocp engine (remote or local). If the result of the evaluation is true then the JSON is signed and returned to the caller, otherwize an error is returned.