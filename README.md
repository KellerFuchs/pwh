# pwh — Password hashing recommendations

This repository contains recommendations for password hashing in modern
web applications.  They specify a high-level protocol for authenticating
clients.  Its design requirements are:

1. We do not rely on any specific authentication database: it may be
   SQL, NoSQL, Datalog, `passwd(5)` files, ...
2. It is easy, for the application's administrator, to transparently
   migrate to new password hashing schemes (either new cryptographic
   primitives, or new parameters) provided that they can securely
   update the authentication server's and client's code.
3. It is relatively easy to transparently migrate existing applications.
4. It is (computationally) impossible, based on the contents of the
   authentication database, to compute a value that would allow a client
   to authenticate themselves.
5. It is (computationally) impossible, for an adversary with full
   control over the authentication server (but not over the client code)
   to recover the user's password.
6. Batch attacks (trying to recover many passwords at a time) apply
   neither to the passwords (req 5.), nor to the authentication tokens
   sent by the client (req. 4).


This is not:
- an advocacy of passwords as an authentication method;
- a new Key Derivation Function for password hashing;
- a zero-knowledge password proof protocol;  this may be modified in
  the future to recommend use of a ZKPP, but the current state of the
  art (the Secure Remote Password protocol) is unsatisfactory;
- [RFC 2119], which defines the meaning of SHOULD and MUST used here;
- a best-practices guide for deploying TLS;
- a best-practices guide for application security;
- a best-practices guide for password-handling UI;  this is *especially*
  not a discussion on password complexity estimators.

[RFC 2119]: https://tools.ietf.org/html/rfc2119


## Adversary model

The design requirements implicitly assume an adversary model:
- The adversary has access to a quantum computer; luckily, this only
  gives them a quadratic speedup on **first preimage** problems
  (finding `p` such that `H(p) = value`).
- The adversary has:
  - read access to the authentication database (as in requirement 2), or
  - compromised the authentication server (and **not** the client code),
    as in requirement 3; for web applications, this means that the
    static content (esp. the login page and associated scripts) should
    be served separately from the authentication API.
- The communication channel between the client and the authentication
  server is confidential and the server end is authenticated.

Note that an adversary with access to the plaintext of the data
exchanged between client and authentication server is modeled here
by an adversary that has compromised the authentication server:
- it may be able to impersonate the client;
- it cannot recover the client's password.


### Rationale

In the absence of a good Zero-Knowledge Password Proof protocol,
it seems impossible to have both:
- the data in the authentication DB is not sufficient for a client
  to successfully authenticate;
- an adversary observing the communication with the authentication
  server may not impersonate the client.

Given that a breaks on the communication channel would likely allow
to impersonate the user in the scope of the current session, and given
the frequency of database “leaks” (vs. critical TLS bugs), it seems
reasonable to prioritize requirement 4.

### TLS for the authentication server

As stated, the authentication server must use a transport protocol that
guarantees confidentiality and authenticates the server.

It is not required to implement it using TLS, but in the case of TLS:
  1. forward secrecy (as provided by Ephemeral (EC)DH) SHOULD be provided;
  2. insecure versions of TLS SHOULD be disabled;
  3. the certificate and signing key used by the authentication server
     SHOULD NOT be used by any other service;
  4. only strong cipher-suites MUST be employed (and accepted);
  5. the client MUST validate the authentication server's certificate;
     the public key, certificate or matching CA SHOULD be pinned by the client.

#### Rationale

- 1. protects clients from a future key compromise.
- 2. and 3. makes the TLS session harder to attack directly;
  recent attacks relied on keys being reused on less-well-configured
  services.
- 4. is a basic requirement for the communication channel to be secure.
- 5. is required to prevent trivial Man-in-the-Middle attacks.


## Pre-requisites

- A constant `SERVICE` string, unique to this service.
  - It SHOULD be the URI of the authentication API endpoint,
    if applicable.
  - If not applicable, it SHOULD be a [RFC 4122] random UUID.
- A set of [hashing scheme]s supported client-side, known to the client,
  including a single *preferred* scheme.
- An authentication database, that can associate to each user:
  - a client- and server-side [hashing scheme];
  - a random **salt**, with a least 256b of entropy;
  - a password hash, whose size depends on the server-side
    hashing scheme.

[RFC 4122]: https://tools.ietf.org/html/rfc4122
[hashing scheme]: HASH_SCHEME.md


### Rationale

- The constant `SERVICE` is used to derive (client-salt) salts from
  the username; without this per-service constant, it could be possible
  to batch passwords for the same username, across many services.
- This constant needs to be unique (per service), which both a URI and
  a large random UUID achieve.
- URIs are preferred when possible, since it requires no additional
  information client-side and clients can have confidence in its
  uniqueness.
- The set of supported hashing schemes is used to prevent the server
  from making the client reveal a hash of the password with weak
  parameters.
- Storing the hashing schemes on a per-user basis is required to be able
  to migrate from one scheme to another.


## Protocol

### Notations

- `HASH(scheme, key, seed)` designates the hash of `key`
  under scheme `scheme` and seed `seed`.
- `SALT(scheme, username)` designates the SHA-256 hash of the binary
  string `SERVICE + '\0' + scheme + '\0' + username`, using the scheme
  serialization mechanism chosen by the implementation.
- `C_HASH(scheme)` is `scheme, HASH(scheme, password, SEED(username, password))`
- `check(username, scheme, client_hash)` describes the following server
  procedure:
  1. Fetch the following data from the authentication DB:
     - the `client_scheme` and `server_scheme` [hashing scheme]s;
     - the `salt` and password `hash`.
  2. If `scheme` and `client_scheme` are not equal,
     return `WRONG_SCHEME` along with `client_scheme`.
  3. If `HASH(server_scheme, client_hash, seed) == hash`,
     return `OK`; otherwise, return `WRONG_PASSWORD`.
     The comparison SHOULD be constant-time.

### Protocol description

1. The client attempts to authenticate:
  - The users inputs their username and password.
  - The client sends `(username, C_HASH(scheme))` to the server.
2. The server returns the value of `check(username, C_HASH(scheme))`.
3. If the server returned `OK` or `WRONG_PASSWORD`, stop here.
   Otherwise, the client received `WRONG_SCHEME` and `client_scheme`.
   - If `client_scheme` does not belong to the set of supported
     client-side schemes, abort.
   - Send `(username, C_HASH(scheme), C_HASH(client_scheme))`.
4. The server performs the following:
   - Return the value of `check(username, C_HASH(client_scheme))`
   - If it was `OK`, the server MAY update the authentication database,
     setting the following:
     - `client_scheme` is replaced by scheme;
     - `seed` is replaced by a random value, with at least 256b of
       entropy;
     - `hash` is replaced by the hash of `client_hash` under
       `server_scheme` and (the new value of) `seed`.
   - The server SHOULD perform any additional checks that are used for
     password changes (such as second factor authentication) *before*
     updating the database.
   - The server SHOULD perform all actions associated with a password
     change (log, email notification, ...) when updating the database.


### Rationale

- The preferred hashing scheme is known so as to avoid an extra
  round-trip to the authentication server (except when migrating to a
  newer hashing scheme).
- The server-side implementation is stateless (excluding the auth DB),
  lending itself to very efficient implementations.
- The same precautions as for password changes should be taken, because
  nothing guarantees that the client sent the hash of the same password.
