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
   to authenticate.
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


### TLS for the authentication server

As stated, the authentication server must use a transport protocol that
guarantees confidentiality and authenticates the server.

It is not required to implement it using TLS, but in the case of TLS:
  - forward secrecy (as provided by Ephemeral (EC)DH) SHOULD be provided;
  - insecure versions of TLS SHOULD be disabled;
  - the certificate and signing key used by the authentication server
	SHOULD NOT be used by any other service;
  - only strong cipher-suites MUST be employed (and accepted);
  - the client MUST validate the authentication server's certificate;
	the public key, certificate or matching CA SHOULD be pinned by the client.


## Requirements

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


## Protocol

1. The client attempts to authenticate:
  - The users inputs their username and password.
  - The client hashes the password, using the preferred scheme,
	and the salt `SERVICE + '\0' + username`.
  - The client sends `(username, scheme, client_hash)` to the server.
2. The server checks the tuple sent from the client:
   - The following data from the authentication DB:
     - the `client_scheme` and `server_scheme` [hashing scheme]s;
     - the `salt` and password `hash`.
   - If `scheme` and `client_scheme` are not equal, the server returns
	 `WRONG_SCHEME` along with `client_scheme`.
   - Otherwise, the server computes the hash of `client_hash`,
     with seed `seed`, under the scheme `server_scheme`.
   - If the resulting hash is equal to `hash`, return `OK`, otherwise
	 return `WRONG_PASSWORD`.  The server SHOULD use a constant-time
	 comparison function there.
3. If the server returned `OK` or `WRONG_PASSWORD`, stop here.
   Otherwise, the client received `WRONG_SCHEME` and `client_scheme`.
   - If `client_scheme` does not belong to the set of supported
     client-side schemes, abort.
   - Hash the password using the `client_scheme` and the salt
	 `SERVICE + '\0' + username`, call the result `old_hash`.
   - Send `(username, scheme, client_hash, client_scheme, old_hash)` to
	 the server.
4. The server performs the following:
   - If `client_scheme` does not match the value from the authentication
	 database, abort.
   - If the hash of `old_hash` under `server_scheme` and `seed` is not
	 equal to `hash`, return `WRONG_PASSWORD`. The server SHOULD use a
	 constant-time comparison function there.
   - At that time, the server MAY update the authentication database,
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
