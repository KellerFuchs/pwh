# pwh — Hashing scheme specification

## Key Derivation Functions

A Key Derivation Function (KDF) maps a binary string `key`,
a binary string `salt` (whose size MAY be specified) and some
*public parameters* to a binary string (called `hash`).

The KDF considered here have the following requirements:
- If the size of `salt` is defined, it MUST be at least 256b.
- The KDF MUST have a security level of 256b, relative to
  **first preimage** resistance, against classical adversaries.
- The KDF SHOULD have a security level of 128b, relative to
  **first preimage** resistance, against post-quantum adversaries.


## Hashing schemes

We define a *hashing scheme* to be a KDF, along with its
*public parameters*.

As such, it can be applied to a `key` and `salt` to produce a `hash`.

Two hashing schemes are equal if they use the same KDF with the same
public parameters.


### Serialization

While *pwh* does not require a specific serialization format for
hashing schemes, the following are suggested:
- If a limited number of hashing schemes are supported,
  they MAY be serialized as integer identifiers.
  - Implementors MUST NOT reuse identifiers for several different schemes,
	regardless of whether they are in use at the same time.
  - Implementors MUST use the same mapping from identifiers to schemes
	for both client- and server-side schemes.
- Hashing schemes MAY be serialized as JSON objects.
  - It must have a `kdf` attribute, with a string value,
	identifying the KDF used.
  - Implementors MUST define the list of supported KDFs.
  - Implementors MUST define, for each KDF, how extra attributes
	encode the public parameters of the KDF.
  - Those definitions SHOULD be formalized as a [JSON Schema].


[JSON Schema]: http://json-schema.org/


## Recommended schemes

### Server-side — PBKDF2-SHA256

We recommend a single KDF server-side: PBKDF2-SHA256.
Its single public parameter is the iteration count.

As of 2016, the recommended value is 100 000, which allows approximately
3000 checks per second (0.3ms/check) on a single Intel i5 CPU core.

We recommend doubling that parameter every two years, or multiplying it
by 1.42 every year, as it is the projected growth in the adversary's
computational power, according to [Moore's law].

The rationale for using PBKDF2-SHA256 is as follows:
- it has widespread support in server-side libraries;
- server-side computations need to be fast, both because of latency
  requirements for user-facing applications, and because a single server
  usually needs to handle many users;
- using non-trivial amounts of memory for a single password hash
  computation is not feasible: it would use (connection rate)×(memory
  usage per hash) in steady-state.


[Moore's law]: https://en.wikipedia.org/wiki/Moore%27s_law


### Client-side — PBKDF2-SHA256

The recommended iteration count, client-side, is set to 1 000 000 (one
million).

PBKDF2-SHA256 is only recommended in legacy applications, where no
support is available for memory-hard functions.


### Client-side — scrypt

[scrypt] was the first memory-hard function used for password hashing,
designed by Colin Percival.  It has been superseeded by [Argon2], winner
of the 2015 Password Hashing Competition.

[scrypt] is only recommended in situation where a good [Argon2]
implementation is not (yet) available.

Based on [Golang's stdlib recommendations](https://godoc.org/golang.org/x/crypto/scrypt)
and [Colin Percival's feedback](https://github.com/Tarsnap/scrypt/issues/19),
we recommend the parameters N=2¹⁴, r=64 and p=1.

The rationale is as follows:
- in general, client-side parallelism cannot be portably expected
  (JavaScript clients, ...), so `p` is set to 1;
- `N` was left unchanged compared to the 2009 recommendations: as Colin
  said, processors didn't get much faster, sequentially speaking;
- the increased transistor count translated instead to larger memories:
  we increased `r` to 64 since the transistor count increased 8-fold.

[scrypt]: https://www.tarsnap.com/scrypt.html


### Client-side — Argon2

[Argon2] is a memory-hard KDF that won the 2015 Password Hashing
Competition.  It is the recommended client-side KDF when available.

with h=1, m=128MiB, XXXTODO

[Argon2]: https://password-hashing.net/
