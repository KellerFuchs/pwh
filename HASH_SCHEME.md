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


### Recommended schemes — server side

We recommend a single KDF server-side: `PBKDF2-SHA256`.
Its single public parameter is the iteration count.

As of 2016, the recommended value is 100 000, which allows approximately
3000 checks per second (0.3ms/check) on a single Intel i5 CPU core.

We recommend doubling that parameter every two years, or multiplying it
by 1.42 every year, as it is the projected growth in the adversary's
computational power, according to [Moore's law].

[Moore's law]: https://en.wikipedia.org/wiki/Moore%27s_law


### Recommended schemes — client side

We recommend three hashing schemes for use client-side:
- PBKDF2-SHA256, as on the server-side, with the same iteration count.
- [scrypt] with N=2¹⁴, r=64 and p=1
- [Argon2] with h=1, m=128MiB, XXXTODO

[scrypt]: https://www.tarsnap.com/scrypt.html
[Argon2]: https://password-hashing.net/
