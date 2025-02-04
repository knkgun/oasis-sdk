# Changelog

## v0.1.0-alpha3

Spotlight change:

- We're upgrading to a newer version of our Ledger library, which will support
  the next version of the Oasis Ledger app.

## v0.1.0-alpha2

Spotlight change:

- The new `LedgerContextSigner.fromTransport` lets you bring your own
  transport object.

New features:

- Errors from Ledger now come as `LedgerCodeError` with a `returnCode`
  property.

Bug fixes:

- Corrected an issue in converting internal Buffers to Uint8Array.
  This should get rid of the extraneous trailing zeros.

## v0.1.0-alpha1

Spotlight change:

- We'll now be putting this on npm.

Note: nonbreaking changes made before v0.1.0 aren't catalogued.
Ask us directly or see the Git history for what changed.

## v0.0.1

Spotlight change:

- `LedgerContextSigner implements ContextSigner` the way
  `Dog implements Animal` in every introduction to OOP ever.
  We would have named it `DogAnimal` though, I guess.
