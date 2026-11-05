# Changelog

## 0.2.0.0

### Breaking changes

- Require GHC 8.10 / base 4.14 or newer.
- Decode credentials with strict RFC 4648 Base64 validation. Quoted tokens,
  embedded whitespace, invalid characters, missing required padding, excess
  padding, and trailing junk are rejected rather than silently repaired.
- Require ASCII spaces after the case-insensitive `Basic` scheme. Tabs and
  nonbreaking spaces are no longer accepted as separators.

Clients should use their HTTP library's Basic Auth option, or send an unquoted
Base64 token. Decoded usernames and passwords are still passed to the checker
unchanged; credentials are not trimmed.

### Fixes and maintenance

- Return `Nothing` for invalid UTF-8 usernames instead of throwing, even if the
  credential checker accepts those bytes. Passwords remain opaque bytes.
- Use a `newtype` for `AuthSettings`; its realm field remains reserved.
- Replace placeholder tests with authentication, UTF-8, and request-cache tests.
- Replace Travis with cached, pedantic GitHub Actions builds for LTS 18.28,
  LTS 22.38, and LTS 24.65.
- Simplify README/Haddock usage and Basic challenge examples, remove unused
  dependencies, and show the callback type directly in the public signature.

Route authorization and HTTP challenges remain application-managed. Successful
and failed authentication results remain cached only within each request.
