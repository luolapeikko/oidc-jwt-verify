# oidc-jwt-verify monorepo

[![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/ellerbrock/typescript-badges/)
[![Maintainability](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/maintainability.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![Code Coverage](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/coverage.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)

Monorepo containing two complementary packages for validating OIDC JWTs and adding Tachyon-based persistence adapters.

## Packages

### `@luolapeikko/oidc-jwt-verify`

Core OIDC JWT validation library.

- Validates asymmetric JWT tokens (OIDC/OpenID providers)
- Builds public PEM certificates from JWK modulus + exponent
- Caches issuer OpenID configuration for 24 hours
- Reloads key set when a new `kid` is seen
- Supports pluggable certificate and token caches

Package README: `packages/oidc-jwt-verify/README.md`

### `@luolapeikko/oidc-jwt-verify-tachyon`

Tachyon Drive adapters for caches used by the core package.

- Provides Tachyon-backed certificate cache adapter
- Provides serializers for validated token cache persistence
- Useful for file-backed or encrypted cache persistence

Package README: `packages/oidc-jwt-verify-tachyon/README.md`
