#####

# Changelog

All notable changes to "Secure Web Auth Template" will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Go to [legend](#legend-types-of-changes) for further information about the types of changes.

## [Unreleased]

## [1.0.0] - 2026-09-18

### Added

- Linter configuration (golangci-lint). [1cc12de](https://github.com/sven-seyfert/secure-web-auth-template/commit/1cc12def696ec0466cde3df6c556891e93fca03d)
- Constants file. [ce6ea9c](https://github.com/sven-seyfert/secure-web-auth-template/commit/ce6ea9cb5a57952e387d65ba9f916fb5ed1eab6f)
- Validation of credentials in backend and frontend code. [d1c19f9](https://github.com/sven-seyfert/secure-web-auth-template/commit/d1c19f99cefbf0de3693b4a389b69aa7ecf13fdf)
- Persistence storage by using SQLite instead of in-memory store. [7bff85e](https://github.com/sven-seyfert/secure-web-auth-template/commit/7bff85e185faabc1ad08bbaf7d6e53bf6ac3bc31)
- Unit tests for database logic. [b8b014e](https://github.com/sven-seyfert/secure-web-auth-template/commit/b8b014e8aa04ce2650addc3bb1c063481c3365fc)
- CHANGELOG.md file. [a2fdb7f](https://github.com/sven-seyfert/secure-web-auth-template/commit/a2fdb7fe816572a0e7b9ac4c49b8fb821290e82e)

### Changed

- Dependency update (new packages for SQLite handling). [1da5e8e](https://github.com/sven-seyfert/secure-web-auth-template/commit/1da5e8e753cc5d18185ca6c136fd6cbe7ab00de8)
- Improve HTTP Server by timeouts and limits. Also add browser security headers (CSP and more). [eb4e70c](https://github.com/sven-seyfert/secure-web-auth-template/commit/eb4e70c1100d6641a4594c977a6e75a1a2feccf0)
- Use repository project root path instead of relative paths. [e31d3fe](https://github.com/sven-seyfert/secure-web-auth-template/commit/e31d3fed71e2d1544a0bbd98c0f66ec7a8787568)
- Improve session handling (metadata handling). [a1dbc4f](https://github.com/sven-seyfert/secure-web-auth-template/commit/a1dbc4f0f8d082411d717eebc014e91ddfd8fa58)
- User handling is based on database storage now. [822dd39](https://github.com/sven-seyfert/secure-web-auth-template/commit/822dd390f268ee658019afcfc54154c2786a631b)
- Apply user handling in auth logic. [ae3f3a7](https://github.com/sven-seyfert/secure-web-auth-template/commit/ae3f3a79dc1c66979c1bc32d71123bbfa6ab7379)
- Apply previous implemented code in main function. [eb31d29](https://github.com/sven-seyfert/secure-web-auth-template/commit/eb31d2982b12cb93e856363fb0f4b2666b9f8da0)
- Update unit tests. [becf595](https://github.com/sven-seyfert/secure-web-auth-template/commit/becf5955b7820c8ea5b6ec42c444d47b75702231)
- Several frontend (javascript) code to be consistent to the backend code. [d0a268e](https://github.com/sven-seyfert/secure-web-auth-template/commit/d0a268eb4815b23f518d4f77518b91fc07c3b133)
- Trivial git related adjustments. [8ab094a](https://github.com/sven-seyfert/secure-web-auth-template/commit/8ab094a30f879fb05becb8b816d14deaab697c3d)

### Documented

- Update README.md file. [342540f](https://github.com/sven-seyfert/secure-web-auth-template/commit/342540f08bea3ff3b725a0cc11a98b261c28afc5)

### Fixed

- Trimming the password is not intended, so trim is reomoved now. [2e01bd1](https://github.com/sven-seyfert/secure-web-auth-template/commit/2e01bd18991134138c4d5b45da535640a39e7602)

### Refactored

- Makefile update. [8e5aef8](https://github.com/sven-seyfert/secure-web-auth-template/commit/8e5aef8fcba172b472a25ebaedcb9e1507ec4c99)
- Use log/slog as logger (instead of log.Printf). [f88f709](https://github.com/sven-seyfert/secure-web-auth-template/commit/f88f70987c629cdcf6bdb9ce21ba92671e0645f6)
- Use errors instead of fmt.Errorf. [532b7a8](https://github.com/sven-seyfert/secure-web-auth-template/commit/532b7a835b23f3fefbed251bbb506c313da1d80a)
- Small clean-ups and linter exception. [a776fe8](https://github.com/sven-seyfert/secure-web-auth-template/commit/a776fe8dabbf539fc6ee6df21874220d341691cf)

### Removed

- In-memory database structure (SQLite is added instead). [54b8efe](https://github.com/sven-seyfert/secure-web-auth-template/commit/54b8efe6ef0fde21f36cac8994f1c9bb8519cff1)
- Unused function (because of a replacement). [6de1e6a](https://github.com/sven-seyfert/secure-web-auth-template/commit/6de1e6a5621639bb71f214881fa6e1cb43c0e179)

### Styled

- Apply canonical format for HTTP headers. [f1cefa2](https://github.com/sven-seyfert/secure-web-auth-template/commit/f1cefa26d8743e2acfd3b06c88a52023efe38712)

## [0.1.0] - 2026-09-09

### Added

- Initial commit (first stable version). [3e610eb](https://github.com/sven-seyfert/secure-web-auth-template/commit/3e610eb8a0a1d0e0c42222f773068d1d3d14c8bd)

[Unreleased]: https://github.com/sven-seyfert/secure-web-auth-template/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sven-seyfert/secure-web-auth-template/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/sven-seyfert/secure-web-auth-template/releases/tag/v0.1.0

---

### Legend - Types of changes

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Documented` for documentation only changes.
- `Fixed` for any bug fixes.
- `Refactored` for changes that neither fixes a bug nor adds a feature.
- `Removed` for now removed features.
- `Security` in case of vulnerabilities.
- `Styled` for changes like whitespaces, formatting, missing semicolons etc.

##

[To the top](#changelog)
