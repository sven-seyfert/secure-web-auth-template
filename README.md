#####

<div align="center">
    <img src="assets/images/logo.png" width="160" />
    <h2 align="center">Welcome to <code>Secure Web Auth Template</code></h2>
</div>

[![license](https://img.shields.io/badge/license-MIT-indianred.svg?style=flat-square&logo=spdx&logoColor=white)](https://github.com/sven-seyfert/secure-web-auth-template/blob/main/LICENSE.md)
[![release](https://img.shields.io/github/release/sven-seyfert/secure-web-auth-template.svg?color=slateblue&style=flat-square&logo=github)](https://github.com/sven-seyfert/secure-web-auth-template/releases/latest)
[![go.mod version)](https://img.shields.io/github/go-mod/go-version/sven-seyfert/secure-web-auth-template?color=lightskyblue&label=go.mod&style=flat-square&logo=go&logoColor=white)](https://github.com/sven-seyfert/secure-web-auth-template/blob/main/go.mod)
[![last commit](https://img.shields.io/github/last-commit/sven-seyfert/secure-web-auth-template.svg?color=darkgoldenrod&style=flat-square&logo=github)](https://github.com/sven-seyfert/secure-web-auth-template/commits/main)
[![contributors](https://img.shields.io/github/contributors/sven-seyfert/secure-web-auth-template.svg?color=darkolivegreen&style=flat-square&logo=github)](https://github.com/sven-seyfert/secure-web-auth-template/graphs/contributors)

[Description](#description) | [Features](#features) | [Getting started](#getting-started) | [Authentication flow](#authentication-flow) | [Security notes](#security-notes) | [License](#license) | [Acknowledgements](#acknowledgements)

---

## Description

This project is a compact template for a secure web authentication flow built with Go on the backend and HTML, CSS, and JavaScript on the frontend. It demonstrates the core pieces of a small auth system: registration, login, session handling, CSRF protection, protected actions, and logout.

The implementation is intentionally compact and easy to read so it can be used as a starting point for internal tools, demos, prototypes, and learning projects. It is not a full identity platform, but it does include the important mechanics of a functional, browser-based authentication flow.

### Typical use cases

This repository is a good fit for:

- internal admin or staff authentication
- small SaaS prototypes
- demo applications with browser-based auth
- secure learning examples for Go web security
- backend starter projects that need an understandable auth baseline

## Features

- registration and login flow with form validation
- username validation with a strict rule set
- password validation with a minimum length
- bcrypt password hashing before persistence
- SQLite-backed user storage with parameterized SQL queries
- random session token and CSRF token generation per login
- session expiry and CSRF expiry checks for protected routes
- browser-side cookie handling for session state and CSRF token management
- protected endpoint requiring both a valid session and a valid CSRF header
- logout flow that clears session cookies and resets stored auth data
- secure HTTP headers applied for all responses
- graceful shutdown and request timeout configuration

## Getting started

1. Run the app:

```bash
# run with Go
go run main.go

# or using the Makefile
make run
```

2. Optional: build the binary instead of running directly:

```bash
# build with Go
go build -o secure-web-auth-template.exe main.go

# or using the Makefile
make build
```

3. Open the app in a browser:

```text
http://localhost:8080
```

4. Use the UI to register a user, log in, access the protected route, and log out again.

> [!TIP]
> Check out the other Makefile commands (options).

## Authentication flow

The full flow in this template is intentionally simple, explicit and educational:

1. submit a registration form with a username and password
2. validate the username and password on the server
3. hash the password using bcrypt and store the user record in SQLite
4. log in with the same credentials
5. create a new session token and CSRF token pair
6. store the tokens in secure cookies and in the database
7. send the CSRF token in the `X-Csrf-Token` header for protected actions
8. call the protected endpoint only when the session and CSRF values are still valid
9. log out to clear the session values and cookies

### Session model

- each user can have only one active session at a time by design
- a second login while a session is still valid is rejected
- if the stored session has expired, the auth flow returns a specific session-expired error
- if the CSRF token has expired, the auth flow returns a specific CSRF-expired error
- protected actions require POST requests and a valid CSRF header

## Security notes

This project is not a production identity system, but it already includes several relevant hardening measures.

### Implemented protections

- bcrypt password hashing
- strict username validation for length and allowed characters
- minimum password length validation
- parameterized SQL queries for SQLite access
- random session and CSRF tokens generated for each login
- session and CSRF expiration checks before access is granted
- secure cookie settings including `HttpOnly`, `Secure`, and `SameSite=Lax`
- CSRF enforcement by comparing the request header `X-Csrf-Token` against the stored value
- restrictive browser security headers:
  - `Content-Security-Policy`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy` restricting camera, microphone, and geolocation access
- frontend validation aligned with the server-side rules to prevent obvious invalid input before it is submitted
- DOM output uses safe text insertion instead of rendering untrusted HTML directly
- HTTP server timeouts and graceful shutdown handling

### Validation policy

The username rule is intentionally narrow and explicit:

- minimum length: 8
- maximum length: 32
- allowed characters: letters, numbers, `.`, `_`, `-`
- first character must be alphanumeric

The password rule is intentionally simple and safe:

- minimum length: 8
- no trimming of leading or trailing spaces before hashing, because those characters are part of the actual password value

### Remaining production considerations (production-grade readiness)

This template is a strong starting point for learning and internal use, but it still needs additional hardening before being treated as a production-grade identity system. The following items are still important in a real deployment:

- TLS termination via HTTPS or a trusted reverse proxy
- rate limiting and brute-force protection
- account lockout or suspicious-login monitoring
- audit logging and operational observability
- network-level controls and secure hosting configuration
- secure deployment of cookies and session policies in the real environment

## License

This project is provided as a template for learning and reuse.

Copyright (c) 2026 Sven Seyfert (SOLVE-SMART)<br>
Distributed under the MIT License. See [LICENSE](https://github.com/sven-seyfert/secure-web-auth-template/blob/main/LICENSE.md) for more information.

## Acknowledgements

- Opportunity by [GitHub](https://github.com)
- Badges by [Shields](https://shields.io) and [SimpleIcons](https://simpleicons.org)
- Thanks to the authors, maintainers and contributors of the various projects and products
  - [golang](https://github.com/golang/go) by the Go team at Google; License: [BSD-3-Clause](https://github.com/golang/go/blob/master/LICENSE)
  - [cURL](https://github.com/curl/curl) by Daniel Stenberg; License: [MIT](lib/curl-license.txt)
  - [SQLite](https://www.sqlite.org/copyright.html) by Richard Hipp; License: [Public Domain](https://www.sqlite.org/copyright.html)
  - [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) by cznic; License: [BSD-3-Clause](https://gitlab.com/cznic/sqlite/-/blob/master/LICENSE)

##

[To the top](#description)
