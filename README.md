
# Information Security Lab 1

Simple Node.js web application built using
- typescript - for typesafe streamlined developer experience
- express.js - web server framework
- jose - jwt library
- @node-rs/argon2 - bindings to rust 🦀 implementation of argon2
  for strong password hashing

## API

### **POST** `/auth/register`

Creates account for a new user.

Endpoint expects login data as json request body with fields
`login` and `password` in plain text. Example:

```json
{
  "login": "coolguy123",
  "password": "12355"
}
```

Requirement for login field:
- non-empty
- only contains unicode chars of class Letters (`L`) and digits (`Nd`)

Password:
- length equals or above 3

If login data does NOT satisfy the above criteria, HTTP 422 is returned
with plain text message as response body.

Endpoint is NOT JWT protected.

If app creates account successfully, 200 OK HTTP response is returned.

Otherwise app returns non 2xx HTTP response with html page
containing error.

### **POST** `/auth/login`

Authenticates a user.

Endpoint accepts login data and returns a JWT token, which is later to be
supplied to protected endpoints.

Endpoint expects login data as json request body with fields
`login` and `password` in plain text. Example:

```json
{
  "login": "coolguy123",
  "password": "12355"
}
```

Requirement for login field:
- non-empty
- only contains unicode chars of class Letters (`L`) and digits (`Nd`)

Password:
- length equals or above 3

If login data does NOT satisfy the above criteria, HTTP 422 is returned
with plain text message as response body.

Endpoint is NOT JWT protected.

Upon successful login JWT is returned in `token` field of json in the
response body.

Example:
```json
{
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJsb2dpbiI6Im93bCIsImF1ZCI6ImxvY2FsaG9zdCIsImV4cCI6MTc2MTczNDYyMywiaXNzIjoibWUiLCJpYXQiOjE3NjE3MzI4MjN9.T8WhtMMr_3vmqBxBpT8b8sur4OSHEtuC1P-HUPlDFnruHiNrgBpmO59tEhYeGtwpQiUyK6JWXqSfhT1bl8B6xg"
}
```

JWT has expiration time of 30 minutes. JWT is invalidated after app restart.

### **GET** `/api/data`

> JWT Protected endpoint

Requests all account known to the app.

Expects JWT Token as query `token` param. 

Example:

```
GET /api/data?token=eyJhbGciOiJIUzUxMiJ9.eyJsb2dpbiI6Im93bCIsImF1ZCI6ImxvY2FsaG9zdCIsImV4cCI6MTc2MTczNDYyMywiaXNzIjoibWUiLCJpYXQiOjE3NjE3MzI4MjN9.T8WhtMMr_3vmqBxBpT8b8sur4OSHEtuC1P-HUPlDFnruHiNrgBpmO59tEhYeGtwpQiUyK6JWXqSfhT1blg HTTP/1.1
```

Endpoint returns json body which contains login of a requester and
logins of all known accounts:

```json
{
    "requester": "owl",
    "all_users": [
        "owl"
    ]
}
```

## Security

Passwords are hashed with argon2 algorithm using random salt.

Auth check middleware was developer to easily add protection to
routes. The middleware validates JWT Token. It validates that token has valid format. Then checks signature of a token using HS512 secret key. They key
is kept in memory and never stored to disk. JWT Payload does not contain
any secret data, so no encryption applied.

Defence against SQL injections is established: app binds
parameters to sql statements instead of plain string concatenation.

Input that is known to be later send back to users is heavily validated:
only letters and digit unicode characters allowed. This renders impossible
to embed HTML or executable code into data.

## CI

The project has CI. The CI workflow performs security checks:
- dependencies are scanned for known vulnerabilities using `pnpm audit`
- code is checked by `semgrep` SAST engine using OWASP TOP 10 rule set


## Security pipeline check results

![pnpm audit successful](media/audit.png)
![semgrep scan successful](media/semgrep.png)

