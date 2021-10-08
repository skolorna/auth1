# auth1

[![codecov](https://codecov.io/gh/skolorna/auth1/branch/main/graph/badge.svg?token=0cXNVd3uLC)](https://codecov.io/gh/skolorna/auth1)

auth1 is an auth system.

## User

### User Object

| Field      | Type     | Description                         |
| ---------- | -------- | ----------------------------------- |
| id         | uuid     | user id                             |
| email      | string   | email address of the user           |
| verified   | boolean  | whether the email has been verified |
| created_at | datetime | account creation timestamp          |
| full_name  | string   | full name of the user               |

### Get Current User

`GET /users/@me`

Get detailed information about the currently logged-in user.

### Register

`POST /register`

Create a user with the specified name, email address, and password. If successful, a welcome email with instructions for email verification will be delivered to the user's inbox.

#### JSON Parameters

| Field     | Type   | Description   |
| --------- | ------ | ------------- |
| email     | string | email address |
| password  | string | password      |
| full_name | string | full name     |

#### Example

```json
{
  "access_token": "ey....",
  "refresh_token": "GEYEt4+ILoMKS5XE3GX+bKX5S0pD05TF"
}
```

### Login

`POST /login`

Login with the specified email and password.

#### JSON Parameters

| Field    | Type   | Description   |
| -------- | ------ | ------------- |
| email    | string | email address |
| password | string | password      |

#### Example

```json
{
  "access_token": "ey....",
  "refresh_token": "lq7il5GEjkNoLsqjAT+Bo/mzImoQZxoZ"
}
```

## Token managment

### Refreshing an access token

`POST /token`

#### Example

```json
{
  "access_token": "ey...."
}
```
