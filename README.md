# auth1

auth1 is an auth system.

## User

### User Object

| Field      | Type     | Description                         |
| ---------- | -------- | ----------------------------------- |
| id         | uuid     | user id                             |
| email      | string   | email address of the user           |
| verified   | boolean  | whether the email has been verified |
| created_at | datetime | account creation timestamp          |

### Get Current User

`GET /users/@me`

Get detailed information about the currently logged-in user.

### Create User

`POST /users`

Create a user with the specified email address and password. If successful, a welcome email
with instructions for email verification will be delivered to the user's inbox.

#### JSON Parameters

| Field    | Type   | Description   |
| -------- | ------ | ------------- |
| email    | string | email address |
| password | string | password      |
