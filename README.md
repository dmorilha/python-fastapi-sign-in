# SING-IN PYTHON FASTAPI + SQLITE3 DEMO

This is a simple example on how to do a self-hosted, self-contained, no TLS sign-up / sign-in functionality using Python 3.13, FastAPI and SQLite3.

## PASSWORD SECURITY

The simplest solution to transmit the user's password safely over the wire was to digest the concatenation of the `username + password` strings using `SHA-512`, and then convert it to `base64` straight into the browser, before sending it through the network.

The `username` was used instead of a random salt to limit interactions between client and server.

**NOTE:** A more advanced solution can be implemented increasing the hash time complexity to diminish the chances of a successful brute force attack, as done by the standard `bcrypt` algorithm.

## FAIL LOCK LIST

If a known or unknown username tries to sign in and fails 3 or more times while the server is up, the user is put into a _Fail Lock_ list for 10 minutes starting from his last attempt. If the same username succeeds before his third failed attempt his entry is removed.

**TO-DO:** The Client's IP could be blocked altogether as well.

##  SIGNED REDIRECT

Redirects are SHA1 HMAC signed, the secret is stored in the python's file.

## SESSION

A Session object is generated upon a username's successful sign in. An HTTP cookie is set containing a randomly generated `UUID4` representing a session id, and the `username`.

### OTHER TO-DOS
 - Better HTML templating, with one of the goals to avoid unnecessary mark-up duplications.
 - Better error handling.
 - Define a workflow to allow users to reset their passwords.
 - Increase the password's hashing complexity.
 - Safely persist secrets in the local disk, some special storage.
 - ...

## SETUP
```
$ python3.13 -m venv fastapi;
$ source fastapi/bin/activate;
$ pip install -r requirements.txt; # requires internet
$

# or ./setup.sh;
```

## RECOVER DATABASE
```
$ sqlite3 users.database;
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password_hash TEXT);
.quit
$

# or ./recreate-database.sh;
```

## RUNNING
```
$ source fastapi/bin/activate;
$ uvicorn main:app --reload;

# or ./run.sh;
```

