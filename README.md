# SING-IN PYTHON FASTAPI + SQLITE3 DEMO

This is a simple example on how to do a self-hosted, self-contained, no TLS sign-up / sign-in functionality using Python 3.13, FastAPI and SQLite3.

## PASSWORD SECURITY

The simplest solution to transmit the user's password safely over the wire was to digest the concatenation of the `username + password` strings using `SHA-512`, and then convert it to `base64` straight into the browser, before sending it through the network.

The `username` was used instead of a random salt to limit interactions between client and server.

**NOTE:** A more advanced solution can be implemented increasing the hash time complexity to diminish the chances of a successful brute force attack, as done by the standard `bcrypt` algorithm.

### OTHER TO-DOS

 - Implement a _JWT_ cookie (or some other mechanism) allowing an authenticated user to navigate through access controlled parts of the website.
 - Increase the password's hashing complexity.
 - Better HTML templating, with the goal of avoiding unnecessary duplications.
 - Better error handling.

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

