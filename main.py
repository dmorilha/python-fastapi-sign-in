from contextlib import closing
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse
import sqlite3

app = FastAPI()

@app.get('/assets/js/password')
def assets_js_password() -> str:
    return PlainTextResponse('''function hash_password_v1(username, password, cb) {
const data = new Uint8Array((username + password).split('').map(el => el.charCodeAt(0)));
crypto.subtle.digest('SHA-512', data).then(function(digest){ /*TODO: increase complexity*/
    const final = '$1$' + (new Uint8Array(digest)).toBase64() + '$';
    cb(final);
});}''')

@app.get('/sign-up')
def sign_up_view() -> HTMLResponse:
    return HTMLResponse('''<html>
<head>
    <title>Sign Up</title>
    <script src="/assets/js/password"></script>
</head>
<body>
    <div align="right"><b>Sign Up</b> | <a href="/sign-in">Sign In</a></div>
    <center>
    <form id="form" action="sign-up" method="post">
        <table border="1">
            <thead>
                <tr><td align="center" colspan="3"><b>Sign Up</b></td></tr>
            </thead>
            <tr>
                <td><b>username</b></td>
                <td><input id="username" name="username" type="text"></input></td>
            </tr>
            <tr>
                <td><b>password</b></td>
                <td>
                    <input id="user-typed-password" type="password"></input>
                    <input id="password" name="password" type="hidden"</input>
                </td>
            </tr>
            <tr>
                <td><b>re-type your password</b></td>
                <td><input id="user-retyped-password" type="password"></input></td>
                <td id="password-message" width="200"></td>
            </tr>
            <tr>
                <td colspan="3" align="right">
                    <input type="submit" value="Sign Up"></input>
                    <input type="reset" value="Reset"></input>
                </td>
            </tr>
        </table>
    </form>
    </center>
</body>
<script>
(function(){
  const form = document.getElementById('form'),
    password = document.getElementById('password'),
    password_message = document.getElementById('password-message'),
    username = document.getElementById('username'),
    user_retyped_password = document.getElementById('user-retyped-password'),
    user_typed_password = document.getElementById('user-typed-password');
  function check_passwords_match() { return user_typed_password.value === user_retyped_password.value; }
  form.onsubmit = function(e) {
    if (check_passwords_match()) {
      hash_password_v1(username.value, user_typed_password.value, function(digest) {
        password.value = digest;
        form.submit();
      });
    } else {
      window.alert('Passwords do not match. Please fix it before clicking submit.');
    }
    e.preventDefault();
  };
  user_typed_password.onkeyup = user_retyped_password.onkeyup = function() {
    password_message.innerText = check_passwords_match() ? '' : 'passwords do not match';
  };
})();
</script>
</html>''')

@app.post('/sign-up')
def sign_up_control(username : str = Form(...), password : str = Form(...)):
    response = {'error': 'unknown error'}
    with closing(sqlite3.connect('users.database')) as connection:
        try:
            connection.cursor().execute('INSERT INTO users (username, password_hash) VALUES (?, ?);', (username, password))
            response = {'username': username, 'password': password}
        except sqlite3.IntegrityError:
            response = {'error': 'username already exists'}
    return response

@app.get('/')
@app.get('/sign-in')
def sign_in_view() -> HTMLResponse:
    return HTMLResponse('''<html>
<head>
    <title>Sign In</title>
    <script src="/assets/js/password"></script>
</head>
<body>
    <div align="right"><a href="/sign-up">Sign Up</a> | <b>Sign In</b></div>
    <center>
    <form id="form" action="sign-in" method="post">
        <table border="1">
            <thead>
                <tr><td align="center" colspan="2"><b>Sign In</b></td></tr>
            </thead>
            <tr>
                <td><b>username</b></td>
                <td><input id="username" name="username" type="text"></input></td>
            </tr>
            <tr>
                <td><b>password</b></td>
                <td>
                    <input id="user-password" type="password"></input>
                    <input id="password" name="password" type="hidden"></input>
                </td>
            </tr>
            <tr>
                <td colspan="2" align="right">
                    <input type="submit" value="Sign In"/></input>
                </td>
            </tr>
        </table>
    </form>
    </center>
</body>
<script>
(function(){
  const form = document.getElementById('form'),
    password = document.getElementById('password'),
    userPassword = document.getElementById('user-password');
    username = document.getElementById('username'),
  form.onsubmit = function(e) {
    hash_password_v1(username.value, userPassword.value, function(digest) {
      password.value = digest;
      form.submit();
    });
    e.prevetDefault();
  };
})();
</script>
</html>''')

@app.post('/sign-in')
def sign_in_control(username : str = Form(...), password : str = Form(...)):
    response = {'error': 'unknown error'}
    with closing(sqlite3.connect('users.database')) as connection:
        record = connection.cursor().execute('SELECT username, password_hash FROM users WHERE username = ? AND password_hash = ?;', (username, password)).fetchone()
        if record is not None:
            response = {'username': record[0], 'password': record[1]}
        else:
            response = {'error': 'user not found'}
    return response
