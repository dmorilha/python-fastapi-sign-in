from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse

import sqlite3

database_file = 'users.database'

app = FastAPI()

@app.get('/js/password')
def js_password() -> str:
    return PlainTextResponse('''function hash_password(username, password, cb) {
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
    <script src="/js/password"></script>
</head>
<body>
    <center>
    <form id="form" action="sign-up" method="post">
        <table border="1">
            <thead>
                <tr><td align="center" colspan="2"><b>Sign Up</b></td></tr>
            </thead>
            <tr>
                <td><b>username</b></td>
                <td><input id="username" name="username" type="text"></input></td>
            </tr>
            <tr>
                <td><b>password</b></td>
                <td>
                    <input id="user-password" type="password"></input>
                    <input id="password" name="password" type="hidden"</input>
                </td>
            </tr>
            <tr>
                <td><b>re-type your password</b></td>
                <td><input id="user-retyped-password" type="password"></input></td>
            </tr>
            <tr>
                <td colspan="2" align="right">
                    <input type="submit" value="Sign Up"/></input>
                    <input type="reset" value="Reset"/></input>
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
    username = document.getElementById('username'),
    userPassword = document.getElementById('user-password');
  form.onsubmit = function(e) {
    hash_password(username.value, userPassword.value, function(digest) {
      password.value = digest;
      form.submit();
    });
    e.prevetDefault();
  };
})();
</script>
</html>''')

@app.post('/sign-up')
def sign_up_control(username : str = Form(...), password : str = Form(...)):
    connection = sqlite3.connect(database_file)
    connection.cursor().execute('INSERT INTO users (username, password_hash) VALUES (?, ?);', (username, password));
    connection.commit()
    connection.close()
    return {'username': username, 'password': password}

@app.get('/')
@app.get('/sign-in')
def sign_in_view() -> HTMLResponse:
    return HTMLResponse('''<html>
<head>
    <title>Sign In</title>
    <script src="/js/password"></script>
</head>
<body>
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
    hash_password(username.value, userPassword.value, function(digest) {
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
    response = {'error': 'user not found'}
    connection = sqlite3.connect(database_file)
    record = connection.cursor().execute('SELECT username, password_hash FROM users WHERE username = ? AND password_hash = ?;', (username, password)).fetchone()
    if record is not None:
        response = {'username': record[0], 'password': record[1]}
    connection.close()
    return response
