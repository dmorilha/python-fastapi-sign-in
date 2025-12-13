from base64 import urlsafe_b64encode
from contextlib import closing
from hashlib import sha1, sha256
from hmac import compare_digest, digest
from time import time
from urllib.parse import parse_qs, urlsplit, urlunsplit
import sqlite3

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

class FailLockList:
  '''
  A list to track users who entered invalid credentials "too many times".
  Parameters are:
   - the number of failed attempts before the user gets locked.
   - the lock duration in seconds.
  '''
  def __init__(self, times : int = 3, lock_duration : int = 10 * 60):
    self.dictionary = {}
    self.times = times
    self.lock_duration = lock_duration

  def check(self, username : str) -> bool:
    if username in self.dictionary:
      # if the last failed attempt was within the lock duration, add a new updated entry.
      failed_attempts = self.dictionary[username]
      if self.times <= len(failed_attempts) and self.lock_duration > time() - failed_attempts[-1]:
        print(' -> user "%s" has been locked' % (username, ))
        self.add(username)
        return False
      else:
        del self.dictionary[username]
    return True

  def clean(self):
    now = time()
    for (key, value) in self.dictionary:
      if self.lock_duration < now - value[-1]:
        del self.dictionary[key]

  def add(self, username : str):
    if username in self.dictionary:
      self.dictionary[username].append(time())
    else:
      self.dictionary[username] = [time()]

class MyUrl:
  '''
  A class to handle various URL trickeries
  The sign / verify pair of methods append a HMAC SHA-1 signature to the fragment portion of the URL
  to attest the URL was signed by the same secret.
  The fragment portion of the URL is not signed, and therefore removed from the signing process.
  '''
  def __init__(self, url : str):
    self.url_components = urlsplit(url)

  def without_fragment(self) -> str:
    url_components = self.url_components
    return url_components._replace(fragment='').geturl()

  def sign(self, secret) -> str:
    url : str = self.without_fragment()
    signature = urlsafe_b64encode(digest(secret, bytes(url, 'ascii'), sha1))
    return url + '#s=' + signature.decode('ascii')

  def verify(self, secret) -> bool:
    fragment_components = parse_qs(self.url_components.fragment)
    if 's' in fragment_components:
      s = fragment_components['s']
      if 0 < len(s):
        url = self.without_fragment()
        signature = urlsafe_b64encode(digest(secret, bytes(url, 'ascii'), sha1))
        for value in s:
          if compare_digest(signature, bytes(value, 'ascii')):
            return True
    return False
      
# globals
app = FastAPI()
fail_lock_list = FailLockList()
my_hmac_secret = b'vovodepijama'

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
    <input id="password" name="password" type="hidden"</input>
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

# TODO: the proper response is a redirect
@app.post('/sign-up')
def sign_up_control(username : str = Form(...), password : str = Form(...)) -> JSONResponse:
  response = JSONResponse()
  with closing(sqlite3.connect('users.database', autocommit = True)) as connection:
    try:
      result = connection.cursor().execute('INSERT INTO users (username, password_hash) VALUES (?, ?);', (username, password, ))
      response.render({'username': username, 'password': password})
      print(' -> user "%s" has been successfully created.' % (username, ))
    except sqlite3.IntegrityError:
      response.render({'error': 'username already exists'})
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
    <input name="redirect" value="/welcome#s=0wIOSFMoPCLCrXv0FHus3NfH_7c=" type="hidden"></input>
    <input id="password" name="password" type="hidden"></input>
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
def sign_in_control(username : str = Form(...), password : str = Form(...), redirect : str = Form(...)) -> JSONResponse:
  response = JSONResponse({'error': 'user not found'})
  with closing(sqlite3.connect('users.database')) as connection:
    record = connection.cursor().execute('SELECT username, password_hash FROM users WHERE username = ?;', (username,)).fetchone()
    if record is not None and record[1] == password and fail_lock_list.check(username):
      #TODO: Add a JWT cookie as part of the response
      url = MyUrl(redirect)
      if url.verify(my_hmac_secret):
        # RedirectResponse here redirects w/ a POST rather than a GET.
        return RedirectResponse(url.without_fragment()) 
      else:
        print(' -> redirect URL signature verification failed.')
  fail_lock_list.add(username)
  return response

#TODO: Decode the JWT cookie and extract the username.
@app.get('/welcome')
@app.post('/welcome')
def welcome_view() -> HTMLResponse:
  return HTMLResponse('''<html>
<head><title>Welcome</title></head>
<div align="right"><a href="/sign-up">Sign Up</a> | <a href="/sign-in">Sign In</a></div>
<body><center><h1>Welcome "You"!</h1></center></body>
</html>''')
