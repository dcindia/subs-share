from flask import Flask, request, render_template, session, redirect, url_for, make_response, jsonify
from werkzeug.datastructures import ImmutableMultiDict
from flask_executor import Executor
import json
import os
import re
import sqlite3 as sqlite
#import sqlitecloud as sqlite
import logging
#from flask_debugtoolbar import DebugToolbarExtension
from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter
from icecream import ic
import jwt

auth_config = {'google_login': {'class_': oauth2.Google,
                          'consumer_key': os.environ.get("CONSUMER_KEY"),
                          'consumer_secret': os.environ.get("CONSUMER_SECRET"),
                          'scope': ['profile', 'email'],
                          'offline': True,
                          'user_authorization_params': {'approval_prompt': "force"},
                          'id': 1},
                'youtube_permission': {'class_': oauth2.Google,
                          'consumer_key': os.environ.get("CONSUMER_KEY"),
                          'consumer_secret': os.environ.get("CONSUMER_SECRET"),
                          'scope': ['https://www.googleapis.com/auth/youtube.readonly'],
                          'offline': True,
                          'user_authorization_params': {'approval_prompt': "auto", "include_granted_scopes": "true"},
                          'id': 2}
                          }
#TODO:Force regenerate google refresh token if failing

authomatic = Authomatic(auth_config, os.environ.get('SECRET_KEY'), logging_level=logging.DEBUG)

app = Flask(__name__)
executor = Executor(app)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
DATABASE_PATH = "./users.db"
#DATABASE_PATH = os.environ.get("SQLITE_CONNECTION")
# toolbar = DebugToolbarExtension(app)


if not os.path.isfile(DATABASE_PATH):
    connection = sqlite.connect(DATABASE_PATH)
    connection.execute(open("./SCHEMA.sql").read())
    connection.commit()

def update_fresh_login(db, sub, value):
    update_command = "UPDATE users SET fresh_login = ? WHERE sub = ?;"
    db.execute(update_command, (value,sub))
    db.commit()

@app.route('/')
def index():
    return render_template('home.html')


@app.route('/sample/')
def sample():
    response = json.load(open('response.json'))
    return render_template('index.html.j2', response=response)

@app.route('/privacy-policy/')
def privacy_policy():
  return render_template('privacypolicy.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    response = make_response()
    mod_url = re.sub(r"(http)(?!:\/\/localhost)", "https", request.base_url, count=1)
    request.base_url = mod_url
    ic(request.base_url)
    sub = None
    
    if 'https://www.googleapis.com/auth/youtube.readonly' not in request.args.get('scope', '', type=str):
        ic("google_login")
        result = authomatic.login(WerkzeugAdapter(request, response), 'google_login')
        if not result:
            return response
        else:
            if result.error:
                return render_template('404.html.j2', )
            
            else:
                if not (result.user.name and result.user.id):
                        result.user.update()
                
                ic(result.user.data)
                sub = result.user.data['sub']
                request.args = ImmutableMultiDict()  # make request object reusable for youtube_permission

    
            
    ic("youtube_permission")  
    result2 = authomatic.login(WerkzeugAdapter(request, response), 'youtube_permission', user_authorization_params={'approval_prompt': "auto", "include_granted_scopes": "true", "login_hint":sub})
    if result2:
        if result2.error:
            return "Logged in with error.z"
        else:
            if result2.user:
                if not (result2.user.name and result2.user.id):
                    result2.user.update()

                ic(result2.user.to_dict())
                print(result2.user.credentials.provider_type_class().to_tuple(result2.user.credentials))
                userdata = result2.user.data
                username = userdata['email'].rsplit('@', 1)[0]
                INSERT_COMMAND = "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET credentials=excluded.credentials"

                db = sqlite.connect(DATABASE_PATH)

                if result2.user.credentials.refresh_token:
                    db.execute(INSERT_COMMAND, (userdata['sub'], userdata['email'], username, userdata['name'], userdata['given_name'], result2.user.credentials.serialize(), 1, json.dumps([]) ))
                    db.commit()

            update_fresh_login(db, userdata['sub'], 1)
            response = result2.provider.access("https://youtube.googleapis.com/youtube/v3/subscriptions?part=snippet&maxResults=100&mine=true")
            #session['signout_banner'] = True
            jwtpayload = {"sub": userdata['sub'], "username": username}
            jwt_token = jwt.encode(jwtpayload, os.environ.get('SECRET_KEY'), algorithm='HS256')
            
            # Return a response with a script to set sessionStorage and redirect
            return f"""
                <form id="redirectForm" action="/{username}/" method="POST">
                    <input type="hidden" name="auth_token" value="{jwt_token}">
                </form>
                <script>
                    // Store the JWT token in sessionStorage
                    sessionStorage.setItem('jwtToken', '{jwt_token}');
                    // Automatically submit the form
                    document.getElementById('redirectForm').submit();
                </script>
                """

    return response


@app.route('/<username>/', methods=['GET', 'POST'])
def main(username, auth=False): #Change auth to False in production
    #signout_banner = session.get('signout_banner', default=False)

    auth = request.form.get('auth_token')  # Retrieve the JWT token from the POST request
    if auth:
        # Decode and verify the JWT token (optional)
        try:
            payload = jwt.decode(auth, os.environ.get('SECRET_KEY'), algorithms=['HS256'])
            print(f"Decoded JWT Payload: {payload}")
        except jwt.ExpiredSignatureError:
            return "Unauthorized: Token expired", 401
        except jwt.InvalidTokenError:
            return "Unauthorized: Invalid token", 401
        
        if payload.get('username') != username:
            return "Unauthorized: Invalid username in token", 401


    fetch_command = "SELECT json_object('sub', sub, 'given_name', given_name, 'credentials', credentials, 'fresh_login', fresh_login, 'hidden_channels', hidden_channels) FROM users WHERE username IS ?;"
    db = sqlite.connect(DATABASE_PATH)
    db.row_factory = sqlite.Row
    user = db.execute(fetch_command, (username,)).fetchone()
    ic(user)

    if user is None:
        error_message = "Given user doesn't exist in our database. Owner has to login with his google account first, only then his subscriptions will be visible to others."
        return render_template('404.html.j2', error_message=error_message)
    else:
        user = json.loads(user[0]) #sqlitecloud returned result as tuple, so we need to extract the first element
        signout_banner = user['fresh_login']
        if user['hidden_channels'] is None:
            hidden_channels = []
        else:
            hidden_channels = json.loads(user['hidden_channels'])

    credentials = authomatic.credentials(user['credentials'])

    refresh_response = credentials.refresh()
    if refresh_response and refresh_response.status == 200:
        """old_credentials = authomatic.credentials(user['credentials'])
        ic(credentials.refresh_token)
        ic(old_credentials.refresh_token)
        ic(credentials.serialize())
        ic(old_credentials.serialize())
        credentials.refresh_token = old_credentials.refresh_token  # fetch refresh token again from database"""
        update_command = "UPDATE users SET credentials = ? WHERE sub = ?"
        db.execute(update_command, (credentials.serialize(), user['sub']))
        db.commit()

    response = authomatic.access(credentials, "https://youtube.googleapis.com/youtube/v3/subscriptions?part=snippet&maxResults=100&mine=true")
    if response.status == 200:
        executor.submit(update_fresh_login, db, user['sub'], 0)
        
        if auth:
            return render_template('admin-index.html.j2', username=username, response=response.data, hidden_channels=hidden_channels, signout_banner=signout_banner, auth=auth)
        else:
            
            return render_template('index.html.j2', username=username, response=response.data, hidden_channels=hidden_channels)

    else:
        return response.data
        # TODO: tell user to login again
        # TODO: provide an option to logout (maybe not required if force login every time)
        # DONE: give an option to user to delete his data
        # DONE: count access in database, useful in banner control
        # DONE: make app online using deta and sqlitecloud

@app.route('/modify/hide/', methods=['PUT'])
def hide():
    ic(request.data)
    # gets reverse parameter from the request and converts it to boolean using lower() and comparison
    reverse = request.args.get('reverse', default='false').lower() == 'true'

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized: Missing or invalid Authorization header"}), 401

    # Extract the token from the header
    token = auth_header.split(' ')[1]

    try:
        # Decode the JWT token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    sub = payload.get('sub')
    username = payload.get('username')
    
    channel_id = request.json.get('channelId')
    if not channel_id:
            return jsonify({"error": "Channel ID is required"}), 400
    
    db = sqlite.connect(DATABASE_PATH)
    result = db.execute("SELECT hidden_channels FROM users WHERE sub = ? AND username = ?;", (sub, username)).fetchone()

    hidden_channels = result[0]

    if hidden_channels is None:
        hidden_channels = json.dumps([])  # Initialize as an empty list if None
    hidden_channels = json.loads(hidden_channels)
    if reverse:
        if channel_id in hidden_channels:
            hidden_channels.remove(channel_id)
    else:
        if channel_id not in hidden_channels:
            hidden_channels.append(channel_id)
    hidden_channels = json.dumps(hidden_channels)
    update_command = "UPDATE users SET hidden_channels = ? WHERE sub = ? AND username = ?;"
    db.execute(update_command, (hidden_channels, sub, username))
    db.commit()
    ic(hidden_channels)

    return "Sucess", 200
    
@app.route('/modify/unhide/', methods=['PUT'])
def unhide():
    return redirect(url_for('hide', reverse=True))
