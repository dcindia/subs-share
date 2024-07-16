from flask import Flask, request, render_template, session, redirect, url_for, make_response
from werkzeug.datastructures import ImmutableMultiDict
from flask_executor import Executor
import json
import os
import re
#import sqlite3 as sqlite
import sqlitecloud as sqlite
import logging
#from flask_debugtoolbar import DebugToolbarExtension
from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter
from icecream import ic

auth_config = {'google_login': {'class_': oauth2.Google,
                          'consumer_key': os.environ.get("CONSUMER_KEY"),
                          'consumer_secret': os.environ.get("CONSUMER_SECRET"),
                          'scope': ['profile', 'email'],
                          'offline': True,
                          'user_authorization_params': {'approval_prompt': "force"},
                          'id': 1},  # not working, insufficient scope
                'youtube_permission': {'class_': oauth2.Google,
                          'consumer_key': os.environ.get("CONSUMER_KEY"),
                          'consumer_secret': os.environ.get("CONSUMER_SECRET"),
                          'scope': ['https://www.googleapis.com/auth/youtube.readonly'],
                          'offline': True,
                          'user_authorization_params': {'approval_prompt': "auto", "include_granted_scopes": "true"},
                          'id': 2}
                          }

authomatic = Authomatic(auth_config, 'dcindia123', logging_level=logging.DEBUG)

app = Flask(__name__)
executor = Executor(app)
app.config['SECRET_KEY'] = "$$enter_secret_here$$"
DATABASE_PATH = "./users.db"
DATABASE_PATH = os.environ.get("SQLITE_CONNECTION")
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
    ic(request.base_url)
    return render_template('home.html')


@app.route('/sample/')
def sample():
    response = json.load(open('response.json'))
    return render_template('index.html.j2', response=response)


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

                print(result2.user.to_dict())
                print("*")
                print(result2.provider)
                print(result2.user.data)
                print(result2.user.credentials.provider_type_class().to_tuple(result2.user.credentials))
                userdata = result2.user.data
                username = userdata['email'].rsplit('@', 1)[0]
                INSERT_COMMAND = "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET credentials=excluded.credentials"

                db = sqlite.connect(DATABASE_PATH)

                if result2.user.credentials.refresh_token:
                    db.execute(INSERT_COMMAND, (userdata['sub'], userdata['email'], username, userdata['name'], userdata['given_name'], result2.user.credentials.serialize()))
                    db.commit()

            update_fresh_login(db, userdata['sub'], 1)
            response = result2.provider.access("https://youtube.googleapis.com/youtube/v3/subscriptions?part=snippet&maxResults=100&mine=true")
            #session['signout_banner'] = True
            return redirect(url_for('main', username=username))

    return response


@app.route('/<username>/')
def main(username):
    #signout_banner = session.get('signout_banner', default=False)

    fetch_command = "SELECT json_object('sub', sub, 'given_name', given_name, 'credentials', credentials, 'fresh_login', fresh_login) FROM users WHERE username IS ?;"
    db = sqlite.connect(DATABASE_PATH)
    #db.row_factory = sqlite.Row
    user = db.execute(fetch_command, (username,)).fetchone()
    ic(user)

    if user is None:
        error_message = "Given user doesn't exist in our database. Owner has to login with his google account first, only then his subscriptions will be visible to others."
        return render_template('404.html.j2', error_message=error_message)
    else:
        user = json.loads(user[0]) #sqlitecloud returned result as tuple, so we need to extract the first element
        signout_banner = user['fresh_login']

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
        return render_template('index.html.j2', username=username, response=response.data, signout_banner=signout_banner)
    else:
        return response.data
        # TODO: tell user to login again
        # TODO: provide an option to logout (maybe not required if force login every time)
        # DONE: give an option to user to delete his data
        # DONE: count access in database, useful in banner control
        # TODO: make app online using deta and sqlitecloud
