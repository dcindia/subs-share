from flask import Flask, request, render_template, url_for, make_response
import json
import os
import sqlite3 as sqlite
import logging
from flask_debugtoolbar import DebugToolbarExtension
from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter
from icecream import ic

auth_config = {'google': {'class_': oauth2.Google,
                          'consumer_key': os.environ.get("CONSUMER_KEY"),
                          'consumer_secret': os.environ.get("CONSUMER_SECRET"),
                          'scope': ['profile', 'email', 'https://www.googleapis.com/auth/youtube.readonly'],
                          'offline': True,
                          'user_authorization_params': {'approval_prompt': "auto"},
                          'id': 123}}

authomatic = Authomatic(auth_config, 'dcindia123', logging_level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = "$$enter_secret_here$$"
DATABASE_PATH = "./users.db"
# toolbar = DebugToolbarExtension(app)


if not os.path.isfile(DATABASE_PATH):
    connection = sqlite.connect(DATABASE_PATH)
    connection.execute(open("./SCHEMA.sql").read())
    connection.commit()


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/sample/')
def sample():
    response = json.load(open('response.json'))
    return render_template('index.html.j2', response=response)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    response = make_response()
    result = authomatic.login(WerkzeugAdapter(request, response), 'google')

    if result:
        if result.error:
            return "Logged in with error.z"

        elif result.user:
            if not (result.user.name and result.user.id):
                result.user.update()
            # print(result.user.to_dict())
            # print("*")
            # print(result.user.data)
            # print(result.user.credentials.provider_type_class().to_tuple(result.user.credentials))
            userdata = result.user.data
            username = userdata['email'].rsplit('@', 1)[0]
            INSERT_COMMAND = "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET credentials=excluded.credentials;"

            if result.user.credentials.refresh_token:
                db = sqlite.connect("./users.db")
                db.execute(INSERT_COMMAND, (userdata['sub'], userdata['email'], username, userdata['name'], userdata['given_name'], result.user.credentials.serialize()))
                db.commit()
                db.close()
            response = result.provider.access("https://youtube.googleapis.com/youtube/v3/subscriptions?part=snippet&maxResults=100&mine=true")
            return response.data

    return response


@app.route('/<username>/')
def main(username):
    fetch_command = "SELECT sub, given_name, credentials FROM users WHERE username IS ?;"
    db = sqlite.connect("./users.db")
    db.row_factory = sqlite.Row
    user = db.execute(fetch_command, (username,)).fetchone()

    if user is None:
        return "Given user doesn't exist in our database."

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
        return render_template('index.html.j2', response=response.data)
    else:
        return response.data
        # TODO: tell user to login again
