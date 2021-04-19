from redis import Redis
import time
from functools import update_wrapper
import random
import string
import json
from collections import OrderedDict
from flask import  (Flask,
                    render_template,
                    request,
                    g,
                    redirect,
                    jsonify,
                    url_for,
                    flash,
                    make_response,
                    session as login_session,
                    current_app,
                    send_from_directory)
from flask_talisman import Talisman
from sqlalchemy import (create_engine,
                        asc)
from sqlalchemy.orm import sessionmaker
from database_setup import (Base,
                            User,
                            Message,
                            MessageLog)
import httplib2
import requests
from cryptography.fernet import Fernet
import os
import shlex, subprocess
from datetime import datetime



# Security size for the messages container
RECIPIENT_MESSAGES_LIMIT = 1000

# Create an instance of the Flask class
app = Flask(__name__)

# Content Security Policies and implementation
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://m4test.com/static/checkFunctions.js',
        'http://localhost:8080/static/checkFunctions.js',
        ],
    'style-src': [
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://m4test.com/static/styles.css',
        'https://m4test.com/static/bootstrap.min.css',
        'http://localhost:8080/static/styles.css',
        'http://localhost:8080/static/bootstrap.min.css',
        ],
    'font-src': [
        'https://fonts.gstatic.com/s/roboto/',
        ]
}

# using Talisman
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src']
)

# Configure Flask JSON to not sort the dictionary when serialize to JSON,
# so we can choose the order of variables to show.
app.config.update(
    JSON_SORT_KEYS=False,
    UPLOAD_FOLDER="dbdump",
)

#Secret key automatically generated, used by Flask to encrypt the session cookies
app.secret_key = ''.join(random.choice(string.ascii_uppercase +
        string.ascii_lowercase + string.digits) for x in range(32))

#Connect to Database and create database session
engine = create_engine('postgresql://messages:greenflowerplus@localhost/messages')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#Load the key for symmetric encryption
file_uri = "/home/messages/messages/key.txt"
if os.path.exists(file_uri):
    key_file = open(file_uri, "rb")
    f_key = key_file.read()
    f = Fernet(f_key)
else:
    print("Error: 'key.txt' didn't found")
    exit()

#Load the PIN for user creation
pin_file_uri = "/home/messages/messages/pin.txt"
if os.path.exists(file_uri):
    pin_file = open(pin_file_uri, "rt")
    PIN = pin_file.readline().splitlines()[0]
else:
    print("Error: 'pin.txt' didn't found")
    exit()

#Redis connection
redis = Redis()

#Access rate limit control
class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)


def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
    return ("<!DOCTYPE html><h2>Query limit achieved for your IP address!<br>" + \
            "Please, return later...<br>",429)

#Defaul window = 5min = 300s
def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(fd):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return fd(*args, **kwargs)
        return update_wrapper(rate_limited, fd)
    return decorator


@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response


#Render Login page
@app.route('/')
@app.route('/index.html')
@ratelimit(limit=30)
def showLogin():
    print('in showLogin')
    # Create a state token to prevent request forgery.
    # Store it in the session for later validation.
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) \
        for x in range(32))
    login_session['state'] = state
    #return "The current session state is %s" % login_session['state']
    #Render the login template, to obtain the local login
    return render_template('index.html', state=state)


#Local login
@app.route('/local_login', methods=['POST'])
@ratelimit(limit=30)
def local_login():

    print('at local login')
    #print(request.form)

    #Test for valid state token (unique session anti-forgery)
    print('testing for valid state token')
    if request.form.get('state') != login_session.get('state'):
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    username = request.form.get('username')
    password = request.form.get('password')

    #Check to see if there are arguments
    if not username or not password:
        print("missing arguments")
        msg = ["Missing arguments.",
               "Please, verify the data informed."]
        return render_template('message.html', msg=msg, dest="/", my_time=8000)

    #Check if the user exists
    print('verifying username')
    id = -1
    users = session.query(User).all()
    for user in users:
        decrypted_username = f.decrypt(user.username).decode()
        print("username:", username)
        if username == decrypted_username:
            id = user.id

    user = session.query(User).filter_by(id=id).first()
    if not user:
        # render intermediate screen
        msg = ["Login is not possible for this user.",
                "The username is not known."]
        return render_template('message.html', msg=msg, dest="/", my_time=8000)


    #Check the password
    print('verifying the password')
    #print('nonce:' + csp_nonce())
    if user.verify_password(password):
        #Loggin the user
        login_session['user_id'] = user.id
        login_session['name'] = f.decrypt(user.name).decode()
        login_session['username'] = f.decrypt(user.username).decode()
        login_session['provider'] = 'local'
        # render intermediate screen
        msg = ["Login Successful for: " + login_session['name'],
                "with the username: "  + login_session['username']]
        return render_template('message.html', msg=msg,
                                dest="/user/" + str(login_session['user_id']) + "/inbox",
                                my_time=4000)

    else:
        # render intermediate screen
        msg = ["Login is not possible.",
                "Please, verify the password."]
        return render_template('message.html', msg=msg, dest="/", my_time=8000)



#Reset the password
@app.route('/reset_password', methods=['GET', 'POST'])
@ratelimit(limit=30)
def resetPassword():
    print('at resetPassword')

    #Process the get username form (getUsername.html)
    if request.method == 'POST' and request.form.get('get_username'):
        print("processing getUsername.html POST")
        #Test for valid state token (unique session anti-forgery atack code)
        print('testing for valid state token')
        if request.form.get('state') != login_session.get('state'):
            response = make_response(json.dumps('Invalid state parameter'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        username = request.form.get('username')

        #Check to see if there are arguments
        if not username:
            print("missing arguments")
            # render intermediate screen
            msg = ["Missing arguments.",
                    "Please, verify the data informed."]
            return render_template('message.html', msg=msg, dest="/reset_password", my_time=8000)

        #Check if the user exists
        print('verifying username')
        id = -1
        users = session.query(User).all()
        for user in users:
            decrypted_username = f.decrypt(user.username).decode()
            print("username:", username)
            if username == decrypted_username:
                id = user.id

        user = session.query(User).filter_by(id=id).first()
        if not user:
            # render intermediate screen
            msg = ["Reseting is not possible for this user.",
                    "The username is not known."]
            return render_template('message.html', msg=msg, dest="/reset_password", my_time=8000)

        #Check if security question and security question answer exists
        security_question = f.decrypt(user.security_question).decode()
        #print("User security question:" + security_question)
        security_question_answer_hash = user.security_question_answer_hash
        if (not security_question) or (not security_question_answer_hash):
            # render intermediate screen
            msg = ["Reseting is not possible for this user.",
                    "The security question or its answer is not registered."]
            return render_template('message.html', msg=msg, dest="/reset_password", my_time=8000)

        return render_template('resetPassword.html', user=user, STATE=request.form.get('state'), f=f)

    #Process the reset password form (resetPassword.html)
    if request.method == 'POST' and request.form.get('reset_password'):
        print("processing resetPassword.html POST")
        #Test for valid state token (unique session anti-forgery atack code)
        print('testing for valid state token')
        if request.form.get('state') != login_session.get('state'):
            response = make_response(json.dumps('Invalid state parameter'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        user_id = request.form.get('user_id')
        old_security_question_answer = request.form.get('old_security_question_answer')
        new_password = request.form.get('password')
        conf_new_password = request.form.get('conf_password')
        new_security_question = request.form.get('security_question')
        new_security_question_answer = request.form.get('security_question_answer')
        conf_new_security_question_answer = request.form.get('conf_security_question_answer')
        pin = str(request.form.get('pin'))

        #print("new_security_question_answer", new_security_question_answer)
        #print("conf_new_security_question_answer", conf_new_security_question_answer)

        if pin != PIN:
            print("incorrect PIN")
            # render intermediate screen
            msg = ["Reseting the password is not possible.",
                   "You are not authorized (incorrect PIN)."]
            return render_template('message.html', msg=msg, dest="/", my_time=8000)

        #Check to see if there are arguments
        if not new_password:
            print("missing password")
            # render intermediate screen
            msg = ["Missing password.",
                   "Please, verify the data informed."]
            return render_template('message.html', msg=msg, dest="/reset_password", my_time=8000)

        #Check to see if new password confirmation matches
        if new_password != conf_new_password:
            print("password does not match")
            # render intermediate screen
            msg = ["Reseting the password is not possible.",
                   "'Password' and 'Confirmation' do not match. "]
            return render_template('message.html', msg=msg, dest="/reset_password", my_time=8000)


        #Check to see if security question answer confirmation matches
        if (new_security_question_answer) and (new_security_question_answer != conf_new_security_question_answer):
            print("security question answer does not match")
            # render intermediate screen
            msg = ["Reseting the password is not possible.",
                   "'New Answer' and 'Confirm the New Answer' do not match. "]
            return render_template('message.html', msg=msg, dest="/reset_password", my_time=8000)


        #Verify the security question answer and edit user data if answer is correct
        userToEdit = session.query(User).filter_by(id=user_id).one()
        if userToEdit and userToEdit.verify_passw_phrase_answer(old_security_question_answer):
            #Save the data to the user
            userToEdit.security_question = f.encrypt(new_security_question.encode())
            userToEdit.hash_passw_phrase_answer(new_security_question_answer)
            userToEdit.hash_password(new_password)
            session.add(userToEdit)
            session.commit()
            # render intermediate screen
            msg = ["Password for User " +  f.decrypt(userToEdit.username).decode() +
                    " successfully reseted!", "Returning to the login page..."]
            return render_template('message.html', msg=msg, dest="/", my_time=8000)

        else:
            print("security question does not match")
            # render intermediate screen
            msg = ["Reseting the password is not possible.",
                   "Security answer is incorrect."]
            return render_template('message.html', msg=msg, dest="/", my_time=8000)

    if request.method == 'GET':
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) \
            for x in range(32))
        login_session['state'] = state
        return render_template('getUsername.html', STATE=state)


#Register new users
@app.route('/new_user', methods=['GET', 'POST'])
@ratelimit(limit=30, per=60*60*12)
def new_user():
    print('at new user')

    if request.method == 'GET':
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) \
            for x in range(32))
        login_session['state'] = state
        return render_template('newUser.html', STATE=state)

    #print(request.form)

    if request.method == 'POST':
        #Test for valid state token (unique session anti-forgery)
        print('testing for valid state token')
        if request.form.get('state') != login_session.get('state'):
            response = make_response(json.dumps('Invalid state parameter'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        conf_password = request.form.get('conf_password')
        security_question = request.form.get('security_question')
        security_question_answer = request.form.get('security_question_answer')
        conf_security_question_answer = request.form.get('conf_security_question_answer')
        pin = str(request.form.get('pin'))

        if pin != PIN:
            print("incorrect PIN")
            # render intermediate screen
            msg = ["User registration is not possible.",
                   "You are not authorized (incorrect PIN)."]
            return render_template('message.html', msg=msg, dest="/", my_time=8000)

        if (not username) or (not password):
            print("missing arguments")
            # render intermediate screen
            msg = ["User registration is not possible.",
                   "Missing arguments. It is necessary username and password."]
            return render_template('message.html', msg=msg, dest="/new_user", my_time=8000)

        #Check to see if password matches
        if password != conf_password:
            print("password does not match")
            # render intermediate screen
            msg = ["User registration is not possible.",
                   "Password confirmation does not match."]
            return render_template('message.html', msg=msg, dest="/new_user", my_time=8000)

        #Check to see if security question answer matches
        if (security_question_answer) and (security_question_answer != conf_security_question_answer):
            print("security question answer does not match")
            # render intermediate screen
            msg = ["User registration is not possible.",
                    "Security question answer confirmation does not match."]
            return render_template('message.html', msg=msg, dest="/new_user", my_time=8000)

        #Check if user with that username already exist
        id = -1
        users = session.query(User).all()
        for user in users:
            decrypted_username = f.decrypt(user.username).decode()
            print("username:", username)
            if username == decrypted_username:
                id = user.id

        user = session.query(User).filter_by(id=id).first()
        if user:
            print("existing username")
            # render intermediate screen
            msg = ["User with username "  +  f.decrypt(user.username).decode() + " already exists.",
                   "Registration is not possible."]
            return render_template('message.html', msg=msg, dest="/", my_time=8000)

        #Create new user
        print("Requisites verified. Registering new user...")
        user = User(name=f.encrypt(name.encode()),
                    username=f.encrypt(username.encode()),
                    security_question=f.encrypt(security_question.encode()))
        user.hash_password(password)
        user.hash_passw_phrase_answer(security_question_answer)
        print('username', f.decrypt(user.username).decode(), ' created')
        session.add(user)
        session.commit()
        # render intermediate screen
        msg = ["User " + f.decrypt(user.username).decode() + " successfully registered!",
                "Please, wait. Returning to the login page..."]
        return render_template('message.html', msg=msg, dest="/", my_time=8000)


# Disconnect
@app.route('/disconnect')
@ratelimit(limit=100)
def disconnect():
    if 'provider' in login_session:
        #This is for a locally registered user
        if login_session['provider'] == 'local':
            print('deleting user locally registered')
            #only locally registered users have a username loaded
            del login_session['username']
        #This is for all users
        del login_session['user_id']
        del login_session['name']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showLogin'))
    else:
        flash("You were not logged in!")
        return redirect(url_for('showLogin'))


#Show user messages (inbox)
@app.route('/user/<int:user_id>/inbox')
@ratelimit(limit=30)
def showUserMessages(user_id):
    print("in showUserMessages")
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect(url_for('showLogin'))
    try:
        user = session.query(User).filter_by(id=user_id).one()
        messages = session.query(Message).filter_by(recipient_id=user.id).all()
        return render_template('inbox.html', user=user, messages=messages, f=f)
    except:
        return render_template('dataNotFound.html')


#Show specific message
@app.route('/user/<int:user_id>/message/<int:message_id>')
@ratelimit(limit=30)
def showMessage(user_id, message_id):
    print("in showMessage")
    print("user_id", user_id)
    print("message_id", message_id)
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect(url_for('showLogin'))
    try:
        user = session.query(User).filter_by(id=user_id).one()
        if not user:
            print("user not found")
        message = session.query(Message).filter_by(id=message_id,recipient_id=user.id).one()
        if not message:
            print("message not found")
        print("Rendering template showMessage.html")
        return render_template('showMessage.html', user=user, message=message, f=f)
    except:
        print("Rendering template dataNotFound.html")
        return render_template('dataNotFound.html')


#Delete specific message
@app.route('/message/<int:message_id>/delete/', methods=['GET', 'POST'])
@ratelimit(limit=30)
def deleteMessage(message_id):
    print("in deleteMessage")
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect(url_for('showLogin'))
    if request.method == 'POST':
        print("in deleteMessage: POST")
        #try:
        messageToDelete = session.query(Message).filter_by(id=message_id).one()
        user_id = messageToDelete.recipient_id
        user = session.query(User).filter_by(id=user_id).one()
        #Protect messages from unauthorized users
        if messageToDelete.recipient_id != login_session['user_id']:
            print('message of not authorized: not the creator')
            # render intermediate screen
            msg = ["** Alert! ***", "You are not authorized to delete this message" +
                    " because you are not the recipient."]
            return render_template('message.html', msg=msg, dest="/", my_time=8000)

        #Backup to message log
        newMessageToLog = MessageLog(sender_id           = messageToDelete.sender_id,
                                     sender_name         = messageToDelete.sender_name,
                                     sender_username     = messageToDelete.sender_username,
                                     sender_ip           = messageToDelete.sender_ip,
                                     recipient_id        = messageToDelete.recipient_id,
                                     recipient_name      = user.name,
                                     recipient_username  = user.username,
                                     recipient_ip        = request.remote_addr,
                                     creation_time       = messageToDelete.creation_time,
                                     title               = messageToDelete.title,
                                     content             = messageToDelete.content,
                                     deletion_time       = datetime.utcnow())
        session.add(newMessageToLog)
        print("deleted message added to log")
        session.commit()
        try:
            message_title = f.decrypt(messageToDelete.title).decode()
            session.delete(messageToDelete)
            session.commit()
            flash(message_title + " Successfully Deleted")
        except:
            flash("An exception occurred")
        return redirect(url_for('showUserMessages', user_id=user_id))

    else:
        print("in deleteMessage: GET")
        try:
            messageToDelete = session.query(Message).filter_by(id=message_id).one()
            user_id = messageToDelete.recipient_id
            return render_template('deleteMessage.html', user_id=user_id, message=messageToDelete, f=f)
        except:
            print("in deleteMessage: GET: except")
            return render_template('dataNotFound.html')


#Create a new message
@app.route('/user/<int:user_id>/message/new', methods=['GET', 'POST'])
@ratelimit(limit=30)
def newMessage(user_id):
    print('in new message')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect(url_for('showLogin'))
    sender_id = user_id
    sender = session.query(User).filter_by(id=sender_id).one()
    if request.method == 'POST':
        recipient_id = request.form['recipient_id']

        #Verify the messages limit for the recipient
        recipient_messages = session.query(Message).filter_by(recipient_id=recipient_id).all()
        n_messages = len(recipient_messages)
        print("recipient messages count:", n_messages)
        if n_messages > RECIPIENT_MESSAGES_LIMIT:
            # render intermediate screen
            msg = ["Messages limit achieved for the recipient.",
                   "The maximum number of messages is " + str(RECIPIENT_MESSAGES_LIMIT)]
            return render_template('message.html', msg=msg,
                                    dest="/user/" + str(login_session['user_id']) + "/inbox",
                                    my_time=8000)

        recipient = session.query(User).filter_by(id=recipient_id).one()
        #Create the new item in the category selected
        message_title = request.form['title']
        message_content = request.form['content']
        if not message_title:
            message_title = "(blank)"
        newMessage = Message(sender_id          = sender.id,
                             sender_name        = sender.name,
                             sender_username    = sender.username,
                             sender_ip          = request.remote_addr,
                             recipient_id       = recipient.id,
                             title              = f.encrypt(message_title.encode()),
                             content            = f.encrypt(message_content.encode()),
                             creation_time      = datetime.utcnow())
        session.add(newMessage)
        session.commit()
        flash('New Message "%s" Successfully Created' % (f.decrypt(newMessage.title).decode()))
        return redirect(url_for('showUserMessages', user_id=user_id))
    else:
        recipients = session.query(User).order_by(asc(User.name))
        return render_template('newMessage.html', user=sender, recipients=recipients, f=f)


#Dump the database
@app.route('/dbdump')
@ratelimit(limit=30)
def messagesDump():
    print("Dumping the database")
    dump_success = 1
    try:
        retcode = subprocess.call(["pg_dump", "-d", "messages",  "--no-owner", "-f", "dbdump/db.sql" ])
        print("process return code:" + str(retcode))

    except Exception as e:
            dump_success = 0
            print('Exception happened during dump %s' %(e))
            flash('Exception happened during dump')

    if dump_success == 1:
        print('Database dump successful')
        flash('Database dump successful')
        print("upload from dir:" + app.config['UPLOAD_FOLDER'])
        flash('Wait for download in your local directory...')
        return send_from_directory(app.config['UPLOAD_FOLDER'], "db.sql")
    else:
        print('db dump failure')

    return redirect(url_for('showLogin'))


if __name__ == '__main__':

    #Debug mode on
    #app.debug = True
    #Server URL, '0.0.0.0' means all public ip addresses
    app.run(host='0.0.0.0', port=80)
