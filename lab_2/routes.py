# -*- coding: utf-8 -*-
"""
    :Extension of Flask Minitwit application
    : for CS3031 Advanced Telecommunications - Trinity College
    : Author - Neil Hickey
    : App Name: TimeLinez

    : Original copyright and license 
    : copyright: (c) 2010 by Armin Ronacher.
    : license: BSD, see LICENSE for more details.
"""
from __future__ import with_statement
from Crypto.Cipher import AES
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5, sha256
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash
from aes import AESCipher
import os, time

# configuration
DATABASE = '/tmp/minitwit.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = '\x19\x8f[\xe1\x93b\xdfzF\x13\x82t\r8\x9d&9\xb9\xf5\xbc\x00\xcbWU'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db

@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()

def init_db():
    """Creates the database tables."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None

def get_username(id):
    """Convenience method to look up the username for a id."""
    rv = query_db('select username from user where user_id = ?',
                  [id], one=True)
    return rv[0] if rv else None

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')

def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?', [session['user_id']], one=True)

@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's messages.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))

    query = query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [session['user_id'], PER_PAGE])
    newmessage = query

    if g.user:
        i = 0
        db = get_db()
        secretKey = query_db('''select _group.shared_key  from _group, _member
            where _group.group_id = _member.group_id and _member.member_id = ?''', [session['user_id']])
        for m in query:
            m = dict(m)
            aes = AESCipher(secretKey[0][0])
            decyrptedtext = aes.decrypt(m['text'])
            newmessage[i] = m
            newmessage[i]['text'] = decyrptedtext
            i = i + 1

        return render_template('timeline.html', messages=newmessage)
    else:
        return render_template('timeline.html', messages=newmessage)

@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    messages = query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''',[PER_PAGE])
    return render_template('timeline.html', messages=messages)

@app.route('/groups')
def groups():
    """Displays the groups"""
    if not g.user:
        abort(401)

    groups = query_db('select * from _group where _group.owner_id != ?', [session['user_id']])
    return render_template('groups.html', groups=groups)

@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)

    query = query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [profile_user['user_id'], PER_PAGE])
    newmessage = query
    
    if g.user:
        secretKey = query_db('''select _group.shared_key from _group, _member where
                _group.owner_id = ? and _group.group_id = _member.group_id 
                and _member.member_id = ?''',[profile_user['user_id'], session['user_id']])
        if secretKey:
            i = 0
            for m in query:
                m = dict(m)
                aes = AESCipher(secretKey[0][0])
                decyrptedtext = aes.decrypt(m['text'])
                newmessage[i] = m
                newmessage[i]['text'] = decyrptedtext
                i = i + 1

            return render_template('timeline.html', messages=newmessage, profile_user=profile_user)
        else:
            return render_template('timeline.html', messages=newmessage, profile_user=profile_user)
    else:
        return render_template('timeline.html', messages=newmessage, profile_user=profile_user)

@app.route('/join_group/<owner_id>')
def join_group(owner_id):
    """Allows a user to create a group"""
    if not g.user:
        abort(401)
    username = get_username(owner_id)
    if owner_id is None:
        abort(404)

    _group = query_db('''select * from _group where _group.owner_id = ?''', [owner_id])
    group_id = _group[0][0]

    db = get_db()
    db.execute('insert into _member (member_id, group_id) values (?, ?)',
              [session['user_id'], group_id])
    db.commit()
    flash('You are now a member of "%s"' % _group[0][3])
    return redirect(url_for('user_timeline', username=username))

@app.route('/leave_group/<owner_id>')
def leave_group(owner_id):
    """Allows a user to leave a group"""
    if not g.user:
        abort(401)

    _group = query_db('''select * from _group where _group.owner_id = ?''', [owner_id])
    group_id = _group[0][0]

    db = get_db()
    db.execute('delete from _member where member_id = ? and group_id = ?',
              [session['user_id'], group_id])
    db.commit()
    flash('You no longer a member of "%s"' % _group[0][3])
    # username = get_username(owner_id)
    return redirect(url_for('groups'))

@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        usr_id = session['user_id'] 
        secretKey = query_db('''select _group.shared_key  from _group, _member
            where _group.group_id = _member.group_id and _member.member_id = ?''', [usr_id])
        aes = AESCipher(secretKey[0][0])
        cyphertext = aes.encrypt(request.form['text'])
       
        db = get_db()
        db.execute('''insert into message (author_id, text, pub_date)
          values (?, ?, ?)''', [session['user_id'], cyphertext,
                                int(time.time())])
        db.commit()
    return redirect(url_for('timeline'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            session['user_id'] = user['user_id']
            session['user_name'] = user['username']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user. A group is created for the user, to allow others to join to view their posts"""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash) values (?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password'])])
            sharedkey = (os.urandom(32).encode('hex'))
            name = request.form['username'] + "'s Group"
            user = query_db('''select * from user where
                            username = ?''', [request.form['username']], one=True)
            db.execute('''insert into _group (shared_key,owner_id,name) values (?,?,?)''',
                      [sharedkey, user['user_id'], name])
            _group = query_db('''select * from _group where _group.owner_id = ?''', [user['user_id']])
            group_id = _group[0][0]
            db.execute('''insert into _member (member_id,group_id) values (?,?)''',
                      [user['user_id'],group_id])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_name', None)
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == '__main__':
    init_db()
    app.run()
