# all the imports

from __future__ import with_statement
import time
from datetime import datetime
from contextlib import closing
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from werkzeug import check_password_hash, generate_password_hash

#configuration
DATABASE= '/tmp/foo.db'
DEBUG = True
SECRET_KEY = 'foo'

# create our little application 
app = Flask(__name__)
app.config.from_object(__name__)

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])


def init_db():
	with closing(connect_db()) as db:
		with app.open_resource('schema.sql') as f:
			db.cursor().executescript(f.read())
		db.commit()

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
	rv = g.db.execute('select user_id from user where username = ?', [username]).fetchone()
	return rv[0] if rv else None`

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')

@app.before_request
def before_request():
	# Make sure we are connected to db.
	# Look up current user to check if still there
	
	g.db = connect_db()
	g.user = None
	if 'user_id' in session:
		g.user = query_db('select * from user where user_id = ?', [session['user_id']], one=True)

@app.teardown_request
def teardown_request(exception):
	if hasattr(g,'db'):
		g.db.close()


@app.route('/')
def timeline():
	if not g.user:
		return redirect(url_for('login'))
	return render_template('timeline.html', timesheets = query_db('''
			select timesheet.*, user.* from timesheet, user
			where timesheet.author_id == user.user_id
			order by timesheet.pub_date desc limit ?''', [10]))

@app.route('/login/', methods=['GET', 'POST'])
def login():
	# if g.user:
	# 	return redirect(url_for('timeline'))
	error = None
	if request.method == 'POST':
		user = query_db('''select * from user where
			username = ?''', [request.form['username']], one=True)
		if user is None:
			error = 'Invalid username.-'
		elif not check_password_hash(user['pw_hash'],
		request.form['password']):
			error = 'Invalid password.'
		else:
			flash('You were logged in')
			session['user_id'] = user['user_id']
			return redirect(url_for('timeline'))
	return render_template('login.html', error= error)

@app.route('/register/', methods=['GET', 'POST'])
def register():
	# if g.user:
	# 	return redirect(url_for('timeline'))
	error = None
	if request.method == 'POST':
		if not request.form['username']:
			error = 'You have to enter a username!'
		elif not request.form['email'] or '@' not in request.form['email']:
			error = 'Please enter a valid email address.'
		elif not request.form['password']:
			error = 'Please enter a valid password.'
		elif request.form['password'] != request.form['password2']:
			error = 'The two passwords given do not match.'
		elif get_user_id(request.form['username']) is not None:
			error = 'The username is not available.'
		else:
			g.db.execute('''insert into user ( username, email, pw_hash) values (?, ?, ?)''',
							[request.form['username'], request.form['email'], generate_password_hash(request.form['password'])])
			g.db.commit()
			flash('Registration complete!')
			return redirect(url_for('login'))
	return render_template('register.html', error=error)

# @app.route('/add_timesheet/', methods=['GET', 'POST'])
# def add_timesheet():
#     if 'user_id' not in session:
#         abort(401)
#     if request.method == 'POST':
#         if not project_name:
#             error = 'You have to enter a project name.'
#         elif not 


@app.route('/logout/')
def logout():
    flash('You were logged out. Come again soon.')
    session.pop('user_id', None)
    return redirect(url_for('login'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime

if __name__ == '__main__':
    app.run()
