from flask import Flask, url_for, render_template, request
from flask import session,redirect,g,flash
import hashlib
import sqlite3
app = Flask(__name__)

app.secret_key = '[\x17e\xab-\x17\xf2\xe2)E\x90\x04\x10\xb0\xfa\x85\xfe\xb3\x08q\xe2\x9f\x1fO'

def getdb():
	db = getattr(g,'db',None)
	if db is None:
		db = g.db = sqlite3.connect('web.sql3')
		db.row_factory = sqlite3.Row
	return db.cursor()

def commitdb():
	db = getattr(g, 'db', None)
	if db is None:
		getdb()
	g.db.commit()

def password_digest(password):
	return hashlib.sha256(password).hexdigest()		

def authenticate(username, password):
	if username is None or password is None:
		return False

	db = getdb()
	return len(db.execute("select * from users where username = ? and password = ?",
			(username,password_digest(password))).fetchall()) > 0

def register_user(username, password, email, name):
	if username == '' or password == '' or email ==  '' or name == '':
		return False

	db = getdb()
	if len(db.execute("select * from users where username = ? ",(username,)).fetchall()) > 0:
		return False
	else:
		db.execute("insert into users ( name, email, username, password) values ( ?,?,?,?)",(name,email,username,password_digest(password)))
		commitdb()
		db.close()
		return True
		 

@app.route('/')
def index():
	if 'username' not in session:
		return redirect(url_for('login'))
	return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'GET':
		if 'username' in session:
			return redirect(url_for('index'))
		else:
			return render_template('login.html') 
	else:
		# login
		username = request.form['username']
		password = request.form['password']
		if authenticate(username, password):
			session['username'] = username;
			return redirect(url_for('index'))
		else:
			flash("You maybe input the wrong username or password",'error')
			return redirect(url_for('login'))

@app.route('/logout')
def logout():
	session.pop('username')
	return redirect(url_for('login'))

@app.route('/register',methods=['GET','POST'])
def register():
	if request.method == 'GET':
		return render_template('register.html')
	else:
		# register
		username = request.form['username']
		password = request.form['password']
		name = request.form['name']
		email = request.form['email']
		repassword = request.form['repassword']		
		# return username + password + name + email + repassword
		if password == repassword:
			if register_user(username,password,email,name):
				return redirect(url_for('login')) 
			else:
				flash('Something wrong or empty...','error')
				return render_template('register.html')
		else:
			flash('Password mismatch','error')
			return render_template('register.html')

@app.route('/profile',methods=['GET','POST'])
def profile():
	if 'username' not in session:
		return redirect(url_for('login'))

	profile = getdb().execute("select * from users where username=?", (session['username'],)).fetchone()

	if request.method == 'GET':
		flash("You can change your Real name & E-mail","notice")	
		return render_template('profile.html',name=profile['name'],email=profile['email'],username=profile['username'] )

	else: # post

		passwd = request.form['password']
		name = request.form['name']
		email = request.form['email']
		
		if password_digest(passwd) == profile['password']:
			if name == profile['name'] and email == profile['email']:
				return render_template('profile.html',name=profile['name'],email=profile['email'],username=profile['username'] )
			else:
				# change name or email
				db = getdb()
				db.execute("update users set name=?,email=? where username=?", (name, email, session['username']))
				commitdb()
				
				# fetch the value in db again
				profile = db.execute("select * from users where username=?", (session['username'],)).fetchone()
				
				# show it in the page
				flash("Update Successfully !!","notice")
				return render_template('profile.html',name=profile['name'],email=profile['email'],username=profile['username'] )
		else:
				flash("Password mismatch...","error")
				return render_template('profile.html',name=profile['name'],email=profile['email'],username=profile['username'] )
				


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=443, debug=True, ssl_context=("server.crt", "server.key"))
