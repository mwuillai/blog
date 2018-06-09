from flask import Flask, render_template, flash, request, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# config Mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'aqwZSX'
app.config['MYSQL_DB'] = 'flaskblog'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/articles')
def articles():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    return render_template('articles.html', articles=articles)
    cur.close()


@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM articles WHERE id = %s", (id))
    article = cur.fetchone()
    return render_template('article.html', article=article)
    cur.close()


class registerform(Form):
    name = StringField('name', [validators.length(min=1, max=50)])
    username = StringField('username', [validators.length(min=4, max=25)])
    email = StringField('email', [validators.length(min=6, max=50)])
    password = PasswordField('password', [validators.DataRequired(
    ), validators.EqualTo('confirm', message='passwords do not match')])
    confirm = PasswordField('confirm password')


class ArticleForm(Form):
    title = StringField('title', [validators.length(min=1, max=255)])
    body = TextAreaField('body')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerform(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create cursor

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (
            name, email, username, password))

        # Commit to DB

        mysql.connection.commit()

        cur.close()

        flash('you are now registered and can log in', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # create cursor

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO articles(title, body) VALUES(%s, %s)", (
            title, body))

        # Commit to DB

        mysql.connection.commit()

        cur.close()

        flash('Article add successfully', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                app.logger.info('PASSWORD MATCHED')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                app.logger.info('PASSWORD NOT MATCHED')
                return render_template('login.html', error=error)
            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out')
    return render_template('login.html')

if __name__ == '__main__':
    app.secret_key="secret123"
    app.run(debug=True)
