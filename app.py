from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from flask import request
from wtforms import SelectField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt 
from flask_mysqldb import MySQL

app = Flask(__name__)

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'databasepwp'
app.secret_key = 'your_secret_key'

mysql = MySQL(app)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('user', 'User '), ('admin', 'Admin')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email already exists!')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        role = form.role.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (username, email, role, password) VALUES (%s, %s, %s, %s)", (username, email, role, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed! Please check your email and password!")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:  # Pastikan pengguna sudah login
        return redirect(url_for('login'))

    # Ambil nama pengguna dari database
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT username FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()[0]
    cursor.close()

    # Ambil data pengguna lain dari database
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()

    return render_template('dashboard.html', user=user, users=users)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:  # Pastikan pengguna sudah login
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Hash password sebelum disimpan ke database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Langsung tambahkan user ke database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)", 
                       (username, email, hashed_password, role))
        mysql.connection.commit()
        cursor.close()

        flash("User     added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:  # Pastikan pengguna sudah login
        return redirect(url_for('login'))

    # Cek role user yang sedang login
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT role FROM users WHERE id=%s", (session['user_id'],))
    current_user_role = cursor.fetchone()[0]

    if current_user_role != 'admin':
        flash("You do not have permission to access this page!", "danger")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User  not found!", "danger")
        return redirect(url_for('dashboard'))

    form = RegisterForm(obj=user)
    form.username.data = user[1]
    form.email.data = user[2]
    form.role.data = user[4]

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        role = form.role.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s AND id!=%s", (email, user_id))
        existing_user = cursor.fetchone()
        cursor.close()

        if existing_user:
            flash("Email already exist!", "danger")
            return redirect(url_for('edit_user', user_id=user_id))

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET username=%s, email=%s, role=%s WHERE id=%s", 
                       (username, email, role, user_id))
        mysql.connection.commit()
        cursor.close()

        flash("User  updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_user.html', form=form, user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    mysql.connection.commit()
    cursor.close()

    flash("User  deleted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return render_template('logout.html')

if __name__ == '__main__':
    app.run(debug=True)