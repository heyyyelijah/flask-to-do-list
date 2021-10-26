from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, RegisterForm
import os
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import os
from decouple import config

Base = declarative_base()
app = Flask(__name__)
app.config['SECRET_KEY'] = config("SECRET_KEY")

bootstrap = Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1",  "sqlite:///flask-todolist.db")
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///blog.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    entry = relationship("TodoList", back_populates="author")
# Line below only required once, when creating DB.
db.create_all()

class TodoList(db.Model):
    __tablename__ = "to_do_list"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="entry")
    date = db.Column(db.String(250), nullable=False)
    entry = db.Column(db.Text, nullable=False)
#Line below only required once, when creating DB.
db.create_all()


def user_logged_out():
    ''' returns True if the user is currently logged out '''
    user_id = current_user.get_id()
    print(type(user_id))
    print(f'id = {user_id}')
    try:
        if str(User.query.get(user_id)) == 'None':
            logged_out = True
        else:
            logged_out = False
    except:
        print('exception triggered: user_logged_out function')
    return logged_out


@app.route('/')
def home():
    logged_out = user_logged_out()
    user = User.query.filter_by(id=current_user.get_id()).first()
    print(f'current_user: {current_user.get_id}')
    print()
    if logged_out == False:
        entries = TodoList.query.filter_by(author_id=current_user.get_id()).all()
        print(len(entries))
        if request.method == "POST":
            return render_template("index.html", home_page=True,
                                   logged_out=logged_out, entry_len=len(entries),
                                   user=user, entries=entries)
        return render_template("index.html", home_page=True, logged_out=logged_out, user=user,
                               entry_len=len(entries), entries=entries
                               )
    
    return render_template("index.html", home_page=True, logged_out=logged_out, entry_len=0)

# add cards like trello

@app.route('/new-entry', methods=["GET", "POST"])
def add_entry():
    logged_out = user_logged_out()
    if request.method == "POST" and logged_out == False:
        # user = User.query.filter_by(id=current_user.get_id()).first()
        new_entry = TodoList(
            entry=request.form['add_entry'],
            author_id=current_user.get_id(),
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for("home"))
    return redirect(url_for("home"))

@app.route('/register', methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # If user's email already exists
        # if User.query.filter_by(email=form.email.data).first():
        #     # Send flash messsage
        #     flash("You've already signed up with that email, log in instead")
        #     # Redirect to /login route.
        #     return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form['password'],
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form['email'],
            name=request.form['name'],
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    # logged_out = user_logged_out()  , logged_out=logged_out
    return render_template("register.html", register_page=True)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        # Check stored password hash against entered password hashed.
        try:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Your email or password is not signed up, register instead")
                return redirect(url_for('register'))
        except AttributeError:
                flash("Your email or password is not signed up, register instead")
                return redirect(url_for('register'))

    logged_out = user_logged_out()
    return render_template("login.html", logged_out=logged_out, sign_in_page=True   )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/delete/<int:entry_id>", methods=["GET", "POST"])
def delete_entry(entry_id):
    entry_to_delete = TodoList.query.get(entry_id)
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)