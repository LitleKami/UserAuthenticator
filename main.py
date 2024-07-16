from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, Blueprint, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String


login_manager = LoginManager()


class Base(DeclarativeBase):
    pass


##Connect to Database
db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)
##CREATE TABLE IN DB AND MIXIN


class User(UserMixin, db.Model):

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)

    __tablename__ = 'users'

    def __init__(self, id):
        self.id = id

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        passw = request.form.get('password')
        word = generate_password_hash(password=passw, salt_length=8)
        user_name = request.form.get('name')
        mail = request.form.get('email')
        if db.session.execute(db.select(User).filter_by(email=mail)).scalar():
            return redirect(url_for('login'))
        else:
            user = User(
                email=mail,
                name=user_name,
                password=word
            )
            db.session.add(user)
            db.session.commit()

            return redirect(url_for('secrets', name=user_name))
    return render_template("/register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mail = request.form['email']
        password = request.form['password']

        if db.session.execute(db.select(User).filter_by(email=mail)).scalar():
            vine = db.one_or_404(db.select(User).filter_by(email=mail))
            word = check_password_hash(vine.password, password)
            if word:
                login_user(vine, remember=True)
                return redirect(url_for('secrets', name=vine.name, logged_in=True))
            else:
                flash('Password incorrect please try again', 'error')
                return redirect(url_for('login'))
        else:
            flash('This email is incorrect please try again', 'error')
            return redirect(url_for('login'))
    return render_template("login.html", logged_in=current_user.is_authenticated)



@app.route('/secrets/<name>')
@login_required
def secrets(name):
    return render_template("secrets.html", name=name, logged_in='True')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home', logged_in=False))


@app.route('/download', methods=['GET'])
def download():
    return send_from_directory(directory='static', path='files/cheat_sheet.pdf')


@app.route('/protected')
@login_required
def protected():
    return f'Hello, {current_user.id}! This is a protected page.'


if __name__ == "__main__":
    app.run(debug=True)

