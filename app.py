from functools import wraps                                                 # для декоратора роутеров
from flask import Flask, render_template, request, redirect, session        # для роутов
from flask_sqlalchemy import SQLAlchemy                                     # для модели
from flask_wtf import FlaskForm                                                  # для форм
from wtforms import StringField, PasswordField                              # для форм
from wtforms.validators import DataRequired                                 # для форм
from werkzeug.security import generate_password_hash, check_password_hash   # для шифрования пароля

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://k3l:wrong_password@127.0.0.1:5432/my_first_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'my-super-secret-phrase-I-dont-tell-this-to-nobody'
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    login = StringField("Логин", [DataRequired(message="Поле логин не может быть пустым")])
    password = StringField("Пароль", [DataRequired(message="Поле пароль не может быть пустым")])


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)

    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def password_valid(self, password):
        return check_password_hash(self.password_hash, password)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect("/")

    form = LoginForm()

    if request.method == "POST":
        print(form.login.data)
        print(form.password.data)

        if not form.validate():
            print("INVALID")
            print(form.errors)
            return render_template("login_page.html", form=form)

        print("I WORK")
        user = User.query.filter_by(login=form.login.data).first()
        if user and user.password_valid(form.password.data):
            session["user"] = {
                "id": user.id,
                "username": user.login,
            }
            return redirect("/")

      #  form.login.errors.append("Не верное имя или пароль")

    return render_template("login_page.html", form=form)


@app.route('/logout')
@login_required
def logout():
    session.pop("user")
    return redirect("/login")


@app.route("/")
@login_required
def index():
    return "Добро пожаловать"


@app.route("/registration", methods=["GET", "POST"])
def registration():
    form = LoginForm()

    if request.method == "POST":
        print("POST")
        print(form.login.data)
        print(form.password.data)
        if not form.validate():
            print("INVALID")
            return render_template("reg_page.html", form=form)

        user = User.query.filter_by(login=form.login.data).first()
        if user:
            form.login.errors.append("Пользователь с таким именем уже существует")
            return render_template("reg_page.html", form=form)

        print("CREATE USER")
        user = User()
        user.login = form.login.data
        user.password(form.password.data)
        db.session.add(user)
        print(user.id)
        db.session.commit()
        print(user.id)

        return redirect("/registration")

    return render_template("reg_page.html", form=form)


app.run("0.0.0.0", "8000", True, ssl_context='adhoc')



# todo
#  удалить бд
#  создать класс юзера
#  создать форму (с правильными ограничениями и ошибками)
#  понять, какого размера должна быть таблица, если я собираюсь хранить пароль в виде хэша
#  создать шаблон
#  создать бд
#  сделать реализацию с помощью либы
#  создать роут
#  заполнить бд тестовыми значениями
#  создать сессию
# сделать реализацию с помощью md5 (на всякий случай)
# сделать красивую архитектуру
# сделать красивый фронт
# узнать, как хранить секретные данные
# сдклать requirements.txt


