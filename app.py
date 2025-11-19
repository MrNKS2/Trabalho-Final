from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email
from db import db
from models import Usuario

app = Flask(__name__)
app.config["SECRET_KEY"] = "segredo"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "entrar"

@login_manager.user_loader
def load_user(usuario_id):
    return Usuario.query.get(int(usuario_id))


class FormRegistro(FlaskForm):
    nome_usuario = StringField("Nome de usuário", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    telefone = StringField("Telefone", validators=[DataRequired()])
    senha = PasswordField("Senha", validators=[DataRequired()])
    confirmar_senha = PasswordField("Confirmar senha", validators=[DataRequired(), EqualTo("senha")])
    enviar = SubmitField("Registrar")


class FormLogin(FlaskForm):
    nome_usuario = StringField("Nome de usuário ou email", validators=[DataRequired()])
    senha = PasswordField("Senha", validators=[DataRequired()])
    entrar = SubmitField("Entrar")


@app.route("/Registrar", methods=["GET", "POST"])
def registrar():
    form = FormRegistro()

    if form.validate_on_submit():
        senha_hash = bcrypt.generate_password_hash(form.senha.data).decode("utf-8")

        novo_usuario = Usuario(
            nome_usuario=form.nome_usuario.data,
            email=form.email.data,
            telefone=form.telefone.data,
            senha=senha_hash
        )

        db.session.add(novo_usuario)
        db.session.commit()

        flash("Conta criada com sucesso!", "sucesso")
        return redirect(url_for("entrar"))

    return render_template("registrar.html", form=form)


@app.route("/Entrar", methods=["GET", "POST"])
def entrar():
    form = FormLogin()

    if form.validate_on_submit():
        usuario = Usuario.query.filter(
            (Usuario.nome_usuario == form.nome_usuario.data) |
            (Usuario.email == form.nome_usuario.data)
        ).first()

        if usuario and bcrypt.check_password_hash(usuario.senha, form.senha.data):
            login_user(usuario)
            return redirect(url_for("inicio"))
        else:
            flash("Dados incorretos", "erro")

    return render_template("entrar.html", form=form)


@app.route("/inicio")
@login_required
def inicio():
    return render_template("inicio.html", nome=current_user.nome_usuario)


@app.route("/sair")
@login_required
def sair():
    logout_user()
    return redirect(url_for("entrar"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
