from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError
from db import db
from models import Usuario

app = Flask(__name__)

app.config["SECRET_KEY"] = "segredo"  # trocar assim que der
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(usuario_id):
    return Usuario.query.get(int(usuario_id))


class FormRegistro(FlaskForm):
    nome_usuario = StringField("Nome de usuário", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email(message="Digite um email válido!")])
    telefone = StringField("Telefone", validators=[DataRequired()])
    senha = PasswordField("Senha", validators=[DataRequired()])
    confirmar_senha = PasswordField("Confirmar senha", validators=[DataRequired(), EqualTo("senha", message="As senhas devem coincidir!")])
    enviar = SubmitField("Registrar")

    def validate_email(self, campo_email):
        existente = Usuario.query.filter_by(email=campo_email.data).first()
        if existente:
            raise ValidationError("Esse email já está registrado!")

    def validate_nome_usuario(self, campo_nome):
        existente = Usuario.query.filter_by(nome_usuario=campo_nome.data).first()
        if existente:
            raise ValidationError("Esse nome de usuário já está em uso!")


class FormLogin(FlaskForm):
    nome_usuario = StringField("Nome de usuário ou email", validators=[DataRequired()])
    senha = PasswordField("Senha", validators=[DataRequired()])
    entrar = SubmitField("Entrar")


@app.route("/login", methods=["GET", "POST"])
def login():
    form_login = FormLogin()
    form_registro = FormRegistro()

    if form_login.entrar.data and form_login.validate_on_submit():

        entrada = form_login.nome_usuario.data.strip()

        usuario = Usuario.query.filter(
            (Usuario.nome_usuario == entrada) | (Usuario.email == entrada)
        ).first()

        if usuario and bcrypt.check_password_hash(usuario.senha, form_login.senha.data):
            login_user(usuario)
            return redirect(url_for("inicio"))
        else:
            flash("Login incorreto!", "erro")


    if form_registro.enviar.data and form_registro.validate_on_submit():

        senha_hash = bcrypt.generate_password_hash(form_registro.senha.data).decode("utf-8")

        novo_usuario = Usuario(
            nome_usuario=form_registro.nome_usuario.data.strip(),
            email=form_registro.email.data.strip().lower(),
            telefone=form_registro.telefone.data,
            senha=senha_hash
        )

        db.session.add(novo_usuario)
        db.session.commit()

        flash("Conta criada com sucesso!", "sucesso")
        return redirect(url_for("login"))

    return render_template("login.html", form_login=form_login, form_registro=form_registro)


@app.route("/inicio")
@login_required
def inicio():
    return render_template("inicio.html", nome=current_user.nome_usuario)


@app.route("/sair")
@login_required
def sair():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
