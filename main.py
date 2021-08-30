from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SECRET_KEY'] = '\xfa y\xaf\x10\xd5P\x93\x91\x9cl\x10\x81JqT'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()  # create a login manager
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            password = request.form["password"]
            hash_password = generate_password_hash(password=password, method="pbkdf2:sha256",
                                                                     salt_length=8)
            new_user = User(name=request.form["name"], email=request.form["email"], password=hash_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return render_template("secrets.html", name=new_user.name)
        except IntegrityError:
            flash("Given email is already taken.")
            return redirect(url_for("register"))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        given_email = request.form.get("email")
        given_password = request.form.get("password")
        try:
            selected_user = User.query.filter_by(email=given_email).first()
            if check_password_hash(pwhash=selected_user.password, password=given_password):
                login_user(selected_user)
                flash('Logged in successfully.')
                return redirect(url_for("secrets"))
            else:
                flash("Invalid password.")
                return redirect(url_for("login"))
        except AttributeError:
            flash("Given email is not in the user data base.")
            return redirect(url_for("login"))
    else:
        return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory("static", filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
