from flask import Flask, redirect, g, url_for, render_template, request, session, flash
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_sqlalchemy import SQLAlchemy
from second import second
from forms import RegisterForm, LoginForm, ResetRequestForm, ResetPasswordForm
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, InputRequired, Length, Email, EqualTo
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user 


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.register_blueprint(second, url_prefix="/admin")
app.secret_key = "hello"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(minutes=20)




db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 



app.config["SECRET_KEY"] = 'hello'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'groupsamine@gmail.com'
app.config['MAIL_PASSWORD'] = 'StudyGroup123'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


mail=Mail(app) 



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)


    def get_token(self,expires_sec=300):
        serial=Serializer(app.config['SECRET_KEY'], expires_in=expires_sec)
        return serial.dumps({'user_id':self.id}).decode('utf-8')
    
    @staticmethod
    def verify_token(token):
        serial=Serializer(app.config['SECRET_KEY'])
        try:
            user_id=serial.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)



    def __repr__(self):
        return f"User('{self.id}','{self.username}', '{self.email}', '{self.password}')"
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text,nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


@app.route('/reset_password',methods=['GET','POST'])
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_mail(user)
            flash("Reset request sent. check your mail")
            return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Request', form=form)



@app.route('/login', methods=['GET','POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashbord'))

        flash("invalid username or password")
        #return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)


        #return '<h1>'+ form.username.data +' '+ form.password.data + '</h1>'

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user=User.verify_token(token)
    if user is None:
        flash('That is invalid token or expired. Please try again.')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user.password=hashed_password
        db.session.commit()
        flash('Password chaged! Please login!')
        return redirect(url_for('login'))
    return render_template('change_password.html', form=form)








@app.route('/dashbord')
@login_required
def dashbord():
    return render_template('Dashio/index.html', name=current_user.username)
#tu peux ajouter ici là haut, à coté du Dashio/index.html, name=current_user.username;
#pour après dans le code du dashbord tu mets {{ name }} pour afficher le nom du User.


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("user has been created")
    

    return render_template('signup.html', form=form)


#@app.route("/admin")
    #return redirect(url_for("admin", name= "admin!"))




    



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))




def send_mail(user):
    token=user.get_token()
    
    msg=Message('Password Reset Request', recipients=[user.email], sender='noreply@aminejh.com')
    msg.body=f''' To reset your password, Please follow the link below.


    {url_for('reset_token', token=token,_external=True)}

    If you didn't send a password reset request. Please ignore this message.


    '''
    mail.send(msg)
    


















'''
class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(80))

    

class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User: {self.username}>'

users = []
users.append(User(id=1, username='Anthony', password='password'))
users.append(User(id=2, username='Becca', password='secret'))
users.append(User(id=3, username='Carlos', password='somethingsimple'))


@app.before_request
def before_request():


    g.user = None

    if 'user_id' in session:
        user = [x for x in users if x.id == session['user_id']][0]
        g.user = user



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.pop('user_id', None)

        username = request.form['username']
        password = request.form['password']
        
        user = [x for x in users if x.username == username][0]
        if user and user.password == password:
            session['user_id'] = user.id
            flash("login Succesful!")
            return redirect(url_for('profile'))

        return redirect(url_for('login'))

    return render_template('login.html')
        
'''



'''
@app.route('/voir')
def voir():
    return render_template("voir.html", values=users.query.all())

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        session.permanent = True
        user = request.form["nm"]
        session["user"] = user
         #pour supprimer des infos de la base de donnée au lieu de faire .first() = .delete()
        found_user = users.query.filter_by(name=user).first()
        # et la mettez:
       # for user in found_user:
        #    user.delete()
        if found_user:
            session["email"] = found_user.email
        else:
            usr = users(user, "")
            db.session.add(usr)
            db.session.commit() 


        flash("login Succesful!")
        return redirect(url_for("user"))
    else:
        if "user" in session:
            flash("Already Logged!")
            return redirect(url_for("user"))

        return render_template("login.html")



@app.route("/user", methods=["POST","GET"])
def user():
    email = None
    if "user" in session:
        user = session["user"]
        if request.method == "POST":
            email = request.form["email"]
            session["email"] = email            
            found_user = users.query.filter_by(name=user).first()
            found_user.email = email
            db.session.commit()
            flash("email was saved!")
        else:
            if "email" in session:
                email = session["email"]
        return render_template("user.html", email=email)
    else:
        flash("You are not logged in!")
        return redirect(url_for("login"))




@app.route("/logout")
def logout():
    if "user" in session:
        user = session["user"] 
        flash(f"You have been logged out!!, {user}", "info")   
    session.pop("user", None)
    session.pop("email", None)
    flash("for login")
    return redirect(url_for("login"))

'''

#def test():
#    return render_template("new.html")
#
#@app.route('/teest')
#def test():
#    return "hi man you're waw"
#def user(name):

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)