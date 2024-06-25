from flask import Flask
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submission = db.relationship('Submission', backref=db.backref('replies', lazy=True))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('submissions'))
        else:
            return "Login Failed. Please check your username and password."
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/submissions')
def submissions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    all_submissions = Submission.query.all()
    return render_template('submissions.html', submissions=all_submissions)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']
        user = User.query.get(user_id)
        new_submission = Submission(username=user.username, title=title, content=content)
        db.session.add(new_submission)
        db.session.commit()
        return redirect(url_for('submissions'))
    return render_template('form.html')

@app.route('/submission/<int:submission_id>', methods=['GET', 'POST'])
def view_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if request.method == 'POST':
        content = request.form['content']
        user_id = session['user_id']
        user = User.query.get(user_id)
        new_reply = Reply(submission_id=submission_id, username=user.username, content=content)
        db.session.add(new_reply)
        db.session.commit()
    return render_template('view_submission.html', submission=submission)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
