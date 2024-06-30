from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

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
    is_anonymous = db.Column(db.Boolean, default=False)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submission = db.relationship('Submission', backref=db.backref('replies', lazy=True))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def home():
    return redirect(url_for('submissions'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Login failed. Username does not exist.")
        elif not check_password_hash(user.password, password):
            flash("Login failed. Incorrect password.")
        else:
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f"Welcome back, {user.username}!")
            return redirect(url_for('submissions'))  # Redirect to another page after successful login

        return redirect(url_for('login'))  # Redirect to login page after failed login attempt

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
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/submissions')
@login_required
def submissions():
    all_submissions = Submission.query.order_by(Submission.id.desc()).all()
    user_submissions = Submission.query.filter_by(username=session.get('username')).order_by(Submission.id.desc()).limit(5).all()
    user_replies = Reply.query.filter_by(username=session.get('username')).order_by(Reply.id.desc()).limit(5).all()
    replied_to_forms = [Submission.query.get(reply.submission_id) for reply in user_replies]
    return render_template('submissions.html', submissions=all_submissions, forms_you_own=user_submissions, replied_to_forms=replied_to_forms)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_anonymous = 'anonymous' in request.form
        user_id = session.get('user_id')
        
        # Ensure user_id exists in session and is valid
        if user_id:
            user = User.query.get(user_id)
            if user:
                new_submission = Submission(
                    username=user.username if not is_anonymous else 'Anonymous',
                    title=title,
                    content=content,
                    is_anonymous=is_anonymous
                )
                db.session.add(new_submission)
                db.session.commit()
                flash('Submission created successfully.')
                return redirect(url_for('submissions'))
            else:
                flash('User not found. Please log in again.')
                return redirect(url_for('login'))
        else:
            flash('User session not found. Please log in again.')
            return redirect(url_for('login'))

    return render_template('form.html')


@app.route('/submission/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def view_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if request.method == 'POST':
        content = request.form['content']
        user_id = session['user_id']
        user = User.query.get(user_id)
        new_reply = Reply(submission_id=submission_id, username=user.username, content=content)
        db.session.add(new_reply)
        db.session.commit()
        flash('Reply posted successfully.')
    return render_template('view_submission.html', submission=submission)

@app.context_processor
def inject_forms():
    if 'user_id' in session:
        user_submissions = Submission.query.filter_by(username=session.get('username')).order_by(Submission.id.desc()).limit(5).all()
        user_replies = Reply.query.filter_by(username=session.get('username')).order_by(Reply.id.desc()).limit(5).all()
        replied_to_forms = [Submission.query.get(reply.submission_id) for reply in user_replies]
        return dict(forms_you_own=user_submissions, replied_to_forms=replied_to_forms)
    return dict(forms_you_own=[], replied_to_forms=[])

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
