from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask.cli import AppGroup
import click
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)
admin_cli = AppGroup('admin')
app.cli.add_command(admin_cli)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    uid = db.Column(db.String(150), unique=True, nullable=False)
    banned = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(150), nullable=True)

    def ban_user(self):
        self.banned = True
        db.session.commit()

    def unban_user(self):
        self.banned = False
        db.session.commit()

class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)

    @classmethod
    def ban_ip(cls, ip_address):
        banned_ip = cls(ip_address=ip_address)
        db.session.add(banned_ip)
        db.session.commit()

    @classmethod
    def unban_ip(cls, ip_address):
        banned_ip = cls.query.filter_by(ip_address=ip_address).first()
        if banned_ip:
            db.session.delete(banned_ip)
            db.session.commit()

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_anonymous = db.Column(db.Boolean, default=False)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)


# Helper Functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        # Check if the logged-in user is banned
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user and user.banned:
                flash('Your account has been banned.', 'error')
                return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        uid = request.form.get('uid')
        user = User.query.filter_by(uid=uid).first()

        if user:
            # Delete the user
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.username} (UID: {user.uid}) has been deleted successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(f'User with UID {uid} not found.', 'error')

    # Fetch all users (example for displaying in the admin dashboard)
    users = User.query.paginate(per_page=10)  # Example pagination for demonstration

    return render_template('admin_dashboard.html', users=users)

@app.route('/delete_user', methods=['POST'])
def delete_user():
    user_uid = request.form.get('user_uid')
    user = User.query.filter_by(uid=user_uid).first()

    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} (UID: {user.uid}) has been deleted successfully.', 'success')
    else:
        flash(f'User with UID {user_uid} not found.', 'error')

    return redirect(url_for('admin_dashboard'))

# CLI Command for Admin
@admin_cli.command('grant_admin')
@click.argument('uid', type=str)
def grant_admin(uid):
    user = User.query.filter_by(uid=uid).first()
    if user:
        user.role = 'admin'
        db.session.commit()
        print(f"User {user.username} (UID: {user.uid}) has been granted admin privileges.")
    else:
        print("User not found.")

@app.route('/delete_form', methods=['POST'])
@admin_required
def delete_form():
    form_id = request.form.get('form_id')
    form = Submission.query.get(form_id)
    if form:
        db.session.delete(form)
        db.session.commit()
        flash(f"Form ID {form_id} has been deleted.")
    else:
        flash("Form not found.")
    return redirect(url_for('admin_dashboard'))

@app.route('/ban_user', methods=['POST'])
@admin_required
def ban_user():
    user_uid = request.form.get('user_uid')
    user = User.query.filter_by(uid=user_uid).first()
    if user:
        user.ban_user()
        flash(f"User {user.username} (UID: {user.uid}) has been banned.")
    else:
        flash("User not found.")
    return redirect(url_for('admin_dashboard'))

@app.route('/unban_user', methods=['POST'])
@admin_required
def unban_user():
    user_uid = request.form.get('user_uid')
    user = User.query.filter_by(uid=user_uid).first()
    if user:
        user.unban_user()
        flash(f"User {user.username} (UID: {user.uid}) has been unbanned.")
    else:
        flash("User not found.")
    return redirect(url_for('admin_dashboard'))

@app.route('/ban_ip', methods=['POST'])
@admin_required
def ban_ip():
    ip_address = request.form.get('ip_address')
    BannedIP.ban_ip(ip_address)
    flash(f"IP Address {ip_address} has been banned.")
    return redirect(url_for('admin_dashboard'))

@app.route('/unban_ip', methods=['POST'])
@admin_required
def unban_ip():
    ip_address = request.form.get('ip_address')
    BannedIP.unban_ip(ip_address)
    flash(f"IP Address {ip_address} has been unbanned.")
    return redirect(url_for('admin_dashboard'))

@app.route('/search_user', methods=['POST'])
@admin_required
def search_user():
    username = request.form.get('username')
    users = User.query.filter(User.username.like(f'%{username}%')).paginate(page=1, per_page=10)
    return render_template('admin_dashboard.html', users=users, username=username)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Login failed. Username does not exist.")
            return redirect(url_for('login'))

        elif user.banned:
            flash("Your account has been banned.")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash("Login failed. Incorrect password.")
            return redirect(url_for('login'))

        else:
            session['logged_in'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f"Welcome back, {user.username}!")
            return redirect(url_for('submissions'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')  # default to 'user' if role is not provided

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        # If the username does not exist, proceed with the registration
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, password=hashed_password, role=role, uid=str(uuid.uuid4()), banned=False)

        db.session.add(new_user)
        try:
            db.session.commit()
            flash('You have successfully registered! You can now log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/submissions')
@login_required
def submissions():
    all_submissions = Submission.query.order_by(Submission.id.desc()).all()
    user_submissions = Submission.query.filter_by(username=session.get('username')).order_by(Submission.id.desc()).limit(5).all()
    user_replies = Reply.query.filter_by(username=session.get('username')).order_by(Reply.id.desc()).limit(5).all()
    
    # Filter out submissions with None IDs
    all_submissions = [submission for submission in all_submissions if submission.id is not None]
    
    # Fetch actual submission objects for replied forms
    replied_to_forms = [Submission.query.get(reply.submission_id) for reply in user_replies if reply.submission_id is not None]
    
    return render_template('submissions.html', submissions=all_submissions, forms_you_own=user_submissions, replied_to_forms=replied_to_forms)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_anonymous = 'anonymous' in request.form
        user_id = session.get('user_id')

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
        user_id = session.get('user_id')
        user = User.query.get(user_id)

        if user:
            new_reply = Reply(
                content=content,
                user_id=user.id,
                submission_id=submission.id,
                username=user.username
            )
            db.session.add(new_reply)
            db.session.commit()
            flash('Reply added successfully.')
            return redirect(url_for('view_submission', submission_id=submission_id))
        else:
            flash('User not found. Please log in again.')
            return redirect(url_for('login'))

    replies = Reply.query.filter_by(submission_id=submission.id).order_by(Reply.id.desc()).all()
    return render_template('view_submission.html', submission=submission, replies=replies)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def get_user(username):
    return User.query.filter_by(username=username).first()

@app.route('/uid')
def show_uuid():
    username = session.get('username')
    if username:
        user = get_user(username)
        if user:
            return jsonify({'username': username, 'uuid': user.uid})
        else:
            return jsonify({'error': 'User not found'}), 404
    return jsonify({'error': 'User session not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
