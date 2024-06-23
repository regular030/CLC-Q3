from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    replies = db.relationship('Reply', backref='submission', lazy=True)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)

@app.route('/')
def index():
    return render_template('form.html')

@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        username = request.form['username']
        title = request.form['title']
        content = request.form['content']
        new_submission = Submission(username=username, title=title, content=content)
        db.session.add(new_submission)
        db.session.commit()
        return redirect(url_for('submissions'))

@app.route('/submissions')
def submissions():
    all_submissions = Submission.query.all()
    return render_template('submissions.html', submissions=all_submissions)

@app.route('/submission/<int:submission_id>', methods=['GET', 'POST'])
def view_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if request.method == 'POST':
        content = request.form['content']
        new_reply = Reply(content=content, submission_id=submission_id)
        db.session.add(new_reply)
        db.session.commit()
        return redirect(url_for('view_submission', submission_id=submission_id))
    return render_template('view_submission.html', submission=submission)

@app.route('/reply/<int:submission_id>', methods=['GET', 'POST'])
def reply(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if request.method == 'POST':
        content = request.form['content']
        new_reply = Reply(content=content, submission_id=submission_id)
        db.session.add(new_reply)
        db.session.commit()
        return redirect(url_for('view_submission', submission_id=submission_id))
    return render_template('reply.html', submission=submission)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
