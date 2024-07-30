import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import logging
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer
import pyotp

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploaded_videos'
app.config['ALERTS_FILE'] = 'alerts.json'
app.config['PREVIOUS_ACCIDENTS_FOLDER'] = 'static/accidents'
app.config['GRAPH_FOLDER'] = 'static/graphs'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PREVIOUS_ACCIDENTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['GRAPH_FOLDER'], exist_ok=True)

if not os.path.exists(app.config['ALERTS_FILE']):
    with open(app.config['ALERTS_FILE'], 'w') as f:
        json.dump([], f)

db = SQLAlchemy(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define a user model
class User(db.Model, UserMixin):
    __tablename__ = 'user'  # Explicitly defining the table name
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32())
    is_admin = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True, unique=True)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

# Create the database tables and ensure reset_token column exists
with app.app_context():
    db.create_all()

    # Initialize admin (example)
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(email='admin@example.com', password=generate_password_hash('adminpassword'), is_admin=True)
        db.session.add(admin)
        db.session.commit()

    # Ensure the reset_token column exists
    with db.engine.connect() as conn:
        result = conn.execute(text("PRAGMA table_info(user)"))
        columns = [row[1] for row in result]  # row[1] is the column name in PRAGMA table_info output
        if 'reset_token' not in columns:
            conn.execute(text('ALTER TABLE user ADD COLUMN reset_token VARCHAR(100)'))

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Simple OTP generation and verification functions
def generate_otp(user):
    totp = pyotp.TOTP(user.otp_secret)
    return totp.now()

def verify_otp(user, otp_entered):
    totp = pyotp.TOTP(user.otp_secret)
    return totp.verify(otp_entered)

# Function to send email
def send_email(subject, body, to_email):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = os.getenv('EMAIL_USER')
    password = os.getenv('EMAIL_PASS')

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, to_email, msg.as_string())
        logging.info("Email sent successfully")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Routes
@app.route('/')
def index():
    # Your index route logic
    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email address is required.')
            return redirect(url_for('forgot_password'))
        
        user = User.query.filter_by(email=email).first()
        logging.debug(f"User found: {user}")
        if user:
            serializer = URLSafeSerializer(app.secret_key)
            reset_token = serializer.dumps(user.id)
            user.reset_token = reset_token
            db.session.commit()
            
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            send_email('Password Reset Request', f'Please click the link to reset your password: {reset_url}', user.email)
            flash('Password reset instructions sent to your email.')
        else:
            flash('Email not found.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = URLSafeSerializer(app.secret_key)
    
    try:
        user_id = serializer.loads(token)
    except Exception as e:
        app.logger.error(f"Failed to load token: {e}")
        flash('The token is invalid or expired.')
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    
    if not user or user.reset_token != token:
        flash('Invalid token.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        
        if not new_password:
            flash('New password is required.')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(new_password)
        
        # Update user's password and clear reset_token
        user.password = hashed_password
        user.reset_token = None
        db.session.commit()
        
        flash('Password reset successfully. Please log in with your new password.')
        return redirect(url_for('login'))  # Redirect to login after successful password reset
    
    return render_template('reset_password.html', token=token)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required.')
            return redirect(url_for('register'))
        
        # Check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.')
            return redirect(url_for('login'))
        
        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if not email or not password:
            flash('Email and password are required.')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.verify_password(password):
            otp = generate_otp(user)
            logging.debug(f"Generated OTP: {otp}")
            send_email("Your OTP Code", f"Your OTP code is {otp}", user.email)
            return redirect(url_for('otp_verification', user_id=user.id))
        
        flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/otp_verification/<int:user_id>', methods=['GET', 'POST'])
def otp_verification(user_id):
    user = load_user(user_id)
    
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_entered = request.form['otp']
        
        if not otp_entered:
            flash('OTP is required.')
            return redirect(url_for('otp_verification', user_id=user_id))
        
        if verify_otp(user, otp_entered):
            login_user(user)
            flash('Logged in successfully.')
            if user.is_admin:
                return redirect(url_for('admin_home'))
            else:
                return redirect(url_for('service_page'))
        else:
            flash('Invalid OTP. Please try again.')

    return render_template('otp_verification.html', user_id=user_id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/service_page')
@login_required
def service_page():
    if current_user.is_admin:
        return redirect(url_for('admin_home'))
    return render_template('service_page.html')

@app.route('/admin_home')
@login_required
def admin_home():
    if not current_user.is_admin:
        return redirect(url_for('service_page'))
    return render_template('admin_home.html')

# Error handlers
@app.errorhandler(400)
def bad_request_error(e):
    return render_template('error.html'), 400

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
