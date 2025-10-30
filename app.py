from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime, timedelta
import json
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Create Flask app first
app = Flask(__name__)
app.secret_key = 'career-guider-secret-key-2025'
CORS(app, supports_credentials=True, origins=["http://localhost:5000", "http://127.0.0.1:5000"])
bcrypt = Bcrypt(app)

# MySQL configuration
db_config = {
    'host': 'localhost',
    'user': 'root', 
    'password': 'Prasad@4455',
    'database': 'career_guider'
}

# Gmail SMTP Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'chukkaharika47@gmail.com'    # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'ymxcpwprnytssyyq'       # Replace with Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'chukkaharika47@gmail.com'

class User:
    def __init__(self, id, email, first_name, last_name, education_level, interests, bio=None, profile_picture=None, member_since=None):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.education_level = education_level
        self.interests = interests
        self.bio = bio
        self.profile_picture = profile_picture
        self.member_since = member_since
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self.id)

def get_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def generate_otp(length=6):
    """Generate a random numeric OTP"""
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email, otp):
    """Send OTP to user's email using Gmail SMTP"""
    try:
        sender_email = app.config['MAIL_USERNAME']
        sender_password = app.config['MAIL_PASSWORD']
        
        # Create message
        message = MIMEMultipart()
        message['From'] = f"Career Guider <{sender_email}>"
        message['To'] = email
        message['Subject'] = 'Career Guider - Password Reset OTP'
        
        # Email body with better styling
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #4e73df, #224abe); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fc; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-code {{ background: #ffffff; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #4e73df; border: 2px dashed #4e73df; border-radius: 10px; margin: 20px 0; }}
                .footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 14px; }}
                .warning {{ background: #fff3cd; color: #856404; padding: 10px; border-radius: 5px; border-left: 4px solid #ffc107; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Career Guider</h1>
                    <h2>Password Reset Request</h2>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>You have requested to reset your password for your Career Guider account. Please use the following One-Time Password (OTP) to proceed:</p>
                    
                    <div class="otp-code">{otp}</div>
                    
                    <div class="warning">
                        <strong>Important:</strong> This OTP will expire in 10 minutes. Do not share this code with anyone.
                    </div>
                    
                    <p>If you didn't request this password reset, please ignore this email. Your account remains secure.</p>
                    
                    <div class="footer">
                        <p>Best regards,<br><strong>The Career Guider Team</strong></p>
                        <p>If you need assistance, please contact us at {sender_email}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        message.attach(MIMEText(body, 'html'))
        
        # Send email using Gmail SMTP
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.set_debuglevel(1)  # Enable debug output
        server.ehlo()
        server.starttls()
        server.ehlo()
        
        # Try login with better error handling
        try:
            server.login(sender_email, sender_password)
            print("✅ Successfully authenticated with Gmail")
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ Authentication failed: {e}")
            server.quit()
            return False
        
        server.sendmail(sender_email, email, message.as_string())
        server.quit()
        
        print(f"✅ OTP email sent successfully to {email}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("❌ SMTP Authentication failed. Check your Gmail credentials.")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ SMTP error occurred: {e}")
        return False
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

def test_email_configuration():
    """Test email configuration on startup"""
    try:
        print("📧 Testing email configuration...")
        
        # Test SMTP connection
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.quit()
        
        print("✅ Email configuration test passed!")
        return True
    except Exception as e:
        print(f"❌ Email configuration test failed: {e}")
        print("Please check your Gmail credentials and ensure:")
        print("1. 2-Factor Authentication is enabled")
        print("2. App Password is generated correctly")
        print("3. MAIL_USERNAME and MAIL_PASSWORD are set correctly")
        return False

def init_database():
    """Initialize database and create tables if they don't exist"""
    try:
        # First connect without database to create it
        temp_config = db_config.copy()
        temp_config.pop('database', None)
        connection = mysql.connector.connect(**temp_config)
        cursor = connection.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['database']}")
        cursor.close()
        connection.close()
        
        # Now connect to the database and create tables
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                education_level VARCHAR(50),
                interests JSON,
                bio TEXT,
                profile_picture TEXT,
                member_since TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        ''')
        
        # Create assessment_results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assessment_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                results JSON,
                completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create password_reset_tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                token VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        connection.commit()
        print("✅ Database initialized successfully!")
        
    except Error as e:
        print(f"❌ Error initializing database: {e}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

# Authentication Routes
@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        print("Registration data received:", data)  # Debug log
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        education_level = data.get('education_level', '')
        interests = data.get('interests', [])
        
        # Validation
        if not all([first_name, last_name, email, password, education_level]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor(dictionary=True)
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Insert new user
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, password_hash, education_level, interests)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (first_name, last_name, email, password_hash, education_level, json.dumps(interests)))
        
        connection.commit()
        user_id = cursor.lastrowid
        
        # Get the created user
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        # Create user object and store in session
        user = User(
            id=user_data['id'],
            email=user_data['email'],
            first_name=user_data['first_name'],
            last_name=user_data['last_name'],
            education_level=user_data['education_level'],
            interests=json.loads(user_data['interests']) if user_data['interests'] else []
        )
        
        session['user_id'] = user.id
        session['user_email'] = user.email
        
        return jsonify({
            'success': True, 
            'message': 'Registration successful!',
            'user': {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'education_level': user.education_level,
                'interests': user.interests,
                'member_since': user_data['member_since'].strftime('%B %Y') if user_data['member_since'] else 'Unknown'
            }
        }), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor(dictionary=True)
        
        # Find user by email
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        
        if not user_data:
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Check password
        if not bcrypt.check_password_hash(user_data['password_hash'], password):
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Update last login
        cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (datetime.now(), user_data['id']))
        connection.commit()
        
        # Parse interests
        interests = json.loads(user_data['interests']) if user_data['interests'] else []
        
        # Create user object and store in session
        user = User(
            id=user_data['id'],
            email=user_data['email'],
            first_name=user_data['first_name'],
            last_name=user_data['last_name'],
            education_level=user_data['education_level'],
            interests=interests,
            bio=user_data['bio'],
            profile_picture=user_data['profile_picture'],
            member_since=user_data['member_since']
        )
        
        session['user_id'] = user.id
        session['user_email'] = user.email
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'user': {
                'id': user_data['id'],
                'first_name': user_data['first_name'],
                'last_name': user_data['last_name'],
                'email': user_data['email'],
                'education_level': user_data['education_level'],
                'interests': interests,
                'bio': user_data['bio'],
                'profile_picture': user_data['profile_picture'],
                'member_since': user_data['member_since'].strftime('%B %Y') if user_data['member_since'] else None
            }
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'message': f'Login failed: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
def logout():
    if request.method == 'OPTIONS':
        return '', 200
        
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/user', methods=['GET'])
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        
        if not user_data:
            session.clear()
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        interests = json.loads(user_data['interests']) if user_data['interests'] else []
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'user': {
                'id': user_data['id'],
                'first_name': user_data['first_name'],
                'last_name': user_data['last_name'],
                'email': user_data['email'],
                'education_level': user_data['education_level'],
                'interests': interests,
                'bio': user_data['bio'],
                'profile_picture': user_data['profile_picture'],
                'member_since': user_data['member_since'].strftime('%B %Y') if user_data['member_since'] else None
            }
        })
        
    except Exception as e:
        print(f"Get user error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get user data'}), 500

@app.route('/api/update-profile', methods=['POST', 'OPTIONS'])
def update_profile():
    if request.method == 'OPTIONS':
        return '', 200
        
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        education_level = data.get('education_level', '')
        interests = data.get('interests', [])
        bio = data.get('bio', '')
        
        if not all([first_name, last_name, education_level]):
            return jsonify({'success': False, 'message': 'First name, last name, and education level are required'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET first_name = %s, last_name = %s, education_level = %s, interests = %s, bio = %s
            WHERE id = %s
        ''', (first_name, last_name, education_level, json.dumps(interests), bio, user_id))
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return jsonify({'success': True, 'message': 'Profile updated successfully!'})
        
    except Exception as e:
        print(f"Profile update error: {e}")
        return jsonify({'success': False, 'message': 'Profile update failed'}), 500

# Forgot Password Routes
@app.route('/api/forgot-password', methods=['POST', 'OPTIONS'])
def forgot_password():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor(dictionary=True)
        
        # Check if user exists
        cursor.execute("SELECT id, first_name, email FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            connection.close()
            # For security, don't reveal if email exists or not
            return jsonify({'success': True, 'message': 'If an account with this email exists, an OTP has been sent.'})
        
        # Generate OTP
        otp = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        
        # Delete any existing unused OTPs for this user
        cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = %s AND used = FALSE", (user['id'],))
        
        # Store new OTP
        cursor.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
            (user['id'], otp, expires_at)
        )
        
        connection.commit()
        cursor.close()
        connection.close()
        
        # Send OTP via email
        if send_otp_email(user['email'], otp):
            return jsonify({
                'success': True, 
                'message': 'OTP has been sent to your email address.',
                'user_id': user['id']
            })
        else:
            return jsonify({
                'success': False, 
                'message': 'Failed to send OTP. Please check your email configuration or try again later.'
            }), 500
            
    except Exception as e:
        print(f"❌ Forgot password error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'}), 500

@app.route('/api/verify-otp', methods=['POST', 'OPTIONS'])
def verify_otp():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        otp = data.get('otp', '').strip()
        
        if not user_id or not otp:
            return jsonify({'success': False, 'message': 'User ID and OTP are required'}), 400
        
        if len(otp) != 6 or not otp.isdigit():
            return jsonify({'success': False, 'message': 'OTP must be a 6-digit number'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor(dictionary=True)
        
        # Verify OTP
        cursor.execute('''
            SELECT * FROM password_reset_tokens 
            WHERE user_id = %s AND token = %s AND used = FALSE AND expires_at > %s
        ''', (user_id, otp, datetime.now()))
        
        token_record = cursor.fetchone()
        
        if not token_record:
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'message': 'Invalid or expired OTP. Please request a new one.'}), 400
        
        # Mark OTP as used
        cursor.execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE id = %s",
            (token_record['id'],)
        )
        
        connection.commit()
        cursor.close()
        connection.close()
        
        # Generate a simple reset token (in production, use JWT or similar)
        reset_token = f"reset_{user_id}_{int(datetime.now().timestamp())}"
        
        return jsonify({
            'success': True, 
            'message': 'OTP verified successfully',
            'reset_token': reset_token
        })
        
    except Exception as e:
        print(f"❌ Verify OTP error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'}), 500

@app.route('/api/reset-password', methods=['POST', 'OPTIONS'])
def reset_password():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        reset_token = data.get('reset_token')
        new_password = data.get('new_password')
        
        if not all([user_id, reset_token, new_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'}), 400
        
        # Basic token validation
        if not reset_token.startswith(f"reset_{user_id}_"):
            return jsonify({'success': False, 'message': 'Invalid reset token'}), 400
        
        # Check if token is not too old (1 hour)
        try:
            token_timestamp = int(reset_token.split('_')[2])
            token_time = datetime.fromtimestamp(token_timestamp)
            if datetime.now() - token_time > timedelta(hours=1):
                return jsonify({'success': False, 'message': 'Reset token has expired'}), 400
        except (IndexError, ValueError):
            return jsonify({'success': False, 'message': 'Invalid reset token format'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = connection.cursor()
        
        # Hash new password
        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Update password
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (password_hash, user_id)
        )
        
        # Delete all used tokens for this user
        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = %s AND used = TRUE",
            (user_id,)
        )
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True, 
            'message': 'Password reset successfully! You can now login with your new password.'
        })
        
    except Exception as e:
        print(f"❌ Reset password error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'}), 500

# Add a test email route to verify configuration
@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Test endpoint to verify email configuration"""
    try:
        data = request.get_json()
        test_email = data.get('email', app.config['MAIL_USERNAME'])
        
        if send_otp_email(test_email, '123456'):
            return jsonify({'success': True, 'message': 'Test email sent successfully!'})
        else:
            return jsonify({'success': False, 'message': 'Failed to send test email'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Serve main application
@app.route('/')
def index():
    return render_template('index.html')

# Quiz routes (keep your existing routes)
@app.route('/eng_quiz')
def eng_quiz():
    return render_template('eng_quiz.html')
    
@app.route('/med_quiz')
def med_quiz():
    return render_template('med_quiz.html')
    
@app.route('/law_quiz')
def law_quiz():
    return render_template('law_quiz.html')
    
@app.route('/def_quiz')
def def_quiz():
    return render_template('def_quiz.html')
    
@app.route('/agr_quiz')
def agr_quiz():
    return render_template('agr_quiz.html')
    
@app.route('/spo_quiz')
def spo_quiz():
    return render_template('spo_quiz.html')
    
@app.route('/ent_quiz')
def ent_quiz():
    return render_template('ent_quiz.html')
    
@app.route('/aca_quiz')
def aca_quiz():
    return render_template('aca_quiz.html')
    
# Serve guidance pages (keep your existing routes)
@app.route('/law1')
def law_guidance1():
    return render_template('law1.html')
    
@app.route('/law2')
def law_guidance2():
    return render_template('law2.html')
    
@app.route('/eng1')
def eng_guidance1():
    return render_template('eng1.html')
    
@app.route('/eng2')
def eng_guidance2():
    return render_template('eng2.html')
    
@app.route('/med1')
def med_guidance1():
    return render_template('med1.html')
    
@app.route('/med2')
def med_guidance2():
    return render_template('med2.html')
    
@app.route('/def1')
def def_guidance1():
    return render_template('def1.html')
    
@app.route('/def2')
def def_guidance2():
    return render_template('def2.html')
    
@app.route('/agr1')
def agr_guidance1():
    return render_template('agr1.html')
    
@app.route('/agr2')
def agr_guidance2():
    return render_template('agr2.html')
    
@app.route('/spo1')
def spo_guidance1():
    return render_template('spo1.html')
    
@app.route('/spo2')
def spo_guidance2():
    return render_template('spo2.html')
    
@app.route('/ent1')
def ent_guidance1():
    return render_template('ent1.html')
    
@app.route('/ent2')
def ent_guidance2():
    return render_template('ent2.html')
    
@app.route('/aca1')
def aca_guidance1():
    return render_template('aca1.html')
    
@app.route('/aca2')
def aca_guidance2():
    return render_template('aca2.html')
    
if __name__ == '__main__':
    try:
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        print(f"✅ Template path: {template_path}")
        if os.path.exists(template_path):
            print(f"✅ Templates folder exists with {len(os.listdir(template_path))} files")
        else:
            print("❌ Templates folder not found!")
    except Exception as e:
        print(f"⚠️ Path check error: {e}")
    # Initialize database before starting the app
    init_database()
    
    # Test email configuration
    test_email_configuration()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
