from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import jwt
import datetime
import config
import pytz
import logging
import uuid
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
import config

# Custom filter to suppress Werkzeug HTTP request logs
class NoWerkzeugFilter(logging.Filter):
    def filter(self, record):
        return not (record.name.startswith('werkzeug') or '_internal.py' in record.pathname)

# Configure logging with simplified format
logging.basicConfig(
    filename='flask.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Apply filter to suppress Werkzeug logs
for handler in logging.getLogger().handlers:
    handler.addFilter(NoWerkzeugFilter())

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# MySQL configurations
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB

mysql = MySQL(app)

# JWT secret key
JWT_SECRET = config.JWT_SECRET

# Email configuration
EMAIL_CONFIG = {
    'SMTP_SERVER': config.SMTP_SERVER,
    'SMTP_PORT': config.SMTP_PORT,
    'SENDER_EMAIL': config.SENDER_EMAIL,
    'SENDER_PASSWORD': config.SENDER_PASSWORD
}

# Enable CORS for Streamlit app domains
CORS(app, resources={
    r"/auth/validate_and_details": {"origins": ["https://mis.agkit.in", 
    "https://mis.agkit.in/team_dashboard",
    "https://mis.agkit.in/ijisem"
    "http://127.0.0.1:8504"]},

    r"/logout": {"origins": ["https://mis.agkit.in",
                              "http://127.0.0.1:8504"]},
                              
    r"/forgot_password": {"origins": ["*"]},
    r"/reset_password": {"origins": ["*"]}
})

# App-based redirect URLs
APP_REDIRECTS={"main": "https://mis.agkit.in", 
               "operations": "https://mis.agkit.in/team_dashboard", 
               "admin": "https://mis.agkit.in", 
               "tasks": "https://mis.agkit.in/tasks",
               "ijisem": "https://mis.agkit.in/ijisem"}

# APP_REDIRECTS={"main": "http://localhost:8501", 
#                 "operations": "http://localhost:8501/team_dashboard", 
#                 "admin": "http://localhost:8501", 
#                 "tasks": "http://localhost:8501/tasks",
#                 "ijisem": "http://localhost:8501/ijisem"}


TOKEN_BLACKLIST = set()
PASSWORD_RESET_TOKENS = {}

@app.route('/')
def index():
    logger.info(f"User accessed root endpoint, session email: {session.get('email', 'None')}")
    if 'email' in session:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        logger.info(f"Trying to login with email: {email}")
        
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, email, password, username, role FROM userss WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            
            if user and user[2] == password:  # Note: In production, use proper password hashing
                session['email'] = user[1]
                session['login_time'] = datetime.now(timezone.utc).isoformat()
                logger.info(f"User {user[3]} logged in successfully, role: {user[4]}")
                
                cur = mysql.connection.cursor()
                cur.execute("""
                    SELECT u.role, uaa.app, uaa.access_type, uaa.level, uaa.start_date, uaa.report_to
                    FROM userss u
                    LEFT JOIN user_app_access uaa ON u.id = uaa.user_id
                    WHERE u.id = %s
                """, (user[0],))
                user_details = cur.fetchall()
                cur.close()
                
                role = user[4].lower()
                app = user_details[0][1].lower() if user_details[0][1] else ''
                
                if role == 'user':
                    ist = pytz.timezone('Asia/Kolkata')
                    current_time = datetime.now(ist)
                    current_hour = current_time.hour
                    if not (9 <= current_hour < 18):
                        logger.warning(f"Login denied for {email}: Outside allowed hours (current hour: {current_hour})")
                        flash('Users can only log in between 9 AM and 6 PM IST', 'error')
                        return redirect(url_for('login'))
                
                token_payload = {
                    'user_id': user[0],
                    'exp': datetime.now(timezone.utc) + timedelta(minutes=60 * 4)
                }
                token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
                
                if role == 'admin':
                    redirect_url = f"{APP_REDIRECTS['admin']}?token={token}"
                else:
                    if app and app in APP_REDIRECTS:
                        redirect_url = f"{APP_REDIRECTS[app]}?token={token}"
                    else:
                        logger.error(f"Invalid app configuration for user {user[3]}, app: {app}")
                        flash('Invalid app configuration', 'error')
                        return redirect(url_for('login'))
                
                logger.info(f"Redirecting user {user[3]} to dashboard")
                return redirect(redirect_url)
            else:
                logger.warning(f"Failed login attempt for email: {email} - Invalid credentials")
                flash('Invalid email or password', 'error')
                return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error during login for {email}: {str(e)}")
            flash('An error occurred during login', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        logger.info(f"Password reset requested for email: {email}")
        
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, email, role, username FROM userss WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            
            if user:
                if user[2].lower() != 'admin':
                    logger.warning(f"Password reset denied for non-admin user: {user[3]}")
                    flash('Only admin users can reset passwords', 'error')
                    return redirect(url_for('forgot_password'))
                
                reset_token = str(uuid.uuid4())
                expiration = datetime.now(timezone.utc) + timedelta(hours=1)
                PASSWORD_RESET_TOKENS[reset_token] = {
                    'user_id': user[0],
                    'expires': expiration
                }
                
                reset_link = f"{request.url_root}reset_password?token={reset_token}"
                email_body = f"""
Dear Administrator,

You have requested to reset your password for AG Publishing House MIS. Please click the link below to set a new password:

{reset_link}

This link will expire in 1 hour for security reasons. If you did not request a password reset, please contact our support team immediately at tech@academicguru24x7.com.

Thank you,
AG Publishing House Team
tech@academicguru24x7.com
"""
                msg = MIMEText(email_body)
                msg['Subject'] = 'AG Publishing House - Password Reset Request for MIS'
                msg['From'] = EMAIL_CONFIG['SENDER_EMAIL']
                msg['To'] = email
                
                with smtplib.SMTP(EMAIL_CONFIG['SMTP_SERVER'], EMAIL_CONFIG['SMTP_PORT']) as server:
                    server.starttls()
                    server.login(EMAIL_CONFIG['SENDER_EMAIL'], EMAIL_CONFIG['SENDER_PASSWORD'])
                    server.send_message(msg)
                
                logger.info(f"Password reset email sent to admin user: {user[3]}")
                flash('Password reset link sent to your email', 'success')
            else:
                logger.warning(f"Password reset attempt for non-existent email: {email}")
                flash('Email not found', 'error')
            
            return redirect(url_for('forgot_password'))
        except Exception as e:
            logger.error(f"Error in password reset for {email}: {str(e)}")
            flash('An error occurred while processing your request', 'error')
            return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        token = request.form.get('token')
        logger.info(f"Password reset attempt with token")
        
        try:
            if token not in PASSWORD_RESET_TOKENS:
                logger.warning(f"Invalid or expired reset token")
                flash('Invalid or expired reset token', 'error')
                return redirect(url_for('forgot_password'))
            
            reset_info = PASSWORD_RESET_TOKENS[token]
            if reset_info['expires'] < datetime.now(timezone.utc):
                logger.warning(f"Expired reset token")
                flash('Reset token has expired', 'error')
                del PASSWORD_RESET_TOKENS[token]
                return redirect(url_for('forgot_password'))
            
            user_id = reset_info['user_id']
            
            cur = mysql.connection.cursor()
            cur.execute("SELECT role, username FROM userss WHERE id = %s", (user_id,))
            user = cur.fetchone()
            cur.close()
            
            if not user or user[0].lower() != 'admin':
                logger.warning(f"Password reset denied for non-admin user_id: {user_id}")
                flash('Only admin users can reset passwords', 'error')
                del PASSWORD_RESET_TOKENS[token]
                return redirect(url_for('forgot_password'))
            
            cur = mysql.connection.cursor()
            cur.execute("UPDATE userss SET password = %s WHERE id = %s", (new_password, user_id))
            mysql.connection.commit()
            cur.close()
            
            del PASSWORD_RESET_TOKENS[token]
            logger.info(f"Password successfully reset for admin user: {user[1]}")
            flash('Password successfully reset. Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in password reset: {str(e)}")
            flash('An error occurred while resetting your password', 'error')
            return redirect(url_for('forgot_password'))
    
    if token not in PASSWORD_RESET_TOKENS or PASSWORD_RESET_TOKENS[token]['expires'] < datetime.now(timezone.utc):
        logger.warning(f"Invalid or expired reset token access")
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('forgot_password'))
    
    try:
        reset_info = PASSWORD_RESET_TOKENS[token]
        user_id = reset_info['user_id']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT role, username FROM userss WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        
        if not user or user[0].lower() != 'admin':
            logger.warning(f"Password reset page access denied for non-admin user_id: {user_id}")
            flash('Only admin users can reset passwords', 'error')
            del PASSWORD_RESET_TOKENS[token]
            return redirect(url_for('forgot_password'))
    except Exception as e:
        logger.error(f"Error validating token for password reset: {str(e)}")
        flash('An error occurred while processing your request', 'error')
        return redirect(url_for('forgot_password'))
    
    return render_template('reset_password.html', token=token)

@app.route('/auth/validate_and_details', methods=['POST'])
def validate_and_details():
    logger.info("Validating token and fetching user details")
    try:
        if not request.is_json:
            logger.warning("Invalid request: Not JSON")
            return jsonify({'valid': False, 'error': 'Request must be JSON'}), 400
        
        token = request.json.get('token')
        if not token:
            logger.warning("Token missing in request")
            return jsonify({'valid': False, 'error': 'Token missing'}), 400
        
        if token in TOKEN_BLACKLIST:
            logger.warning("Attempt to use blacklisted token")
            return jsonify({'valid': False, 'error': 'Token invalidated'}), 401
        
        # Decode JWT
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded['user_id']
        if not user_id or 'exp' not in decoded:
            logger.warning("Missing user_id or exp in token")
            return jsonify({'valid': False, 'error': 'Invalid token'}), 401
        
        # Fetch user details from database
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT u.id, u.username, u.email, u.role, u.associate_id, u.designation,
                   uaa.app, uaa.access_type, uaa.level, uaa.start_date, uaa.report_to
            FROM userss u
            LEFT JOIN user_app_access uaa ON u.id = uaa.user_id
            WHERE u.id = %s
        """, (user_id,))
        user_data = cur.fetchall()
        cur.close()
        
        if not user_data:
            logger.warning(f"User not found for user_id: {user_id}")
            return jsonify({'valid': False, 'error': 'User not found'}), 404
        
        # Process user details
        user = user_data[0]
        access_list = []
        app = user[6].lower() if user[6] else ''
        access_type = user[7] if user[7] else ''
        
        if app == 'main':
            access_list = [acc.strip() for acc in access_type.split(',') if acc.strip()] if access_type else []
        elif app in ('operations', 'ijisem', 'tasks'):
            access_list = [access_type] if access_type else []
        
        start_date = user[9].isoformat() if user[9] else None
        logger.info(f"Successfully validated token and retrieved details for user: {user[1]}")
        
        return jsonify({
            'valid': True,
            'user_id': user_id,
            'user_details': {
                'username': user[1],
                'email': user[2],
                'role': user[3].lower(),
                'app': app,
                'access': access_list,
                'level': user[8] if user[8] else None,
                'start_date': start_date,
                'report_to': user[10] if user[10] else None,
                'associate_id': user[4] if user[4] else None,
                'designation': user[5] if user[5] else None
            }
        })
    
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Error in validate_and_details: {str(e)}")
        return jsonify({'valid': False, 'error': 'Server error'}), 500

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=False, host='0.0.0.0', port=5001)