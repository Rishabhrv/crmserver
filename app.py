from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import config
import pytz
import logging
import re
import uuid
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
import config
from config import APP_REDIRECTS, SOCKET_CORS_ORIGINS, FLASK_CORS_ORIGINS
from flask_socketio import SocketIO, join_room, emit
from datetime import datetime, timedelta
from functools import wraps
from mysql.connector import pooling
import os
from werkzeug.utils import secure_filename
from flask import Flask, send_from_directory
import json
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask_cors import CORS

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



logging.basicConfig(
    filename="error.log",
    level=logging.ERROR,
    format="%(asctime)s %(levelname)s: %(message)s",
)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins=SOCKET_CORS_ORIGINS)
#CORS(app, resources={r"/*": {"origins": FLASK_CORS_ORIGINS}})


try:
    # Pool for 'ict' database (chat)
    ict_pool = pooling.MySQLConnectionPool(
        pool_name="ict_pool",
        pool_size=20,
        host=config.MYSQL_ICT_HOST,
        user=config.MYSQL_ICT_USER,
        password=config.MYSQL_ICT_PASSWORD,
        database=config.MYSQL_ICT_DB,
        autocommit=True
    )
    logger.info("ICT MySQL pool created")

    # Pool for 'booktracker' (optional)
    book_pool = pooling.MySQLConnectionPool(
        pool_name="book_pool",
        pool_size=20,
        host=config.MYSQL_HOST,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        database=config.MYSQL_DB,
        autocommit=True
    )
    logger.info("Booktracker MySQL pool created")

except Exception as e:
    logger.error(f"MySQL pool error: {e}")
    raise


# JWT secret key
JWT_SECRET = config.JWT_SECRET

# Email configuration
EMAIL_CONFIG = {
    'SMTP_SERVER': config.SMTP_SERVER,
    'SMTP_PORT': config.SMTP_PORT,
    'SENDER_EMAIL': config.SENDER_EMAIL,
    'SENDER_PASSWORD': config.SENDER_PASSWORD
}

UPLOAD_FOLDER = config.UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
IS_PRODUCTION = os.getenv('FLASK_ENV') == 'production'

GROUP_UPLOAD_FOLDER = config.GROUP_UPLOAD_FOLDER
os.makedirs(GROUP_UPLOAD_FOLDER, exist_ok=True)

# File restrictions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "docx", "xlsx", "csv", "zip", "pptx", "rar", "doc"}
MAX_FILE_SIZE = 100 * 1024 * 1024 
MAX_FILES_PER_REQUEST = 10

TOKEN_BLACKLIST = set()
PASSWORD_RESET_TOKENS = {}

# -------------------- Login Rate Limiting --------------------
# In-memory storage for login attempts
IP_ATTEMPTS = {}
EMAIL_ATTEMPTS = {}
MAX_ATTEMPTS_PER_IP = 15
MAX_ATTEMPTS_PER_EMAIL = 5
LOCKOUT_WINDOW_MINUTES = 10

def check_rate_limit(ip, email):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
    
    # Check IP
    if ip in IP_ATTEMPTS:
        IP_ATTEMPTS[ip] = [t for t in IP_ATTEMPTS[ip] if t > cutoff]
        logger.info(f"IP {ip} has {len(IP_ATTEMPTS[ip])} recent attempts")
        if len(IP_ATTEMPTS[ip]) >= MAX_ATTEMPTS_PER_IP:
            return True, f"Too many login attempts from this IP. Please try again in {LOCKOUT_WINDOW_MINUTES} minutes."
            
    # Check Email
    if email in EMAIL_ATTEMPTS:
        EMAIL_ATTEMPTS[email] = [t for t in EMAIL_ATTEMPTS[email] if t > cutoff]
        logger.info(f"Email {email} has {len(EMAIL_ATTEMPTS[email])} recent attempts")
        if len(EMAIL_ATTEMPTS[email]) >= MAX_ATTEMPTS_PER_EMAIL:
            return True, f"Too many login attempts for this account. Please try again in {LOCKOUT_WINDOW_MINUTES} minutes."
            
    return False, ""

def record_login_failure(ip, email):
    now = datetime.now(timezone.utc)
    if ip:
        IP_ATTEMPTS.setdefault(ip, []).append(now)
    if email:
        EMAIL_ATTEMPTS.setdefault(email, []).append(now)
    logger.info(f"Recorded failure for IP: {ip}, Email: {email}. Total failures now: IP={len(IP_ATTEMPTS.get(ip, []))}, Email={len(EMAIL_ATTEMPTS.get(email, []))}")

def reset_login_attempts(ip, email):
    if ip in IP_ATTEMPTS:
        del IP_ATTEMPTS[ip]
    if email in EMAIL_ATTEMPTS:
        del EMAIL_ATTEMPTS[email]

# -------------------- Helper Functions --------------------
def now_ist():
    return datetime.now(pytz.timezone("Asia/Kolkata"))

def get_ict_cursor():
    conn = ict_pool.get_connection()
    return conn, conn.cursor(dictionary=True)

def get_book_cursor():
    conn = book_pool.get_connection()
    return conn, conn.cursor(dictionary=True)

# -------------------- Auth decorator --------------------
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth or not auth.startswith('Bearer '):
            return jsonify({"error": "Token missing"}), 401
        try:
            token = auth.split(" ")[1]
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon_black.ico', mimetype='image/vnd.microsoft.icon')


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
        ip = request.remote_addr
        logger.info(f"Trying to login with email: {email} from IP: {ip}")

        # Ensure a consistent session_id exists for this login attempt sequence
        if 'temp_session_id' not in session:
            session['temp_session_id'] = str(uuid.uuid4())
        session_id = session['temp_session_id']

        # Fetch user first to get accurate username/id for logs
        conn, cur = get_book_cursor()
        user = None
        try:
            cur.execute(
                "SELECT id, email, password, password_hash, username, role, login_time_start, login_time_end, status FROM userss WHERE email = %s",
                (email,)
            )
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        # Determine logging identity
        log_uid = user['id'] if user else 0
        log_uname = user['username'] if user else email

        # ----- Rate Limit Check -----
        is_limited, limit_msg = check_rate_limit(ip, email)
        if is_limited:
            logger.warning(f"Rate limit exceeded: IP={ip}, Email={email}")
            log_activity(log_uid, log_uname, session_id, "Login Blocked", f"Rate limit exceeded from IP: {ip}")
            flash(limit_msg, 'error')
            return render_template('login.html'), 429

        # User not found check
        if not user:
            logger.warning(f"User not found: {email}")
            record_login_failure(ip, email)
            log_activity(0, email, session_id, "Login Failed", f"User not found for email: {email} from IP: {ip}")
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        # ----- Status Check -----
        if user.get('status', 'active').lower() != 'active':
            logger.warning(f"Inactive user attempted login: {email}")
            record_login_failure(ip, email)
            log_activity(user['id'], user['username'], session_id, "Login Failed", "Account is inactive")
            flash('Your account is inactive. Please contact the administrator.', 'error')
            return redirect(url_for('login'))

        # Check password using hash if available, fallback to plain text if not hashed yet
        is_password_correct = False
        if user.get('password_hash'):
            is_password_correct = check_password_hash(user['password_hash'], password)
        else:
            # Fallback for any non-migrated users
            is_password_correct = (user['password'] == password)
            if is_password_correct:
                # Optionally hash it now and save
                try:
                    conn, cur = get_book_cursor()
                    cur.execute("UPDATE userss SET password_hash = %s WHERE id = %s", (generate_password_hash(password), user['id']))
                    conn.commit()
                    cur.close()
                    conn.close()
                except Exception as e:
                    logger.error(f"Failed to auto-migrate password for {email}: {e}")

        if not is_password_correct:
            logger.warning(f"Invalid password for: {email}")
            record_login_failure(ip, email)
            log_activity(user['id'], user['username'], session_id, "Login Failed", "Incorrect password")
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        # ----- SUCCESS -----
        reset_login_attempts(ip, email)
        # Finalize the session_id (remove temp prefix in logic, though value remains same)
        session.pop('temp_session_id', None) 
        session['email'] = user['email']
        session['session_id'] = session_id
        session['login_time'] = datetime.now(timezone.utc).isoformat()
        
        # Pre-authentication log (internal)
        logger.info(f"User {user['username']} pre-authenticated, session_id: {session_id}")

        # ----- Fetch app access -----
        conn, cur = get_book_cursor()
        user_details = []
        try:
            cur.execute("""
                SELECT u.role, uaa.app, uaa.access_type, uaa.level, uaa.start_date, uaa.report_to
                FROM userss u
                LEFT JOIN user_app_access uaa ON u.id = uaa.user_id
                WHERE u.id = %s
            """, (user['id'],))
            user_details = cur.fetchall()
        finally:
            cur.close()
            conn.close()

        role = user['role'].lower()
        app_name = user_details[0]['app'].lower() if user_details and user_details[0]['app'] else ''

        # ----- Time restriction -----
        if role != 'admin':
            login_start = user.get('login_time_start')
            login_end = user.get('login_time_end')

            if login_start and login_end:
                now = datetime.now(pytz.timezone('Asia/Kolkata')).time()

                # Helper to convert potential formats (timedelta for MySQL TIME, or string) to time object
                def parse_time(t):
                    if isinstance(t, timedelta):
                        return (datetime.min + t).time()
                    if isinstance(t, str):
                        for fmt in ('%H:%M:%S', '%H:%M'):
                            try:
                                return datetime.strptime(t, fmt).time()
                            except ValueError:
                                continue
                    return t

                start_t = parse_time(login_start)
                end_t = parse_time(login_end)

                if start_t and end_t:
                    if not (start_t <= now <= end_t):
                        log_activity(user['id'], user['username'], session_id, "Login Failed", f"Off-hours login attempt at {now.strftime('%I:%M %p')}")
                        flash(f'Login allowed only between {start_t.strftime("%I:%M %p")} and {end_t.strftime("%I:%M %p")} IST', 'error')
                        return redirect(url_for('login'))
            elif role == 'user':
                # Fallback to default if no dynamic timing is set for 'user' role
                current_hour = datetime.now(pytz.timezone('Asia/Kolkata')).hour
                if not (9 <= current_hour < 18):
                    log_activity(user['id'], user['username'], session_id, "Login Failed", f"Standard user off-hours login attempt at {current_hour}:00")
                    flash('Users can only log in between 9 AM and 6 PM IST', 'error')
                    return redirect(url_for('login'))

        # Final Activity Log after ALL validations
        log_activity(user['id'], user['username'], session_id, "Login Success", f"User logged in from IP: {ip}")
        logger.info(f"User {user['username']} logged in successfully, role: {user['role']}")

        # ----- JWT -----
        token = jwt.encode({
            'user_id': user['id'],
            'session_id': session_id,
            'exp': datetime.now(timezone.utc) + timedelta(minutes=240)
        }, JWT_SECRET, algorithm='HS256')

        # ----- Redirect -----
        if role == 'admin':
            redirect_url = f"{APP_REDIRECTS['admin']}?token={token}"
        elif app_name in APP_REDIRECTS:
            redirect_url = f"{APP_REDIRECTS[app_name]}?token={token}"
        else:
            flash('Invalid app configuration', 'error')
            return redirect(url_for('login'))

        return redirect(redirect_url)

    return render_template('login.html')


@app.route('/auth/validate_and_details', methods=['POST'])
def validate_and_details():
    logger.info("Validating token and fetching user details")
    
    if not request.is_json:
        return jsonify({'valid': False, 'error': 'Request must be JSON'}), 400

    token = request.json.get('token')
    if not token:
        return jsonify({'valid': False, 'error': 'Token missing'}), 400

    if token in TOKEN_BLACKLIST:
        return jsonify({'valid': False, 'error': 'Token invalidated'}), 401

    # --- Decode JWT ---
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded['user_id']
        session_id = decoded.get('session_id')
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

    # --- Fetch user from DB ---
    conn, cur = get_book_cursor()
    try:
        cur.execute("""
            SELECT 
                u.id, u.username, u.email, u.role, u.associate_id, u.designation,
                uaa.app, uaa.access_type, uaa.level, uaa.start_date, uaa.report_to
            FROM userss u
            LEFT JOIN user_app_access uaa ON u.id = uaa.user_id
            WHERE u.id = %s
        """, (user_id,))
        rows = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    if not rows:
        return jsonify({'valid': False, 'error': 'User not found'}), 404

    # --- Use dictionary keys (NOT numbers!) ---
    user = rows[0]

    app_name = (user['app'] or '').lower()
    access_type = user['access_type'] or ''

    # --- Build access list ---
    if app_name == 'main':
        access_list = [a.strip() for a in access_type.split(',') if a.strip()]
    elif app_name in ('operations', 'ijisem', 'tasks', 'sales'):
        access_list = [access_type] if access_type else []
    else:
        access_list = []

    # --- Format dates ---
    start_date = user['start_date'].isoformat() if user['start_date'] else None

    # --- Return clean response ---
    return jsonify({
        'valid': True,
        'user_id': user_id,
        'session_id': session_id,
        'user_details': {
            'username': user['username'],
            'email': user['email'],
            'role': user['role'].lower(),
            'app': app_name,
            'access': access_list,
            'level': user['level'],
            'start_date': start_date,
            'report_to': user['report_to'],
            'associate_id': user['associate_id'],
            'designation': user['designation']
        }
    })


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        logger.info(f"Password reset requested for email: {email}")

        conn, cur = get_book_cursor()
        try:
            cur.execute(
                "SELECT id, email, role, username FROM userss WHERE email = %s",
                (email,)
            )
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if user and user['role'].lower() == 'admin':
            reset_token = str(uuid.uuid4())
            expiration = datetime.now(timezone.utc) + timedelta(hours=1)
            PASSWORD_RESET_TOKENS[reset_token] = {
                'user_id': user['id'],
                'expires': expiration
            }

            reset_link = f"{request.url_root}reset_password?token={reset_token}"
            email_body = f"""Dear Administrator,

You have requested to reset your password for AG Publishing House MIS. Click the link below:

{reset_link}

This link expires in 1 hour.
Thank you,
AG Publishing House Team
tech@academicguru24x7.com"""

            try:
                msg = MIMEText(email_body)
                msg['Subject'] = 'AG Publishing House - Password Reset'
                msg['From'] = EMAIL_CONFIG['SENDER_EMAIL']
                msg['To'] = email

                with smtplib.SMTP(EMAIL_CONFIG['SMTP_SERVER'], EMAIL_CONFIG['SMTP_PORT']) as server:
                    server.starttls()
                    server.login(EMAIL_CONFIG['SENDER_EMAIL'], EMAIL_CONFIG['SENDER_PASSWORD'])
                    server.send_message(msg)

                logger.info(f"Password reset email sent to admin: {user['username']}")
                flash('Password reset link sent to your email', 'success')

            except smtplib.SMTPAuthenticationError:
                logger.error("SMTP authentication failed — check EMAIL_CONFIG credentials")
                flash('Email service is temporarily unavailable. Please contact support.', 'error')

            except smtplib.SMTPException as e:
                logger.error(f"SMTP error while sending reset email: {e}")
                flash('Failed to send reset email. Please try again later.', 'error')

            except Exception as e:
                logger.error(f"Unexpected error sending reset email: {e}")
                flash('An unexpected error occurred. Please try again later.', 'error')

        else:
            logger.warning(f"Password reset attempt for non-admin or unknown email: {email}")
            flash('Only admin users can reset passwords', 'error')

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token') or request.form.get('token')

    if request.method == 'POST':
        new_password = request.form.get('password')
        if not token or token not in PASSWORD_RESET_TOKENS:
            flash('Invalid or expired token', 'error')
            return redirect(url_for('forgot_password'))

        info = PASSWORD_RESET_TOKENS[token]
        if info['expires'] < datetime.now(timezone.utc):
            del PASSWORD_RESET_TOKENS[token]
            flash('Reset token has expired', 'error')
            return redirect(url_for('forgot_password'))

        user_id = info['user_id']
        conn, cur = get_book_cursor()
        try:
            cur.execute("SELECT role, username FROM userss WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user or user['role'].lower() != 'admin':
                flash('Only admin users can reset passwords', 'error')
                del PASSWORD_RESET_TOKENS[token]
                return redirect(url_for('forgot_password'))

            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE userss SET password = %s, password_hash = %s WHERE id = %s", (new_password, hashed_password, user_id))
            conn.commit()
        finally:
            cur.close()
            conn.close()

        del PASSWORD_RESET_TOKENS[token]
        logger.info(f"Password reset successful for admin: {user['username']}")
        flash('Password successfully reset. Please login.', 'success')
        return redirect(url_for('login'))

    # GET – show form
    if not token or token not in PASSWORD_RESET_TOKENS or \
       PASSWORD_RESET_TOKENS[token]['expires'] < datetime.now(timezone.utc):
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)


# -------------------- Activity Log Helper --------------------
logged_click_ids = set()  # To avoid duplicate navigation logs

def log_activity(user_id, username, session_id, action, details):
    conn, cur = get_book_cursor()
    try:
        ist_time = now_ist().strftime('%Y-%m-%d %H:%M:%S')

        # ✅ FALLBACK session_id
        if not session_id:
            session_id = f"auto-{user_id}-{int(datetime.now().timestamp())}"

        cur.execute("""
            INSERT INTO activity_log 
            (user_id, username, session_id, action, details, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, username, session_id, action, details, ist_time))

        conn.commit()

    except Exception:
        logger.exception("Activity Log Error")

    finally:
        cur.close()
        conn.close()





logged_click_ids = set()  # Avoid duplicates

@app.route("/log_navigation", methods=["POST"])
@token_required
def log_navigation():
    data = request.json
    click_id = data.get("click_id")
    page = data.get("page")
    session_id = data.get("session_id")  # ✅ Now received from frontend

    if not click_id or not page or not session_id:
        return jsonify({"error": "click_id, page and session_id required"}), 400

    # ✅ Avoid duplicate logs
    if click_id in logged_click_ids:
        return jsonify({"status": "ignored"}), 200

    logged_click_ids.add(click_id)

    # ✅ Fetch username from DB using request.user_id from token
    conn, cur = get_book_cursor()
    cur.execute("SELECT username FROM userss WHERE id=%s", (request.user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    username = user["username"] if user else "Unknown"

    # ✅ Log activity using session_id from frontend
    log_activity(
        user_id=request.user_id,
        username=username,
        session_id=session_id,
        action="navigation to page",
        details=f"Page: {page}"
    )

    return jsonify({"status": "logged"}), 200



@app.route("/conversations", methods=["GET"])
@token_required
def get_conversations():
    uid = request.user_id
    ict_conn, ict_cur = get_ict_cursor()   # For messages & conversations
    book_conn, book_cur = get_book_cursor()  # For user info

    try:
        # 🔹 Fetch conversations + last message + message_type
        ict_cur.execute("""
            SELECT 
                c.id,
                CASE 
                    WHEN c.user1_id = %s THEN c.user2_id 
                    ELSE c.user1_id 
                END AS other_user_id,
                m.message AS last_message,
                m.message_type AS last_message_type,
                m.timestamp AS last_time
            FROM conversations c
            LEFT JOIN messages m ON m.id = (
                SELECT id 
                FROM messages 
                WHERE conversation_id = c.id
                ORDER BY timestamp DESC 
                LIMIT 1
            )
            WHERE c.user1_id = %s OR c.user2_id = %s
            ORDER BY m.timestamp DESC
        """, (uid, uid, uid))

        rows = ict_cur.fetchall()
        convos = []

        for r in rows:
            other_id = r["other_user_id"]

            # 🔹 Get user info from book database
            book_cur.execute("SELECT username FROM userss WHERE id=%s", (other_id,))
            other = book_cur.fetchone() or {}

            # 🔹 Count unread messages
            ict_cur.execute("""
                SELECT COUNT(*) AS unread
                FROM messages
                WHERE conversation_id=%s AND sender_id!=%s AND seen=0
            """, (r["id"], uid))
            unread = ict_cur.fetchone()["unread"]

            convos.append({
                "id": r["id"],
                "other_user_id": other_id,
                "other_username": other.get("username", "Unknown"),
                "last_message": r["last_message"],
                "last_message_type": r.get("last_message_type"),  
                "last_time": r["last_time"],
                "unread": unread
            })


        return jsonify(convos)

    finally:
        ict_cur.close()
        book_cur.close()
        ict_conn.close()
        book_conn.close()




@app.route("/messages/<int:conversation_id>", methods=["GET"])
@token_required
def get_messages(conversation_id):
    uid = request.user_id
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    conn, cur = get_ict_cursor()
    try:
        # 📨 Fetch paginated messages in this conversation
        cur.execute("""
            SELECT m.*, u.username AS sender_name
            FROM messages m
            LEFT JOIN (
                SELECT id AS uid, username FROM booktracker.userss
            ) u ON m.sender_id = u.uid
            WHERE m.conversation_id = %s
            ORDER BY m.id DESC        -- latest first
            LIMIT %s OFFSET %s
        """, (conversation_id, limit, offset))
        msgs = cur.fetchall()

        # 🔄 Reverse again so UI still shows oldest→newest order
        msgs.reverse()

        # 🧩 Fetch reply + reaction details
        bconn, bcur = get_book_cursor()
        for m in msgs:
            if m.get("reply_to"):
                cur.execute("SELECT message, sender_id FROM messages WHERE id = %s", (m["reply_to"],))
                reply_msg = cur.fetchone()
                if reply_msg:
                    m["reply_to_text"] = reply_msg["message"]
                    bcur.execute("SELECT username FROM userss WHERE id = %s", (reply_msg["sender_id"],))
                    reply_user = bcur.fetchone()
                    m["reply_to_user"] = reply_user["username"] if reply_user else "Unknown"
                else:
                    m["reply_to_text"] = None
                    m["reply_to_user"] = None
            else:
                m["reply_to_text"] = None
                m["reply_to_user"] = None

            # ✅ Fetch reactions
            cur.execute("""
                SELECT emoji, COUNT(*) AS count
                FROM message_reactions
                WHERE message_id = %s
                GROUP BY emoji
            """, (m["id"],))
            m["reactions"] = cur.fetchall() or []

        bcur.close()
        bconn.close()

        # ✅ Mark other-user messages as seen
        # cur.execute("""
        #     UPDATE messages 
        #     SET seen = 1, seen_time = %s 
        #     WHERE conversation_id = %s 
        #       AND sender_id != %s 
        #       AND seen = 0
        # """, (now_ist().strftime("%Y-%m-%d %H:%M:%S"), conversation_id, uid))
        # conn.commit()

        return jsonify(msgs or [])

    except Exception as e:
        logger.info("Error in get_messages:", e)
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()





@app.route('/users')
def search_users():
    term = request.args.get('search', '')
    conn, cur = get_book_cursor()   # ✅ Correct: connect to 'book' DB
    try:
        cur.execute(
            "SELECT id, username FROM userss WHERE username LIKE %s LIMIT 10",
            (f"%{term}%",)
        )
        users = cur.fetchall()
        return jsonify(users)
    finally:
        cur.close()
        conn.close()


@app.route("/createConversation", methods=["POST"])
@token_required
def create_conversation():
    try:

        data = request.get_json() or {}
        user1_id = data.get("user1_id")      # current user
        user2_id = data.get("user2_id")      # other user
        session_id = data.get("session_id")

        if not user1_id or not user2_id:
            return jsonify({"success": False, "error": "Both user IDs required"}), 400

        # Fetch actor username
        book_conn, book_cur = get_book_cursor()
        book_cur.execute("SELECT username FROM userss WHERE id=%s", (request.user_id,))
        actor = book_cur.fetchone()
        actor_name = actor["username"] if actor else "Unknown"
        book_cur.close()
        book_conn.close()

        conn, cur = get_ict_cursor()

        # ------------------------------------------------------------
        #STEP 1 — Checking for existing conversation (soft + normal)
        # ------------------------------------------------------------

        cur.execute("""
            SELECT c.id, c.user1_id, c.user2_id
            FROM conversations c
            WHERE
                -- Case 1: Normal match (3,1)
                (c.user1_id = %s AND c.user2_id = %s)
        
                OR
        
                -- Case 2: Swapped match (1,3)
                (c.user1_id = %s AND c.user2_id = %s)
        
                OR
        
                -- Case 3: Soft delete -> user2_id deleted 
                -- Original was (user1_id=user1, user2_id=user2)
                (
                    c.user1_id = %s
                    AND c.user2_id IS NULL
                    AND EXISTS (
                        SELECT 1 FROM user_delete_data ud
                        WHERE ud.conversation_id = c.id
                        AND ud.user_id = %s
                        AND ud.deleted_column='user2_id'
                    )
                )
        
                OR
        
                -- Case 4: Soft delete (reversed order): 
                -- Original was (user1_id=user2, user2_id=user1)
                (
                    c.user1_id = %s
                    AND c.user2_id IS NULL
                    AND EXISTS (
                        SELECT 1 FROM `user_delete_data` ud
                        WHERE ud.conversation_id = c.id
                        AND ud.user_id = %s
                        AND ud.deleted_column='user2_id'
                    )
                )

                OR
        
                -- Case 5: Soft delete -> user1_id deleted
                (
                    c.user2_id = %s
                    AND c.user1_id IS NULL
                    AND EXISTS (
                        SELECT 1 FROM `user_delete_data` ud
                        WHERE ud.conversation_id = c.id
                        AND ud.user_id = %s
                        AND ud.deleted_column='user1_id'
                    )
                )
        
                OR
        
                -- Case 6: Soft delete (reversed order):
                (
                    c.user2_id = %s
                    AND c.user1_id IS NULL
                    AND EXISTS (
                        SELECT 1 FROM `user_delete_data` ud
                        WHERE ud.conversation_id = c.id
                        AND ud.user_id = %s
                        AND ud.deleted_column='user1_id'
                    )
                )
        """, (
            user1_id, user2_id,      # Case 1
            user2_id, user1_id,      # Case 2
            user1_id, user2_id,      # Case 3
            user2_id, user1_id,      # Case 4
            user2_id, user1_id,      # Case 5
            user1_id, user2_id       # Case 6
        ))
        
        convo = cur.fetchone()


        # STEP 2 — NEW RULE CHECK (Prevent new conversation)
        # ------------------------------------------------------------
        if convo:
            convo_id_check = convo["id"]

            # ALWAYS CHECK DELETE STATE (do not depend on user1_in_convo)
            cur.execute("""
                SELECT deleted_column 
                FROM `user_delete_data`
                WHERE conversation_id=%s 
                AND user_id=%s
                LIMIT 1
            """, (convo_id_check, user2_id))
        
            other_user_delete_row = cur.fetchone()
        
            other_user_deleted_this = False

            if other_user_delete_row:
                deleted_column = other_user_delete_row["deleted_column"]
        
                # CASE A — user2_id deleted
                if deleted_column == "user2_id" and convo["user2_id"] is None:
                    other_user_deleted_this = True
        
                # CASE B — user1_id deleted
                if deleted_column == "user1_id" and convo["user1_id"] is None:
                    other_user_deleted_this = True
        
        
            # Block only if OTHER USER deleted and current user is not same
            if other_user_deleted_this and user2_id != request.user_id:
                cur.close()
                conn.close()
                return jsonify({
                    "success": False,
                    "error": "Conversation exists but the other user has deleted it. Cannot create new."
                }), 409



        # ------------------------------------------------------------
        # STEP 3 — Handling EXISTING CONVERSATION cases
        # ------------------------------------------------------------
        if convo:
            convo_id = convo["id"]

            cur.execute("""
                SELECT deleted_column 
                FROM `user_delete_data`
                WHERE conversation_id=%s AND user_id=%s
                LIMIT 1
            """, (convo_id, user1_id))
            my_delete = cur.fetchone()

            cur.execute("""
                SELECT deleted_column 
                FROM `user_delete_data`
                WHERE conversation_id=%s AND user_id=%s
                LIMIT 1
            """, (convo_id, user2_id))
            other_delete = cur.fetchone()

            # CASE A
            if other_delete:
                cur.close()
                conn.close()
                return jsonify({
                    "success": False,
                    "error": "The other user left this chat. Only they can restore it."
                }), 403

            # CASE B — Restore
            if my_delete:
                deleted_column = my_delete["deleted_column"]

                cur.execute(f"""
                    UPDATE conversations
                    SET {deleted_column}=%s
                    WHERE id=%s
                """, (user1_id, convo_id))
                conn.commit()

                cur.execute("""
                    DELETE FROM `user_delete_data`
                    WHERE conversation_id=%s AND user_id=%s
                """, (convo_id, user1_id))
                conn.commit()

                cur.execute("SELECT * FROM conversations WHERE id=%s", (convo_id,))
                restored_convo = cur.fetchone()

                log_activity(
                    user_id=request.user_id,
                    username=actor_name,
                    session_id=session_id,
                    action="Restore Conversation",
                    details=f"{actor_name} restored conversation with user {user2_id} (ID {convo_id})"
                )

                cur.close()
                conn.close()

                return jsonify({
                    "success": True,
                    "message": "Conversation restored",
                    "conversation": restored_convo
                }), 200

            # CASE C — Normal existing conversation
            cur.execute("SELECT * FROM conversations WHERE id=%s", (convo_id,))
            existing_convo = cur.fetchone()


            log_activity(
                user_id=request.user_id,
                username=actor_name,
                session_id=session_id,
                action="Open Conversation",
                details=f"{actor_name} opened existing conversation with user {user2_id} (ID {convo_id})"
            )

            cur.close()
            conn.close()

            return jsonify({
                "success": True,
                "message": "Conversation already exists",
                "conversation": existing_convo
            }), 200

        # ------------------------------------------------------------
        # STEP 4 — Creating NEW conversation
        # ------------------------------------------------------------
        current_time = now_ist().strftime("%Y-%m-%d %H:%M:%S")

        cur.execute("""
            INSERT INTO conversations (user1_id, user2_id, created_at)
            VALUES (%s, %s, %s)
        """, (user1_id, user2_id, current_time))
        conn.commit()

        convo_id = cur.lastrowid

        cur.execute("SELECT * FROM conversations WHERE id=%s", (convo_id,))
        new_convo = cur.fetchone()

        log_activity(
            user_id=request.user_id,
            username=actor_name,
            session_id=session_id,
            action="Create Conversation",
            details=f"{actor_name} started a new conversation with user {user2_id} (ID {convo_id})"
        )

        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": "New conversation created",
            "conversation": new_convo
        }), 201

    except Exception as e:
        logger.info("\n❌ ERROR in createConversation:", str(e))
        return jsonify({"success": False, "error": str(e)}), 500


#-------------------- Msg Delete-----------------------------

@app.route("/delete_message/<int:msg_id>", methods=["DELETE"])
@token_required
def delete_message(msg_id):
    user_id = request.user_id
    ict_conn, ict_cur = get_ict_cursor()

    try:
        # 🔹 Check if the message exists and belongs to this user
        ict_cur.execute(
            "SELECT sender_id, conversation_id FROM messages WHERE id = %s",
            (msg_id,),
        )
        msg = ict_cur.fetchone()
        if not msg:
            return jsonify({"error": "Message not found"}), 404

        if msg["sender_id"] != user_id:
            return jsonify({"error": "You can only delete your own messages"}), 403

        # 🔹 Delete message from DB
        ict_cur.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
        ict_conn.commit()

        # 🔹 Notify all clients in that conversation (via socket.io)
        socketio.emit(
            "delete_message",
            {"id": msg_id, "conversation_id": msg["conversation_id"]},
            room=str(msg["conversation_id"]),
        )

        return jsonify({"success": True, "message": "Message deleted successfully"})
    except Exception as e:
        ict_conn.rollback()
        logger.error(f"Delete message error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        ict_cur.close()
        ict_conn.close()





@app.route('/all_users', methods=['GET'])
@token_required
def get_all_users():
    ict_conn, ict_cur = get_book_cursor()

    try:
        # 🔹 Fetch all users (no exclusions)
        ict_cur.execute("""
            SELECT id, username 
            FROM userss
        """)
        users = ict_cur.fetchall()

        return jsonify(users)

    except Exception as e:
        logger.error(f"Error fetching all users: {e}")
        return jsonify({"error": "Internal server error"}), 500

    finally:
        ict_cur.close()
        ict_conn.close()


        



# -------------------- SocketIO --------------------
@socketio.on("join")
def socket_join(data):
    token = data.get("token")
    conv_id = data.get("conversation_id")
    if not token or not conv_id:
        emit("error", {"error": "missing token/conversation_id"})
        return

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["user_id"]
    except:
        emit("error", {"error": "invalid token"})
        return

    join_room(f"conv_{conv_id}")
    emit("system", {"msg": f"user {user_id} joined"}, room=f"conv_{conv_id}")




@socketio.on("send_message")
def socket_send_message(data):
    token = data.get("token")
    conv_id = data.get("conversation_id")
    message_text = data.get("message")
    message_type = data.get("message_type", "text")
    reply_to = data.get("reply_to")  # ✅ Optional reply message ID
    file_size = data.get("file_size")  


    if not token or not conv_id or not message_text:
        emit("error", {"error": "missing fields"})
        return

    # 🔐 Decode JWT
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        sender_id = payload["user_id"]
    except jwt.ExpiredSignatureError:
        emit("error", {"error": "token expired"})
        return
    except jwt.InvalidTokenError:
        emit("error", {"error": "invalid token"})
        return

    # 🕒 Use IST time
    current_time = now_ist()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn, cur = get_ict_cursor()

        # ✅ Step 1: If replying to a message, fetch its text and sender_id
        reply_to_text = None
        reply_to_user = None
        if reply_to:
            cur.execute("SELECT message, sender_id FROM messages WHERE id = %s", (reply_to,))
            reply_msg = cur.fetchone()
            if reply_msg:
                reply_to_text = reply_msg["message"]
                reply_sender_id = reply_msg["sender_id"]

                # ✅ Get username from BOOK database (since userss table is there)
                try:
                    bconn, bcur = get_book_cursor()
                    bcur.execute("SELECT username FROM userss WHERE id = %s", (reply_sender_id,))
                    buser = bcur.fetchone()
                    if buser:
                        reply_to_user = buser["username"]
                finally:
                    bcur.close()
                    bconn.close()

        # ✅ Step 2: Insert the new message into ICT DB
        cur.execute("""
            INSERT INTO messages (conversation_id, sender_id, message, message_type, file_size, timestamp, reply_to)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (conv_id, sender_id, message_text, message_type, file_size, formatted_time, reply_to))
        conn.commit()
        message_id = cur.lastrowid

        # ✅ Step 3: Mark previous messages from others as seen
        cur.execute("""
            UPDATE messages
            SET seen = 1
            WHERE conversation_id = %s
              AND sender_id != %s
              AND seen = 0
              AND id < %s
        """, (conv_id, sender_id, message_id))
        conn.commit()

    except Exception as e:
        emit("error", {"error": f"DB error: {str(e)}"})
        return
    finally:
        cur.close()
        conn.close()

    # ✅ Step 4: Get sender username from BOOK DB
    try:
        bconn, bcur = get_book_cursor()
        bcur.execute("SELECT username FROM userss WHERE id = %s", (sender_id,))
        sender_name = (bcur.fetchone() or {}).get("username", "Unknown")
    except Exception:
        sender_name = "Unknown"
    finally:
        bcur.close()
        bconn.close()

    # ✅ Step 5: Build payload
    payload_msg = {
        "id": message_id,
        "conversation_id": conv_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "message": message_text,
        "message_type": message_type,
        "file_size": file_size,
        "timestamp": formatted_time,
        "reply_to": reply_to,
        "reply_to_text": reply_to_text,
        "reply_to_user": reply_to_user
    }




    # 📡 Broadcast to all users in the conversation
    emit("new_message", payload_msg, room=f"conv_{conv_id}")

    # # ---------------------- SEND FCM PUSH NOTIFICATIONS -----------------------

    # # Get conversation participants except sender
    # ict_conn, ict_cur = get_ict_cursor()
    # try:
    #     ict_cur.execute("""
    #         SELECT user_id FROM conversation_participants
    #         WHERE conversation_id = %s AND user_id != %s
    #     """, (conv_id, sender_id))
    
    #     participants = ict_cur.fetchall()
    #     receiver_ids = [row["user_id"] for row in participants]
    
    #     if receiver_ids:
    #         # Fetch FCM tokens for these users
    #         format_strings = ",".join(["%s"] * len(receiver_ids))
    #         ict_cur.execute(
    #             f"SELECT token FROM device_tokens WHERE user_id IN ({format_strings})",
    #             tuple(receiver_ids)
    #         )
    #         tokens = [row["token"] for row in ict_cur.fetchall()]

    #         # Send notification
    #         send_fcm_notification(
    #             tokens,
    #             title=f"New message from {sender_name}",
    #             body=message_text if message_type == "text" else "Sent a file",
    #             data={
    #                 "conversation_id": str(conv_id),
    #                 "sender_id": str(sender_id),
    #                 "message_type": message_type
    #             }
    #         )
    # finally:
    #     ict_cur.close()
    #     ict_conn.close()


    # ✅ Notify that previous messages were marked as seen
    emit("messages_marked_seen", {"conversation_id": conv_id}, room=f"conv_{conv_id}")

    # 📨 Acknowledge sender (optional)
    emit("message_sent", payload_msg, room=request.sid)




@socketio.on("mark_seen")
def handle_mark_seen(data):
    message_id = data.get("message_id")
    conversation_id = data.get("conversation_id")
    token = data.get("token")

    # ✅ Validate token
    try:
        user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        emit("auth_error", {"error": "Invalid token"})
        return

    # ✅ Update database (seen = 1)
    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            UPDATE messages 
            SET seen = 1, seen_time = %s 
            WHERE id = %s
        """, (now_ist().strftime("%Y-%m-%d %H:%M:%S"), message_id))

        conn.commit()
    finally:
        cur.close()
        conn.close()

    # ✅ Notify everyone in this conversation that a message was seen
    emit(
        "message_seen",
        {"message_id": message_id, "conversation_id": conversation_id},
        room=f"conv_{conversation_id}",
    )



@app.route("/get_conversation_media", methods=["GET"])
def get_conversation_media():
    conversation_id = request.args.get("conversation_id")

    if not conversation_id:
        return jsonify({"error": "conversation_id required"}), 400

    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            SELECT id AS message_id, message_type, message AS file_url
            FROM messages
            WHERE conversation_id = %s AND message_type IN ('image', 'file')
            ORDER BY id DESC
        """, (conversation_id,))
        data = cur.fetchall()
    except Exception as e:
        logger.info("Error fetching media:", e)
        return jsonify({"error": "Database error"}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify(data)





#-------------- Message Reaction-------------

@app.route("/add_reaction", methods=["POST"])
@token_required
def add_reaction():
    """Add, update, or remove a single emoji reaction for a message per user."""
    user_id = request.user_id
    data = request.get_json()
    message_id = data.get("message_id")
    emoji = data.get("emoji")

    if not message_id or not emoji:
        return jsonify({"error": "message_id and emoji required"}), 400

    conn, cur = get_ict_cursor()
    try:
        # 🔍 Check if user already reacted (any emoji)
        cur.execute("""
            SELECT id, emoji FROM message_reactions
            WHERE message_id=%s AND user_id=%s
        """, (message_id, user_id))
        existing = cur.fetchone()

        if existing:
            # ✅ MySQL cursor returns tuple — handle both tuple/dict cases
            existing_id = existing["id"] if isinstance(existing, dict) else existing[0]
            existing_emoji = existing["emoji"] if isinstance(existing, dict) else existing[1]

            if existing_emoji == emoji:
                # ✅ Same emoji → toggle off (remove)
                cur.execute("DELETE FROM message_reactions WHERE id=%s", (existing_id,))
                action = "removed"
            else:
                # ✅ Different emoji → replace old with new
                cur.execute("UPDATE message_reactions SET emoji=%s WHERE id=%s", (emoji, existing_id))
                action = "updated"
        else:
            # ✅ First-time reaction
            cur.execute("""
                INSERT INTO message_reactions (message_id, user_id, emoji)
                VALUES (%s, %s, %s)
            """, (message_id, user_id, emoji))
            action = "added"

        conn.commit()

        # 🔹 Fetch updated list of reactions
        cur.execute("""
            SELECT emoji, COUNT(*) AS count
            FROM message_reactions
            WHERE message_id=%s
            GROUP BY emoji
        """, (message_id,))
        reactions = cur.fetchall()
        

        # 📡 Emit update
        socketio.emit("reaction_update", {
            "message_id": message_id,
            "reactions": reactions
        }, broadcast=True)

        return jsonify({"success": True, "action": action, "reactions": reactions})

    except Exception as e:
        conn.rollback()
        logger.info("Reaction error:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()



@socketio.on("send_reaction")
def handle_reaction(data):
    """Handle real-time emoji reactions (one per user per message)."""
    token = data.get("token")
    message_id = data.get("message_id")
    emoji = data.get("emoji")

    # 🔐 Validate token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["user_id"]
    except Exception:
        emit("auth_error", {"error": "Invalid token"})
        return

    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            SELECT id, emoji FROM message_reactions
            WHERE message_id=%s AND user_id=%s
        """, (message_id, user_id))
        existing = cur.fetchone()

        if existing:
            existing_id = existing["id"] if isinstance(existing, dict) else existing[0]
            existing_emoji = existing["emoji"] if isinstance(existing, dict) else existing[1]

            if existing_emoji == emoji:
                # ✅ Same emoji — remove
                cur.execute("DELETE FROM message_reactions WHERE id=%s", (existing_id,))
                action = "removed"
            else:
                # ✅ Replace with new emoji
                cur.execute("UPDATE message_reactions SET emoji=%s WHERE id=%s", (emoji, existing_id))
                action = "updated"
        else:
            # ✅ Add new emoji
            cur.execute("""
                INSERT INTO message_reactions (message_id, user_id, emoji)
                VALUES (%s, %s, %s)
            """, (message_id, user_id, emoji))
            action = "added"

        conn.commit()

        # Fetch new list
        cur.execute("""
            SELECT emoji, COUNT(*) AS count
            FROM message_reactions
            WHERE message_id=%s
            GROUP BY emoji
        """, (message_id,))
        reactions = cur.fetchall()

        emit("reaction_update", {
            "message_id": message_id,
            "emoji": emoji,
            "action": action,
            "reactions": reactions
        }, broadcast=True)

    except Exception as e:
        conn.rollback()
        logger.info("Socket reaction error:", e)
        emit("error", {"error": str(e)})
    finally:
        cur.close()
        conn.close()



@app.route("/seen/<int:conversation_id>", methods=["POST"])
@token_required
def mark_seen(conversation_id):
    uid = request.user_id
    conn, cur = get_ict_cursor()
    try:
        # Update messages as seen
        cur.execute("""
            UPDATE messages
            SET seen = 1, seen_time = %s
            WHERE conversation_id = %s
              AND sender_id != %s
              AND seen = 0
        """, (now_ist().strftime("%Y-%m-%d %H:%M:%S"), conversation_id, uid))
        conn.commit()

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

    # ⭐ EMIT REAL-TIME SEEN EVENT (this is the missing part)
    socketio.emit(
        "messages_marked_seen",
        {"conversation_id": conversation_id},
        room=f"conv_{conversation_id}"
    )

    return jsonify({"success": True})



@app.route("/delete_user_from_conversation", methods=["POST"])
@token_required
def delete_user_from_conversation():
    try:
        data = request.get_json() or {}

        conversation_id = data.get("conversation_id")
        user_id_to_remove = data.get("user_id")
        session_id = data.get("session_id")

        if not conversation_id or not user_id_to_remove:
            return jsonify({
                "success": False,
                "error": "conversation_id and user_id are required"
            }), 400

        # ---------------------------
        # Fetch actor (current user)
        # ---------------------------
        book_conn, book_cur = get_book_cursor()
        book_cur.execute("SELECT username FROM userss WHERE id=%s", (request.user_id,))
        actor = book_cur.fetchone()
        actor_name = actor["username"] if actor else "Unknown"
        book_cur.close()
        book_conn.close()

        conn, cur = get_ict_cursor()

        # 🔹 Fetch conversation row
        cur.execute(
            "SELECT user1_id, user2_id FROM conversations WHERE id = %s",
            (conversation_id,)
        )
        convo = cur.fetchone()

        if not convo:
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Conversation not found"}), 404

        user1 = convo["user1_id"]
        user2 = convo["user2_id"]

        deleted_column = None

        # ---------------------------
        # Find other user's name
        # ---------------------------
        other_user_id = user2 if user1 == user_id_to_remove else user1

        book_conn, book_cur = get_book_cursor()
        book_cur.execute("SELECT username FROM userss WHERE id=%s", (other_user_id,))
        other_user = book_cur.fetchone()
        other_user_name = other_user["username"] if other_user else "Unknown"
        book_cur.close()
        book_conn.close()

        # ---------------------------
        # Nullify the correct column
        # ---------------------------
        if user1 == user_id_to_remove:
            deleted_column = "user1_id"
            cur.execute("UPDATE conversations SET user1_id = NULL WHERE id = %s", (conversation_id,))
        elif user2 == user_id_to_remove:
            deleted_column = "user2_id"
            cur.execute("UPDATE conversations SET user2_id = NULL WHERE id = %s", (conversation_id,))
        else:
            cur.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Given user_id is not part of this conversation"
            }), 400

        # 🔹 Check updated values
        cur.execute("SELECT user1_id, user2_id FROM conversations WHERE id = %s", (conversation_id,))
        updated = cur.fetchone()
        updated_user1 = updated["user1_id"]
        updated_user2 = updated["user2_id"]

        # ---------------------------
        # CASE: BOTH users left
        # ---------------------------
        if updated_user1 is None and updated_user2 is None:

            # Delete conversation
            cur.execute("DELETE FROM conversations WHERE id = %s", (conversation_id,))

            # Delete logs for this conversation
            cur.execute("DELETE FROM `user_delete_data` WHERE conversation_id = %s", (conversation_id,))

            conn.commit()

            cur.close()
            conn.close()

            return jsonify({
                "success": True,
                "message": "Conversation deleted because both users left",
                "deleted": True
            }), 200

        # ---------------------------
        # Normal delete-user scenario
        # ---------------------------
        cur.execute("""
            INSERT INTO `user_delete_data` (conversation_id, user_id, deleted_column, deleted_at)
            VALUES (%s, %s, %s, %s)
        """, (
            conversation_id,
            user_id_to_remove,
            deleted_column,
            now_ist().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()

        # 🔥 Activity log
        log_activity(
            user_id=request.user_id,
            username=actor_name,
            session_id=session_id,
            action="Leave Conversation",
            details=f"{actor_name} de conversation with {other_user_name} (Conversation ID: {conversation_id})"
        )

        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"User {user_id_to_remove} removed from {deleted_column}",
            "deleted_column": deleted_column,
            "deleted": False
        }), 200

    except Exception as e:
        logger.info("Delete user error:", e)
        return jsonify({"success": False, "error": str(e)}), 500
    


@app.route("/check_conversation/<int:user1>/<int:user2>", methods=["GET"])
@token_required
def check_conversation(user1, user2):
    conn, cur = get_ict_cursor()

    # STEP 1: Find ANY matching conversation
    cur.execute("""
        SELECT id, user1_id, user2_id
        FROM conversations
        WHERE 
            (
                (user1_id = %s OR user1_id IS NULL)
             AND user2_id = %s
            )
            OR
            (
                (user2_id = %s OR user2_id IS NULL)
             AND user1_id = %s
            )
    """, (user1, user2, user1, user2))

    convo = cur.fetchone()

    if not convo:
        cur.close()
        conn.close()
        return jsonify({"exists": False})

    convo_id = convo["id"]

    # STEP 2: Check IF *THIS CURRENT USER* deleted earlier
    cur.execute("""
        SELECT deleted_column
        FROM user_delete_data
        WHERE conversation_id = %s AND user_id = %s
        ORDER BY id DESC LIMIT 1
    """, (convo_id, user1))
    deleted_self = cur.fetchone()

    cur.close()
    conn.close()

    # ❌ User deleted earlier → treat as "no conversation" (so Connect = Restore)
    if deleted_self:
        return jsonify({"exists": False})

    # ✅ Conversation exists normally
    return jsonify({"exists": True})



@app.route("/save_feature_info", methods=["POST"])
@token_required     # if you use token auth
def save_feature_info():
    data = request.get_json()
    user_id = data.get("user_id")
    popup_id = data.get("popup_id")

    if not user_id or not popup_id:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    conn, cur = get_ict_cursor()

    # check if exists
    cur.execute("""
        SELECT id FROM `feature_info`
        WHERE user_id=%s AND popup_id=%s
        LIMIT 1
    """, (user_id, popup_id))

    exists = cur.fetchone()

    if exists:
        return jsonify({"success": True, "already_saved": True})

    # insert
    cur.execute("""
        INSERT INTO `feature_info` (user_id, popup_id)
        VALUES (%s, %s)
    """, (user_id, popup_id))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"success": True})


@app.route("/check_feature_info", methods=["GET"])
@token_required
def check_feature_info():
    user_id = request.args.get("user_id")
    popup_id = request.args.get("popup_id")

    conn, cur = get_ict_cursor()

    cur.execute("""
        SELECT id FROM `feature_info`
        WHERE user_id=%s AND popup_id=%s
        LIMIT 1
    """, (user_id, popup_id))

    exists = cur.fetchone()

    cur.close()
    conn.close()

    return jsonify({"exists": bool(exists)})




#---Group---

@socketio.on("join_group")
def handle_join_group(data):
    token = data.get("token")
    group_id = data.get("group_id")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["user_id"]
        join_room(f"group_{group_id}")
        emit("system", {"msg": f"User {user_id} joined group {group_id}"}, room=f"group_{group_id}")
    except jwt.InvalidTokenError:
        emit("error", {"error": "Invalid token"})


@socketio.on("send_group_message")
def handle_group_message(data):
    token = data.get("token")
    group_id = data.get("group_id")
    message = data.get("message")
    message_type = data.get("message_type", "text")
    reply_to = data.get("reply_to")
    file_size = data.get("file_size")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        sender_id = payload["user_id"]
    except Exception as e:
        emit("error", {"error": f"Invalid token: {str(e)}"})
        return

    # ✅ 1. Get sender_name from BOOK DB
    conn1, cur1 = get_book_cursor()
    cur1.execute("SELECT username FROM userss WHERE id = %s", (sender_id,))
    user_row = cur1.fetchone()
    sender_name = user_row["username"] if user_row else "Unknown User"
    cur1.close()
    conn1.close()

    # ✅ 2. Save message in ICT DB
    # 🕒 Use IST time
    current_time = now_ist()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    
    conn2, cur2 = get_ict_cursor()
    cur2.execute(
        """INSERT INTO group_messages 
        (group_id, sender_id, message, message_type, file_size, reply_to, timestamp) 
        VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (group_id, sender_id, message, message_type, file_size, reply_to, formatted_time)
    )
    conn2.commit()
    message_id = cur2.lastrowid
    cur2.close()
    conn2.close()

    # ✅ 3. Fetch reply message & username (SAME LOGIC AS USER CHAT ✅)
    reply_to_text = None
    reply_to_user = None

    if reply_to:
        try:
            connR, curR = get_ict_cursor()  # ✅ group_messages is in ICT DB
            curR.execute("SELECT message, sender_id FROM group_messages WHERE id = %s", (reply_to,))
            reply_row = curR.fetchone()
            curR.close()
            connR.close()

            if reply_row:
                reply_to_text = reply_row["message"]
                reply_sender_id = reply_row["sender_id"]

                # ✅ Get reply sender username from BOOK DB
                bconn, bcur = get_book_cursor()
                bcur.execute("SELECT username FROM userss WHERE id = %s", (reply_sender_id,))
                buser = bcur.fetchone()
                bcur.close()
                bconn.close()

                if buser:
                    reply_to_user = buser["username"]

        except Exception as e:
            logger.info("❌ Reply Fetch Error:", e)

    # ✅ 4. Build response exactly like user chat structure
    response_data = {
        "id": message_id,
        "group_id": group_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "message": message,
        "file_size": file_size,
        "message_type": message_type,
        "timestamp": datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(),

        "reply_to": reply_to,
        "reply_to_text": reply_to_text,     # ✅ ADDED (frontend needs this)
        "reply_to_user": reply_to_user      # ✅ ADDED (frontend needs this)
    }


    emit("new_group_message", response_data, room=f"group_{group_id}")






@socketio.on("group_typing")
def handle_group_typing(data):
    token = data.get("token"); group_id = data.get("group_id"); username = data.get("username"); typing = data.get("typing", False)
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return
    emit("group_typing", {"group_id": group_id, "username": username, "typing": typing}, room=f"group_{group_id}", include_self=False)





# -------------------- Helpers --------------------

def clean_filename(filename):
    # Keep name EXACTLY the same — except remove illegal characters + %
    filename = os.path.basename(filename)

    # Remove Windows-invalid characters: < > : " / \ | ? *
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)

    # REMOVE % (your new requirement)
    filename = filename.replace('%', '')

    # Do not touch underscores, spaces, unicode, emojis
    return filename.strip()



def allowed_file(filename):
    """Check if the file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_unique_filename(folder, original_filename):
    safe_name = clean_filename(original_filename)   # KEEP EXACT NAME
    name, ext = os.path.splitext(safe_name)

    counter = 1
    new_name = safe_name

    # If file exists → auto add (1), (2), (3)
    while os.path.exists(os.path.join(folder, new_name)):
        new_name = f"{name}({counter}){ext}"
        counter += 1

    return new_name



# -------------------- File Upload --------------------
@app.route("/upload_file", methods=["POST", "OPTIONS"])
def upload_file():
    if request.method == "OPTIONS":
        return "", 200

    if "file" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist("file")
    if len(files) > MAX_FILES_PER_REQUEST:
        return jsonify({"error": f"Too many files. Max {MAX_FILES_PER_REQUEST} allowed."}), 400

    username = request.form.get("username", "guest").strip()
    if not username:
        return jsonify({"error": "Username required"}), 400

    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(username))
    os.makedirs(user_folder, exist_ok=True)

    uploaded_files = []

    for file in files:
        if file.filename == "":
            continue

        if not allowed_file(file.filename):
            return jsonify({"error": f"File type not allowed: {file.filename}"}), 400

        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size > MAX_FILE_SIZE:
            return jsonify({"error": f"{file.filename} exceeds 25MB limit."}), 400

        original_name = file.filename
        saved_name = get_unique_filename(user_folder, original_name)  # ✅ auto-increment naming
        filepath = os.path.join(user_folder, saved_name)

        try:
            file.save(filepath)
            file_url = f"{request.host_url}uploads/{username}/{saved_name}"
            uploaded_files.append({
                "original_name": original_name,
                "saved_name": saved_name,
                "url": file_url
            })
        except Exception as e:
            return jsonify({"error": f"Failed to save {original_name}", "details": str(e)}), 500

    return jsonify({"uploads": uploaded_files}), 200


# -------------------- Serve Uploaded Files --------------------
@app.route("/uploads/<username>/<path:filename>", methods=["GET", "OPTIONS"])
def serve_uploaded_file(username, filename):
    if request.method == "OPTIONS":
        return "", 200
    try:
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(username))
        return send_from_directory(user_folder, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to serve file: {str(e)}"}), 500

#---------------------------- Group Section ----------------------------



@app.route("/create_group", methods=["POST"])
@token_required
def create_group():
    created_by = request.user_id
    session_id = None

    group_image = None
    members = []

    # Case 1: JSON (no image)
    if request.is_json:
        data = request.get_json()
        group_name = data.get("group_name")
        members = data.get("members", []) or []
        session_id = data.get("session_id")
    # Case 2: FormData (with image)
    else:
        group_name = request.form.get("group_name")
        members_str = request.form.get("members", "[]")
        session_id = request.form.get("session_id")
        try:
            members = json.loads(members_str)
            if not isinstance(members, list):
                return jsonify({"error": "Members must be a list"}), 400
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid members JSON format"}), 400

        image = request.files.get("group_image")

        if not group_name:
            return jsonify({"error": "Group name required"}), 400

        # Create a folder for this group inside your static upload folder
        safe_group_name = secure_filename(group_name) or "group"
        group_folder = os.path.join(GROUP_UPLOAD_FOLDER, safe_group_name)
        try:
            os.makedirs(group_folder, exist_ok=True)
        except OSError as e:
            app.logger.exception("Failed to create group folder")
            return jsonify({"error": f"Failed to create group folder: {str(e)}"}), 500

        # If image is uploaded, save it
        if image:
            filename = secure_filename(image.filename)
            filepath = os.path.join(group_folder, filename)
            try:
                image.save(filepath)
                # set a web-accessible path (do not expose server absolute path)
                group_image = f"/{group_folder}/{filename}"
            except Exception as e:
                app.logger.exception("Failed to save group image")
                return jsonify({"error": f"Failed to save image: {str(e)}"}), 500

    if not group_name:
        return jsonify({"error": "Group name required"}), 400

    # ensure members is a list of ints (or strings as your DB expects)
    if not isinstance(members, list):
        return jsonify({"error": "Members must be a list"}), 400

    # Optionally sanitize/convert member ids
    sanitized_members = []
    for uid in members:
        try:
            sanitized_members.append(int(uid))
        except Exception:
            # ignore invalid ids or respond with error
            return jsonify({"error": f"Invalid member id: {uid}"}), 400

    conn, cur = get_ict_cursor()
    try:
        # Insert group (quote table identifiers)
        cur.execute(
            "INSERT INTO `groups` (group_name, created_by, group_image) VALUES (%s, %s, %s)",
            (group_name, created_by, group_image),
        )
        # fetch inserted id in a DB-agnostic way
        group_id = cur.lastrowid

        # Add creator as admin (use parameterized role)
        cur.execute(
            "INSERT INTO `group_members` (group_id, user_id, role) VALUES (%s, %s, %s)",
            (group_id, created_by, "admin"),
        )

        # Bulk insert members (skip if empty)
        if sanitized_members:
            # remove creator if included in members to avoid duplicate pk error (if you have unique constraint)
            member_rows = [
                (group_id, uid, "member") for uid in sanitized_members if uid != int(created_by)
            ]
            if member_rows:
                cur.executemany(
                    "INSERT INTO `group_members` (group_id, user_id, role) VALUES (%s, %s, %s)",
                    member_rows,
                )

        conn.commit()

        # ✅ Fetch username from DB using request.user_id from token
        conn, cur = get_book_cursor()
        cur.execute("SELECT username FROM userss WHERE id=%s", (request.user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()
    
        username = user["username"] if user else "Unknown"

        log_activity(
            user_id=request.user_id,
            username=username,
            session_id=session_id,
            action="Create Group",
            details=f"Create a Group {group_name} by {username}"
        )

        return jsonify({
            "success": True,
            "group_id": group_id,
            "group_image": group_image,
            "folder": f"/{group_folder}" if group_image else None
        })

    except Exception as e:
        logger.info("🔥 /groups error:", str(e))
        logger.error("🔥 /groups DB error: %s", str(e))
    
        return jsonify({"error": str(e)})
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass

   



def safe_datetime(val):
    if not val:
        return None
    if isinstance(val, str):
        try:
            return datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
        except:
            return val  # return as-is if format unknown
    return val


@app.route("/groups", methods=["GET"])
@token_required
def get_groups():
    user_id = request.user_id
    conn, cur = get_ict_cursor()
    book_conn, book_cur = get_book_cursor()

    try:
        # Base query (safe for old servers)
        cur.execute("""
            SELECT g.id, g.group_name, g.group_image, g.created_by, g.created_at
            FROM `groups` g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = %s
            ORDER BY g.created_at DESC
        """, (user_id,))

        groups = cur.fetchall()
        result = []

        for g in groups:
            group_id = g["id"]

            # ------ SAFE last message lookup ------
            try:
                cur.execute("""
                    SELECT message, message_type, timestamp, sender_id
                    FROM `group_messages`
                    WHERE group_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                """, (group_id,))
                last = cur.fetchone()
            except:
                last = None

            last_message = last["message"] if last else None
            last_message_type = last["message_type"] if last else None
            last_time = None
            if last and last.get("timestamp"):
                try:
                    last_time = last["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                except:
                    last_time = None

            # Sender username lookup
            sender_name = None
            if last and last.get("sender_id"):
                try:
                    book_cur.execute("SELECT `username` FROM userss WHERE id=%s", (last["sender_id"],))
                    sender = book_cur.fetchone()
                    sender_name = sender["username"] if sender else None
                except:
                    sender_name = None


                        # ---------- 🔥 UNREAD COUNT ----------
            unread = 0
            try:
                cur.execute("""
                    SELECT COUNT(*) AS unread
                    FROM `group_messages` gm
                    WHERE gm.group_id = %s
                    AND gm.sender_id != %s        
                    AND gm.id NOT IN (
                        SELECT message_id 
                        FROM group_message_seen 
                        WHERE user_id = %s
                    )
                """, (group_id, user_id, user_id))

                row = cur.fetchone()
                unread = row["unread"] if row else 0
            except:
                unread = 0

            result.append({
                "id": g["id"],
                "group_name": g["group_name"],
                "group_image": g["group_image"],
                "created_by": g["created_by"],
                "created_at": g["created_at"].strftime("%Y-%m-%d %H:%M:%S") if g["created_at"] else None,

                # NEW but SAFE
                "last_message": last_message,
                "last_message_type": last_message_type,
                "last_time": last_time,
                "last_sender": sender_name,

                "unread": unread,
                "type": "group",
                "hasConversation": True
            })

        return jsonify(result)

    except Exception as e:
        import traceback
        logger.info("🔥 /groups error: %s", str(e))     # logs the error
        logger.info(traceback.format_exc())             # logs full traceback
        return jsonify({"error": "Internal server error"}), 500

    finally:
        try: cur.close(); conn.close()
        except: pass
        try: book_cur.close(); book_conn.close()
        except: pass




@app.route("/group_messages/<int:group_id>", methods=["GET"])
@token_required
def get_group_messages(group_id):
    try:
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", 100))
    except:
        offset = 0
        limit = 100

    conn, cur = get_ict_cursor()

    # 1️⃣ Fetch messages
    cur.execute("""
        SELECT gm.*, rm.message AS reply_message, rm.sender_id AS reply_sender_id
        FROM group_messages gm
        LEFT JOIN group_messages rm ON gm.reply_to = rm.id
        WHERE gm.group_id = %s
        ORDER BY gm.id DESC
        LIMIT %s OFFSET %s
    """, (group_id, limit, offset))

    rows = cur.fetchall()
    if not rows:
        cur.close()
        conn.close()
        return jsonify([])

    messages = list(reversed(rows))
    message_ids = [m["id"] for m in messages]

    # 2️⃣ Fetch reactions
    format_ids = ",".join(["%s"] * len(message_ids))
    cur.execute(f"""
        SELECT id, message_id, user_id, emoji
        FROM group_message_reactions
        WHERE message_id IN ({format_ids})
    """, tuple(message_ids))
    reactions = cur.fetchall()

    # 3️⃣ Group reactions + collect reaction user IDs ✅
    reaction_map = {}
    reaction_user_ids = set()

    for r in reactions:
        reaction_user_ids.add(r["user_id"])
        reaction_map.setdefault(r["message_id"], []).append({
            "id": r["id"],
            "user_id": r["user_id"],
            "emoji": r["emoji"]
        })

    # 4️⃣ Collect message sender + reply sender IDs
    sender_ids = set()
    for m in messages:
        if m.get("sender_id"):
            sender_ids.add(m["sender_id"])
        if m.get("reply_sender_id"):
            sender_ids.add(m["reply_sender_id"])

    # 🔥 MERGE all user IDs (senders + reactions)
    all_user_ids = sender_ids | reaction_user_ids

    # 5️⃣ Fetch usernames from BOOK DB
    user_map = {}
    if all_user_ids:
        bconn, bcur = get_book_cursor()
        format_users = ",".join(["%s"] * len(all_user_ids))
        bcur.execute(
            f"SELECT id, username FROM userss WHERE id IN ({format_users})",
            tuple(all_user_ids)
        )
        for row in bcur.fetchall():
            user_map[row["id"]] = row["username"]
        bcur.close()
        bconn.close()

    # 6️⃣ Build final response
    result = []
    for m in messages:
        msg = dict(m)

        msg["sender_name"] = user_map.get(msg.get("sender_id"), "Unknown")

        # Reply block
        if msg.get("reply_message"):
            msg["reply_to_message"] = {
                "sender_name": user_map.get(msg.get("reply_sender_id"), "Unknown"),
                "message": msg.get("reply_message")
            }
        else:
            msg["reply_to_message"] = None

        # ✅ Attach reactions WITH usernames
        msg["reactions"] = [
            {
                "id": r["id"],
                "emoji": r["emoji"],
                "user_id": r["user_id"],
                "username": user_map.get(r["user_id"], "Unknown")
            }
            for r in reaction_map.get(msg["id"], [])
        ]

        result.append(msg)

    cur.close()
    conn.close()
    return jsonify(result)




@app.route("/send_group_message", methods=["POST"])
@token_required
def send_group_message():
    data = request.get_json()
    group_id = data.get("group_id")
    message = data.get("message")
    message_type = data.get("message_type", "text")
    reply_to = data.get("reply_to")
    sender_id = request.user_id

    if not group_id or not message:
        return jsonify({"error": "Missing fields"}), 400

    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            INSERT INTO `group_messages` (group_id, sender_id, message, message_type, reply_to)
            VALUES (%s, %s, %s, %s, %s)
        """, (group_id, sender_id, message, message_type, reply_to))
        conn.commit()
        msg_id = cur.lastrowid
        return jsonify({"success": True, "message_id": msg_id})
    finally:
        cur.close()
        conn.close()


@socketio.on("send_group_reaction")
def handle_group_reaction(data):
    token = data.get("token")
    message_id = data.get("message_id")
    emoji = data.get("emoji")

    if not token or not message_id or not emoji:
        return

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["user_id"]
    except:
        return

    try:
        # ---------- ICT DB ----------
        conn, cur = get_ict_cursor()

        # Toggle reaction
        cur.execute("""
            SELECT 1 FROM group_message_reactions
            WHERE message_id=%s AND user_id=%s AND emoji=%s
        """, (message_id, user_id, emoji))

        if cur.fetchone():
            cur.execute("""
                DELETE FROM group_message_reactions
                WHERE message_id=%s AND user_id=%s AND emoji=%s
            """, (message_id, user_id, emoji))
        else:
            cur.execute("""
                INSERT INTO group_message_reactions (message_id, user_id, emoji)
                VALUES (%s, %s, %s)
            """, (message_id, user_id, emoji))

        conn.commit()

        # Fetch reactions again
        cur.execute("""
            SELECT emoji, user_id
            FROM group_message_reactions
            WHERE message_id=%s
        """, (message_id,))
        raw_reactions = cur.fetchall()

        cur.close()
        conn.close()

        # ---------- BOOKTRACKER DB ----------
        user_ids = list({r["user_id"] for r in raw_reactions})
        user_map = {}

        if user_ids:
            book_conn, book_cur = get_book_cursor()
            format_ids = ",".join(["%s"] * len(user_ids))

            book_cur.execute(
                f"SELECT id, username FROM userss WHERE id IN ({format_ids})",
                tuple(user_ids)
            )

            for u in book_cur.fetchall():
                user_map[u["id"]] = u["username"]

            book_cur.close()
            book_conn.close()

        # ✅ BUILD CLEAN RESPONSE (IMPORTANT)
                # ✅ BUILD CLEAN RESPONSE
        reactions = [
            {
                "emoji": r["emoji"],
                "user_id": r["user_id"],
                "username": user_map.get(r["user_id"], "Unknown")
            }
            for r in raw_reactions
        ]

        # 🔥 DEBUG OUTPUT
        print("📤 SENDING GROUP REACTION UPDATE")
        print("Message ID:", message_id)
        print("Reactions payload:")
        for r in reactions:
            print(r)

        emit(
            "group_reaction_update",
            {
                "message_id": message_id,
                "reactions": reactions
            },
            broadcast=True
        )


    except Exception as e:
        print("❌ Group Reaction Error:", e)



@app.route("/delete_group_message/<int:msg_id>", methods=["DELETE"])
@token_required
def delete_group_message(msg_id):
    user_id = request.user_id  # ✅ same as working 1-to-1 delete
    ict_conn, ict_cur = get_ict_cursor()

    try:
        # 🔹 Check if the message exists and belongs to this user
        ict_cur.execute(
            "SELECT sender_id, group_id FROM group_messages WHERE id = %s",
            (msg_id,),
        )
        msg = ict_cur.fetchone()
        if not msg:
            return jsonify({"error": "Message not found"}), 404

        if msg["sender_id"] != user_id:
            return jsonify({"error": "You can only delete your own messages"}), 403

        # 🔹 Delete reactions first
        ict_cur.execute("DELETE FROM group_message_reactions WHERE message_id = %s", (msg_id,))

        # 🔹 Delete message from DB
        ict_cur.execute("DELETE FROM group_messages WHERE id = %s", (msg_id,))
        ict_conn.commit()

        # 🔹 Notify all clients in that group (socket.io)
        socketio.emit(
            "delete_group_message",
            {"id": msg_id, "group_id": msg["group_id"]},
            room=str(msg["group_id"]),
        )

        return jsonify({"success": True, "message": "Group message deleted successfully"})

    except Exception as e:
        ict_conn.rollback()
        logger.info("Delete group message error:", e)
        return jsonify({"error": "Internal server error"}), 500

    finally:
        ict_cur.close()
        ict_conn.close()


@app.route("/get_group_members", methods=["GET"])
@token_required
def get_group_members():
    group_id = request.args.get("group_id")

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn, cur = get_ict_cursor()
    book_conn, book_cur = get_book_cursor()

    try:
        cur.execute("""
            SELECT user_id,role FROM `group_members`
            WHERE group_id = %s
        """, (group_id,))
        members = cur.fetchall()

        result = []
        for m in members:
            book_cur.execute("SELECT username FROM userss WHERE id = %s", (m["user_id"],))
            user = book_cur.fetchone()
            if user:
                result.append({
                    "user_id": m["user_id"],
                    "username": user["username"],
                    "role": m["role"]
                })

        return jsonify(result)

    except Exception as e:
        logger.info("🔥 get_group_members error:", e)
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
        conn.close()
        book_conn.close()
        book_cur.close()


@app.route("/get_group_media", methods=["GET"])
@token_required
def get_group_media():
    group_id = request.args.get("group_id")

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn, cur = get_ict_cursor()

    try:
        cur.execute("""
            SELECT message AS file_url, message_type
            FROM `group_messages`
            WHERE group_id = %s 
            AND message_type IN ('image', 'file')
            ORDER BY timestamp DESC
        """, (group_id,))

        files = cur.fetchall()

        return jsonify(files)

    except Exception as e:
        logger.info("🔥 get_group_media error:", e)
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
        conn.close()



@app.route("/add_group_member", methods=["POST"])
@token_required
def add_group_member():
    data = request.json or {}
    group_id = data.get("group_id")
    user_id = data.get("user_id")      # member to add
    session_id = data.get("session_id")

    if not group_id or not user_id:
        return jsonify({"success": False, "error": "group_id and user_id are required"}), 400

    ict_conn, ict_cur = get_ict_cursor()
    book_conn, book_cur = get_book_cursor()

    try:
        # 1️⃣ Insert member into group_members
        ict_cur.execute(
            "INSERT INTO `group_members` (group_id, user_id, role) VALUES (%s, %s, 'member')",
            (group_id, user_id)
        )
        ict_conn.commit()

        # 2️⃣ Fetch added member details (for UI)
        book_cur.execute(
            "SELECT id AS user_id, username FROM userss WHERE id = %s",
            (user_id,)
        )
        added_user = book_cur.fetchone()

        # 3️⃣ Fetch actor (current logged-in user)
        book_cur.execute(
            "SELECT username FROM userss WHERE id = %s",
            (request.user_id,)
        )
        actor_row = book_cur.fetchone()
        actor_name = actor_row["username"] if actor_row else "Unknown"

        # 4️⃣ Fetch group name
        ict_cur.execute(
            "SELECT group_name FROM `groups` WHERE id = %s",
            (group_id,)
        )
        group_row = ict_cur.fetchone()
        group_name = group_row["group_name"] if group_row else "Unknown"

        # 5️⃣ Log activity
        log_activity(
            user_id=request.user_id,
            username=actor_name,
            session_id=session_id,
            action="Add Member in Group",
            details=f"{actor_name} added {added_user['username'] if added_user else 'Unknown user'} to group '{group_name}' (ID: {group_id})"
        )

        return jsonify({"success": True, "user": added_user})

    except Exception as e:
        logger.info("❌ add_group_member error:", e)
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        try:
            ict_cur.close()
            ict_conn.close()
        except Exception:
            pass
        try:
            book_cur.close()
            book_conn.close()
        except Exception:
            pass



@app.route("/leave_group", methods=["POST"])
@token_required
def leave_group():
    data = request.json or {}

    group_id = data.get("group_id")
    user_id = data.get("user_id")           # user leaving
    session_id = data.get("session_id")     # for activity log

    if not group_id or not user_id:
        return jsonify({"success": False, "error": "Missing group_id or user_id"}), 400

    # DB Connections
    ict_conn, ict_cur = get_ict_cursor()
    book_conn, book_cur = get_book_cursor()

    try:
        # 1️⃣ Delete user from group
        ict_cur.execute("""
            DELETE FROM group_members
            WHERE group_id = %s AND user_id = %s
        """, (group_id, user_id))
        ict_conn.commit()

        # 2️⃣ Fetch actor username
        book_cur.execute("SELECT username FROM userss WHERE id=%s", (request.user_id,))
        actor = book_cur.fetchone()
        actor_name = actor["username"] if actor else "Unknown"

        # 3️⃣ Fetch group name
        ict_cur.execute("SELECT group_name FROM `groups` WHERE id=%s", (group_id,))
        group = ict_cur.fetchone()
        group_name = group["group_name"] if group else "Unknown"

        # 4️⃣ Log activity
        log_activity(
            user_id=request.user_id,
            username=actor_name,
            session_id=session_id,
            action="Leave Group",
            details=f"{actor_name} left group '{group_name}' (ID: {group_id})"
        )

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        try:
            ict_cur.close()
            ict_conn.close()
        except:
            pass
        try:
            book_cur.close()
            book_conn.close()
        except:
            pass





#-----------------------Notifcation---------------------------

@app.route("/get_notification_setting", methods=["GET"])
@token_required
def get_notification_setting():
    user_id = request.user_id

    conn, cur = get_book_cursor()
    cur.execute("SELECT allow_notification FROM user_notification_settings WHERE user_id=%s", (user_id,))
    row = cur.fetchone()

    if not row:
        return jsonify({"allow_notification": 1})
    
    return jsonify(row)


@app.route("/update_notification_setting", methods=["POST"])
@token_required
def update_notification_setting():
    data = request.json
    user_id = request.user_id
    allow = data.get("allow", 1)

    conn, cur = get_book_cursor()
    cur.execute(
                "INSERT INTO user_notification_settings(user_id, allow_notification) VALUES (%s,%s) ON DUPLICATE KEY UPDATE allow_notification=%s",
        (user_id, allow, allow)
    )
    conn.commit()

    return jsonify({"success": True})



@app.route("/group_seen/<int:group_id>", methods=["POST"])
@token_required
def mark_group_seen(group_id):
    user_id = request.user_id
    current_time = now_ist()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            INSERT INTO `group_message_seen` (group_id, user_id, message_id, seen_time)
            SELECT gm.group_id, %s, gm.id, %s
            FROM group_messages gm
            LEFT JOIN group_message_seen gms
                ON gms.message_id = gm.id AND gms.user_id = %s
            WHERE gm.group_id = %s
              AND gm.sender_id != %s     -- 🚀 do not include own messages
              AND gms.id IS NULL
        """, (user_id, formatted_time, user_id, group_id, user_id))

        conn.commit()
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"error": "Failed to update seen"}), 500

    finally:
        try: cur.close(); conn.close()
        except: pass



@app.route("/group_message_info/<int:msg_id>", methods=["GET"])
@token_required
def group_message_info(msg_id):

    # ICT DB
    ict_conn, ict_cur = get_ict_cursor()

    # BOOK DB
    book_conn, book_cur = get_book_cursor()

    try:
        # 🔥 1. Fetch sender_id first
        ict_cur.execute("SELECT sender_id, group_id FROM group_messages WHERE id = %s", (msg_id,))
        msg = ict_cur.fetchone()
        if not msg:
            return jsonify({"error": "Message not found"}), 404

        sender_id = msg["sender_id"]
        group_id = msg["group_id"]

        # 🔥 2. Fetch SEEN users
        ict_cur.execute("""
            SELECT user_id, seen_time
            FROM group_message_seen
            WHERE message_id = %s
            ORDER BY seen_time ASC
        """, (msg_id,))
        seen_raw = ict_cur.fetchall()

        # Append usernames
        seen = []
        for row in seen_raw:
            book_cur.execute("SELECT username FROM userss WHERE id = %s", (row["user_id"],))
            u = book_cur.fetchone()
            seen.append({
                "user_id": row["user_id"],
                "username": u["username"] if u else "Unknown",
                "seen_at": row["seen_time"]
            })

        # 🔥 3. Fetch ALL group members
        ict_cur.execute("SELECT user_id FROM group_members WHERE group_id = %s", (group_id,))
        members = ict_cur.fetchall()
        member_ids = [m["user_id"] for m in members]

        # 🔥 4. Delivered = members NOT in seen & NOT sender
        seen_user_ids = {row["user_id"] for row in seen_raw}

        delivered = []
        for uid in member_ids:
            if uid not in seen_user_ids and uid != sender_id:
                book_cur.execute("SELECT username FROM userss WHERE id = %s", (uid,))
                u = book_cur.fetchone()
                delivered.append({
                    "user_id": uid,
                    "username": u["username"] if u else "Unknown"
                })

        return jsonify({
            "seen": seen,
            "delivered": delivered,
            "sender_id": sender_id              # 🔥 IMPORTANT
        })

    except Exception as e:
        return jsonify({"error": "Something went wrong"}), 500

    finally:
        try: ict_cur.close(); ict_conn.close()
        except: pass
        try: book_cur.close(); book_conn.close()
        except: pass



@app.route("/recent_chats", methods=["GET"])
@token_required
def recent_chats():
    user_id = request.user_id   # ✅ FIXED

    conn, cur = get_ict_cursor()

    # -------------------------
    # 1️⃣ Recent Direct Chats
    # -------------------------
    cur.execute("""
        SELECT 
            c.id AS conversation_id,
            IF(c.user1_id=%s, c.user2_id, c.user1_id) AS other_user_id,
            MAX(m.timestamp) AS last_time
        FROM conversations c
        JOIN messages m ON m.conversation_id = c.id
        WHERE %s IN (c.user1_id, c.user2_id)
        GROUP BY c.id
        ORDER BY last_time DESC
        LIMIT 10
    """, (user_id, user_id))

    direct = cur.fetchall()

    # -------------------------
    # 2️⃣ Recent Group Chats
    # -------------------------
    cur.execute("""
        SELECT 
            gm.group_id,
            MAX(gm.timestamp) AS last_time
        FROM group_messages gm
        JOIN group_members mem ON mem.group_id = gm.group_id
        WHERE mem.user_id = %s
        GROUP BY gm.group_id
        ORDER BY last_time DESC
        LIMIT 10
    """, (user_id,))

    groups = cur.fetchall()

    cur.close()
    conn.close()

    # -------------------------
    # 3️⃣ Fetch Names
    # -------------------------
    user_ids = {d["other_user_id"] for d in direct}
    group_ids = {g["group_id"] for g in groups}

    user_map = {}
    group_map = {}

    if user_ids:
        bconn, bcur = get_book_cursor()
        bcur.execute(
            f"SELECT id, username FROM userss WHERE id IN ({','.join(['%s']*len(user_ids))})",
            tuple(user_ids)
        )
        for u in bcur.fetchall():
            user_map[u["id"]] = u["username"]
        bcur.close()
        bconn.close()

    if group_ids:
        conn, cur = get_ict_cursor()
        cur.execute(
            f"SELECT id, group_name FROM `groups` WHERE id IN ({','.join(['%s']*len(group_ids))})",
            tuple(group_ids)
        )
        for g in cur.fetchall():
            group_map[g["id"]] = g["group_name"]
        cur.close()
        conn.close()

    # -------------------------
    # 4️⃣ Merge + Sort
    # -------------------------
    combined = []

    for d in direct:
        combined.append({
            "id": d["other_user_id"],
            "type": "user",
            "name": user_map.get(d["other_user_id"], "Unknown"),
            "time": d["last_time"]
        })

    for g in groups:
        combined.append({
            "id": g["group_id"],
            "type": "group",
            "name": group_map.get(g["group_id"], "Group"),
            "time": g["last_time"]
        })

    combined.sort(key=lambda x: x["time"], reverse=True)

    for c in combined:
        c.pop("time", None)

    return jsonify(combined)




def delete_old_messages_and_files():
    logger.info("🧹 Running daily cleanup...")

    # -------------------------------
    # 1️⃣ DELETE OLD PRIVATE MESSAGES
    # -------------------------------
    ict_conn, ict_cur = get_ict_cursor()
    try:
        ict_cur.execute("""
            SELECT id, message_type, message 
            FROM messages
            WHERE timestamp < NOW() - INTERVAL 180 DAY
        """)
        private_msgs = ict_cur.fetchall()

        private_files_deleted = 0

        for msg in private_msgs:
            msg_id = msg["id"]
            msg_type = msg["message_type"]
            file_path = msg["message"]

            # Delete physical file (private chat)
            if msg_type in ["image", "file"] and file_path:
                try:
                    if file_path.startswith("http"):
                        # Extract "uploads/<username>/<file>"
                        relative = "/" + "/".join(file_path.split("/", 3)[3:])
                    else:
                        relative = file_path

                    relative = relative.lstrip("/")
                    abs_path = os.path.join(UPLOAD_FOLDER, relative)

                    if os.path.exists(abs_path):
                        os.remove(abs_path)
                        private_files_deleted += 1

                except Exception as e:
                    logger.info("❌ Private file deletion error:", e)

            ict_cur.execute("DELETE FROM messages WHERE id = %s", (msg_id,))

        ict_conn.commit()
        logger.info(f"🗑 PRIVATE CHAT → Deleted {len(private_msgs)} msgs, {private_files_deleted} files")

    finally:
        ict_cur.close()
        ict_conn.close()



    # --------------------------------
    # 2️⃣ DELETE OLD GROUP MESSAGES
    # --------------------------------
    ict_conn2, ict_cur2 = get_ict_cursor()
    try:
        ict_cur2.execute("""
            SELECT id, message_type, message 
            FROM `group_messages`
            WHERE timestamp < NOW() - INTERVAL 180 DAY
        """)
        group_msgs = ict_cur2.fetchall()

        group_files_deleted = 0

        for msg in group_msgs:
            msg_id = msg["id"]
            msg_type = msg["message_type"]
            file_path = msg["message"]

            # Delete physical file (group chat)
            if msg_type in ["image", "file"] and file_path:
                try:
                    if file_path.startswith("http"):
                        # Extract "uploads/<username>/<file>"
                        relative = "/" + "/".join(file_path.split("/", 3)[3:])
                    else:
                        relative = file_path

                    relative = relative.lstrip("/")
                    abs_path = os.path.join(UPLOAD_FOLDER, relative)

                    if os.path.exists(abs_path):
                        os.remove(abs_path)
                        group_files_deleted += 1

                except Exception as e:
                    logger.info("❌ Group file deletion error:", e)

            ict_cur2.execute("DELETE FROM group_messages WHERE id = %s", (msg_id,))

        ict_conn2.commit()
        logger.info(f"🗑 GROUP CHAT → Deleted {len(group_msgs)} msgs, {group_files_deleted} files")

    finally:
        ict_cur2.close()
        ict_conn2.close()

    logger.info("🔥 Daily cleanup complete.")

# ---------------------------------------------------------
# ✅ Start APScheduler only once (important for Flask debug)
# ---------------------------------------------------------
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    scheduler = BackgroundScheduler(timezone=pytz.timezone("Asia/Kolkata"))
    scheduler.add_job(delete_old_messages_and_files, IntervalTrigger(days=1))
    scheduler.start()
    logger.info("APScheduler started (daily cleanup enabled)")


if __name__ == '__main__':
    logger.info("Starting Flask-SocketIO application")
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)