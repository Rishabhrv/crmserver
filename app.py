from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
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
from flask_socketio import SocketIO, join_room, emit
from datetime import datetime, timedelta
from functools import wraps
import mysql.connector  # <-- NEW: Use mysql-connector-python
from mysql.connector import pooling


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
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app, resources={r"/*": {"origins": ["http://localhost:8501", "https://mis.agkit.in"]}})

try:
    # Pool for 'ict' database (chat)
    ict_pool = pooling.MySQLConnectionPool(
        pool_name="ict_pool",
        pool_size=5,
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
        pool_size=3,
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


# # App-based redirect URLs
# APP_REDIRECTS={"main": "https://mis.agkit.in", 
#                "operations": "https://mis.agkit.in/team_dashboard", 
#                "admin": "https://mis.agkit.in", 
#                "tasks": "https://mis.agkit.in/tasks",
#                "ijisem": "https://mis.agkit.in/ijisem",
#                 "sales": "https://mis.agkit.in/sales"}

APP_REDIRECTS={"main": "http://localhost:8501", 
                "operations": "http://localhost:8501/team_dashboard", 
                "admin": "http://localhost:8501", 
                "tasks": "http://localhost:8501/tasks",
                "ijisem": "http://localhost:8501/ijisem",
                "sales":"http://localhost:8501/sales"}


TOKEN_BLACKLIST = set()
PASSWORD_RESET_TOKENS = {}

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
            payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            request.user_id = payload["id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper

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

        conn, cur = get_book_cursor()
        user = None
        try:
            cur.execute(
                "SELECT id, email, password, username, role FROM userss WHERE email = %s",
                (email,)
            )
            user = cur.fetchone()  # ← This is a DICT
        finally:
            cur.close()
            conn.close()

        # ← NOW use dict keys, NOT numbers!
        if not user:
            logger.warning(f"User not found: {email}")
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        if user['password'] != password:  # ← Use 'password', not [2]
            logger.warning(f"Invalid password for: {email}")
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        # ----- SUCCESS -----
        session['email'] = user['email']
        session['login_time'] = datetime.now(timezone.utc).isoformat()
        logger.info(f"User {user['username']} logged in, role: {user['role']}")

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
        if role == 'user':
            current_hour = datetime.now(pytz.timezone('Asia/Kolkata')).hour
            if not (9 <= current_hour < 18):
                flash('Users can only log in between 9 AM and 6 PM IST', 'error')
                return redirect(url_for('login'))

        # ----- JWT -----
        token = jwt.encode({
            'user_id': user['id'],
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
                'user_id': user[0],
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
            msg = MIMEText(email_body)
            msg['Subject'] = 'AG Publishing House - Password Reset'
            msg['From'] = EMAIL_CONFIG['SENDER_EMAIL']
            msg['To'] = email

            with smtplib.SMTP(EMAIL_CONFIG['SMTP_SERVER'], EMAIL_CONFIG['SMTP_PORT']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['SENDER_EMAIL'], EMAIL_CONFIG['SENDER_PASSWORD'])
                server.send_message(msg)

            logger.info(f"Password reset email sent to admin: {user[3]}")
            flash('Password reset link sent to your email', 'success')
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

            cur.execute("UPDATE userss SET password = %s WHERE id = %s", (new_password, user_id))
            conn.commit()
        finally:
            cur.close()
            conn.close()

        del PASSWORD_RESET_TOKENS[token]
        logger.info(f"Password reset successful for admin: {user[1]}")
        flash('Password successfully reset. Please login.', 'success')
        return redirect(url_for('login'))

    # GET – show form
    if not token or token not in PASSWORD_RESET_TOKENS or \
       PASSWORD_RESET_TOKENS[token]['expires'] < datetime.now(timezone.utc):
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)


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

@app.route("/conversations", methods=["GET"])
@token_required
def get_conversations():
    uid = request.user_id
    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            SELECT c.id,
                   CASE WHEN c.user1_id = %s THEN c.user2_id ELSE c.user1_id END AS other_user_id,
                   m.message AS last_message,
                   m.timestamp AS last_time
            FROM conversations c
            LEFT JOIN messages m ON m.id = (
                SELECT id FROM messages WHERE conversation_id = c.id
                ORDER BY timestamp DESC LIMIT 1
            )
            WHERE c.user1_id = %s OR c.user2_id = %s
            ORDER BY m.timestamp DESC
        """, (uid, uid, uid))
        rows = cur.fetchall()

        convos = []
        for r in rows:
            other_id = r["other_user_id"]
            cur2 = conn.cursor(dictionary=True)
            cur2.execute("SELECT username FROM users WHERE id=%s", (other_id,))
            other = cur2.fetchone() or {}
            cur2.execute(
                "SELECT COUNT(*) AS unread FROM messages WHERE conversation_id=%s AND sender_id!=%s AND seen=0",
                (r["id"], uid)
            )
            unread = cur2.fetchone()["unread"]
            cur2.close()

            convos.append({
                "id": r["id"],
                "other_user_id": other_id,
                "other_username": other.get("username", "Unknown"),
                "last_message": r["last_message"],
                "last_time": r["last_time"],
                "unread": unread
            })
        return jsonify(convos)
    finally:
        cur.close()
        conn.close() 

@app.route("/messages/<int:conversation_id>", methods=["GET"])
@token_required
def get_messages(conversation_id):
    uid = request.user_id
    conn, cur = get_ict_cursor()
    try:
        cur.execute(
            "SELECT * FROM messages WHERE conversation_id=%s ORDER BY timestamp ASC",
            (conversation_id,)
        )
        msgs = cur.fetchall()

        cur.execute(
            "UPDATE messages SET seen=1 WHERE conversation_id=%s AND sender_id!=%s",
            (conversation_id, uid)
        )
        return jsonify(msgs or [])
    finally:
        cur.close()
        conn.close()

@app.route('/users')
def search_users():
    term = request.args.get('search', '')
    conn, cur = get_ict_cursor()
    try:
        cur.execute(
            "SELECT id, username FROM users WHERE username LIKE %s LIMIT 10",
            (f"%{term}%",)
        )
        users = cur.fetchall()
        return jsonify(users)
    finally:
        cur.close()
        conn.close()

# -------------------- SocketIO --------------------
@socketio.on("join")
def socket_join(data):
    token = data.get("token")
    conv_id = data.get("conversation_id")
    if not token or not conv_id:
        emit("error", {"error": "missing token/conversation_id"})
        return

    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        user_id = payload["id"]
    except:
        emit("error", {"error": "invalid token"})
        return

    join_room(f"conv_{conv_id}")
    emit("system", {"msg": f"user {user_id} joined"}, room=f"conv_{conv_id}")

@socketio.on("send_message")
def socket_send_message(data):
    token = data.get("token")
    conv_id = data.get("conversation_id")
    text = data.get("message")
    if not all([token, conv_id, text]):
        emit("error", {"error": "missing fields"})
        return

    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        sender_id = payload["id"]
    except:
        emit("error", {"error": "invalid token"})
        return

    ts = now_ist().strftime("%Y-%m-%d %H:%M:%S")
    conn, cur = get_ict_cursor()
    try:
        cur.execute(
            "INSERT INTO messages (conversation_id, sender_id, message, timestamp) VALUES (%s, %s, %s, %s)",
            (conv_id, sender_id, text, ts)
        )
        msg_id = cur.lastrowid
        msg = {
            "id": msg_id,
            "conversation_id": conv_id,
            "sender_id": sender_id,
            "message": text,
            "timestamp": ts
        }
        emit("new_message", msg, room=f"conv_{conv_id}")
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    logger.info("Starting Flask-SocketIO application")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)