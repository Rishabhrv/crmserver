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
from mysql.connector import pooling
import os
from werkzeug.utils import secure_filename
from flask import Flask, send_from_directory
from urllib.parse import unquote
from flask import send_file


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
socketio = SocketIO(app, cors_allowed_origins=["https://chat.mis.agkit.in", "https://mis.agkit.in"])
# CORS(app, resources={r"/*": {"origins": ["http://localhost:8501", "http://localhost:3000"]}})
#CORS(app, resources={r"/*": {"origins": ["https://chat.mis.agkit.in", "https://mis.agkit.in"]}})

# Configure CORS with explicit headers
# CORS(app, resources={
#     r"/upload_file": {
#         "origins": ["https://chat.mis.agkit.in", "https://mis.agkit.in"],
#         "methods": ["GET", "POST", "OPTIONS"],
#         "allow_headers": ["Content-Type", "Authorization"]
#     }
# })

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

UPLOAD_FOLDER = config.UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
IS_PRODUCTION = os.getenv('FLASK_ENV') == 'production'

GROUP_UPLOAD_FOLDER = config.GROUP_UPLOAD_FOLDER
os.makedirs(GROUP_UPLOAD_FOLDER, exist_ok=True)

# File restrictions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "docx", "xlsx", "csv", "zip"}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 10 MB in bytes
MAX_FILES_PER_REQUEST = 5

#app.static_folder = UPLOAD_FOLDER

# App-based redirect URLs
APP_REDIRECTS={"main": "https://mis.agkit.in", 
               "operations": "https://mis.agkit.in/team_dashboard", 
               "admin": "https://mis.agkit.in", 
               "tasks": "https://mis.agkit.in/tasks",
               "ijisem": "https://mis.agkit.in/ijisem",
                "sales": "https://mis.agkit.in/sales"}

# APP_REDIRECTS={"main": "http://localhost:8501", 
#                 "operations": "http://localhost:8501/team_dashboard", 
#                 "admin": "http://localhost:8501", 
#                 "tasks": "http://localhost:8501/tasks",
#                 "ijisem": "http://localhost:8501/ijisem",
#                 "sales": "http://localhost:8501/sales",
#                 "clone": "http://localhost:3000/clone",
#                 "ict": "http://localhost:3000/chat"
#                 }



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
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_id = payload["user_id"]
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


#--------------------Create New Conversations-----------------

@app.route("/createConversation", methods=["POST"])
@token_required
def create_conversation():
    try:
        data = request.get_json() or {}
        user1_id = data.get("user1_id")
        user2_id = data.get("user2_id")

        if not user1_id or not user2_id:
            return jsonify({"success": False, "error": "Both user IDs required"}), 400

        conn, cur = get_ict_cursor()  # ✅ FIXED

        # ✅ Check if conversation already exists
        cur.execute("""
            SELECT id FROM conversations
            WHERE (user1_id = %s AND user2_id = %s)
               OR (user1_id = %s AND user2_id = %s)
        """, (user1_id, user2_id, user2_id, user1_id))
        convo = cur.fetchone()

        if convo:
            convo_id = convo["id"]
            cur.execute("SELECT * FROM conversations WHERE id=%s", (convo_id,))
            existing_convo = cur.fetchone()
            conn.close()
            return jsonify({
                "success": True,
                "message": "Conversation already exists",
                "conversation": existing_convo
            }), 200

        # ✅ Create new conversation
        cur.execute("""
            INSERT INTO conversations (user1_id, user2_id, created_at)
            VALUES (%s, %s, NOW())
        """, (user1_id, user2_id))
        conn.commit()

        convo_id = cur.lastrowid
        cur.execute("SELECT * FROM conversations WHERE id=%s", (convo_id,))
        new_convo = cur.fetchone()

        conn.close()
        return jsonify({
            "success": True,
            "message": "New conversation created",
            "conversation": new_convo
        }), 201

    except Exception as e:
        print("Error creating conversation:", str(e))
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
    message_type = data.get("message_type", "text")  # ✅ default type

    if not token or not conv_id or not message_text:
        emit("error", {"error": "missing fields"})
        return

    # 🔐 Decode JWT using consistent key and payload structure
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        sender_id = payload["user_id"]
    except jwt.ExpiredSignatureError:
        emit("error", {"error": "token expired"})
        return
    except jwt.InvalidTokenError:
        emit("error", {"error": "invalid token"})
        return

    # 🕒 Use IST time (assuming you have now_ist() helper)
    current_time = now_ist()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        # ✅ Connect to ICT DB (where messages table exists)
        conn, cur = get_ict_cursor()
        cur.execute(
            """
            INSERT INTO messages (conversation_id, sender_id, message, message_type, timestamp)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (conv_id, sender_id, message_text, message_type, formatted_time)
        )
        conn.commit()
        message_id = cur.lastrowid
    except Exception as e:
        emit("error", {"error": f"DB error: {str(e)}"})
        return
    finally:
        cur.close()
        conn.close()

    # 🧩 Get sender username from book DB
    try:
        book_conn, book_cur = get_book_cursor()
        book_cur.execute("SELECT username FROM userss WHERE id = %s", (sender_id,))
        sender_name = (book_cur.fetchone() or {}).get("username", "Unknown")
    except Exception as e:
        sender_name = "Unknown"
    finally:
        book_cur.close()
        book_conn.close()

    # 📦 Build message payload
    payload_msg = {
        "id": message_id,
        "conversation_id": conv_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "message": message_text,
        "message_type": message_type,
        "timestamp": formatted_time
    }

    # 📡 Broadcast to all users in this conversation room
    emit("new_message", payload_msg, room=f"conv_{conv_id}")

    # 📨 Acknowledge the sender (optional but good UX)
    emit("message_sent", payload_msg, room=request.sid)




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

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        sender_id = payload["user_id"]
    except Exception as e:
        emit("error", {"error": f"Invalid token: {str(e)}"})
        return

    # ✅ Get sender_name from userss
    conn, cur = get_book_cursor()
    cur.execute("SELECT username FROM userss WHERE id = %s", (sender_id,))
    user_row = cur.fetchone()
    sender_name = user_row["username"] if user_row else "Unknown User"
    cur.close()
    conn.close()

    # ✅ Save message
    conn, cur = get_ict_cursor()
    cur.execute(
        "INSERT INTO group_messages (group_id, sender_id, message, message_type, timestamp) VALUES (%s,%s,%s,%s,NOW())",
        (group_id, sender_id, message, message_type)
    )
    conn.commit()
    message_id = cur.lastrowid
    cur.close()
    conn.close()

    # ✅ Include sender_name when emitting
    emit("new_group_message", {
        "id": message_id,
        "group_id": group_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "message": message,
        "message_type": message_type,
        "timestamp": datetime.now().isoformat()
    }, room=f"group_{group_id}")


# -------------------- File Upload Handling --------------------

@app.route('/uploads/<path:filename>', methods=['GET', 'OPTIONS'])
def serve_uploaded_file(filename):
    if request.method == 'OPTIONS':
        return '', 200
    try:
        # Decode URL-encoded characters (e.g., %20 -> space)
        from urllib.parse import unquote
        decoded_filename = unquote(filename)
        
        # Construct the full file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], decoded_filename)
        
        # Security check: ensure the path is within UPLOAD_FOLDER
        if not os.path.abspath(file_path).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            logger.error(f'Path traversal attempt: {filename}')
            return jsonify({'error': 'Invalid file path'}), 403
        
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f'File not found: {decoded_filename}')
            return jsonify({'error': 'File not found'}), 404
        
        # Serve the file without forcing download (removes as_attachment=True)
        # This allows browsers to display PDFs/images inline
        return send_file(file_path)
        
    except Exception as e:
        logger.error(f'Error serving file {filename}: {e}')
        return jsonify({'error': 'Failed to serve file'}), 500

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload_file', methods=['POST'])  # Only POST now
def upload_file():
    
    if 'file' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    files = request.files.getlist('file')
    if len(files) > MAX_FILES_PER_REQUEST:
        return jsonify({'error': f'Too many files. Max {MAX_FILES_PER_REQUEST} allowed.'}), 400

    username = request.form.get('username', 'guest').strip()
    if not username:
        return jsonify({'error': 'Username required'}), 400
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(username))
    os.makedirs(user_folder, exist_ok=True)

    uploaded_urls = []
    for file in files:
        if file.filename == '':
            continue
        if not allowed_file(file.filename):
            return jsonify({'error': f'File type not allowed: {file.filename}'}), 400
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': f'{file.filename} exceeds 25MB limit.'}), 400
        filename = secure_filename(file.filename)
        filepath = os.path.join(user_folder, filename)
        try:
            file.save(filepath)
            file_url = f'{request.host_url}uploads/{username}/{filename}'
            uploaded_urls.append(file_url)
        except Exception as e:
            logger.error(f'File save error for {filename}: {e}')
            return jsonify({'error': f'Failed to save {filename}'}), 500

    if not uploaded_urls:
        return jsonify({'error': 'No valid files uploaded'}), 400
    return jsonify({'urls': uploaded_urls}), 200


#---------------------------- Group Section ----------------------------


@app.route("/create_group", methods=["POST"])
@token_required
def create_group():
    created_by = request.user_id

    # ✅ Case 1: JSON (no image)
    if request.is_json:
        data = request.get_json()
        group_name = data.get("group_name")
        members = data.get("members", [])
        group_image = None

    # ✅ Case 2: FormData (with image)
    else:
        group_name = request.form.get("group_name")
        members = request.form.get("members", "[]")
        import json
        members = json.loads(members)
        image = request.files.get("group_image")
        group_image = None

        if not group_name:
            return jsonify({"error": "Group name required"}), 400

        # ✅ Create a folder for this group (use safe folder name)
        safe_group_name = secure_filename(group_name)
        group_folder = os.path.join(UPLOAD_FOLDER, safe_group_name)
        os.makedirs(group_folder, exist_ok=True)

        # ✅ If image is uploaded, save it inside this group's folder
        if image:
            filename = secure_filename(image.filename)
            filepath = os.path.join(group_folder, filename)
            image.save(filepath)
            group_image = f"/{group_folder}/{filename}"  # relative path for frontend

    if not group_name:
        return jsonify({"error": "Group name required"}), 400

    conn, cur = get_ict_cursor()
    try:
        # ✅ Insert group (with optional image)
        cur.execute(
            "INSERT INTO groups (group_name, created_by, group_image) VALUES (%s, %s, %s)",
            (group_name, created_by, group_image),
        )
        group_id = cur.lastrowid

        # Add creator as admin
        cur.execute(
            "INSERT INTO group_members (group_id, user_id, role) VALUES (%s, %s, 'admin')",
            (group_id, created_by),
        )

        # Add members
        for uid in members:
            cur.execute(
                "INSERT INTO group_members (group_id, user_id, role) VALUES (%s, %s, 'member')",
                (group_id, uid),
            )

        conn.commit()
        return jsonify({
            "success": True,
            "group_id": group_id,
            "group_image": group_image,
            "folder": f"/{group_folder}"
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/groups", methods=["GET"])
@token_required
def get_groups():
    user_id = request.user_id  # from token
    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            SELECT g.id, g.group_name, g.group_image, g.created_by, g.created_at
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = %s
            ORDER BY g.created_at DESC
        """, (user_id,))
        groups = cur.fetchall()

        result = []
        for g in groups:
            result.append({
                "id": g["id"],
                "group_name": g["group_name"],
                "group_image": g["group_image"],
                "created_by": g["created_by"],
                "created_at": g["created_at"].strftime("%Y-%m-%d %H:%M:%S") if g["created_at"] else None,
            })

        return jsonify(result)
    except Exception as e:
        print("🔥 /groups error:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/group_messages/<int:group_id>", methods=["GET"])
@token_required
def get_group_messages(group_id):
    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            SELECT gm.id, gm.sender_id, u.username AS sender_name, gm.message, gm.message_type, gm.timestamp
            FROM group_messages gm
            JOIN booktracker.userss u ON gm.sender_id = u.id
            WHERE gm.group_id = %s
            ORDER BY gm.timestamp ASC
        """, (group_id,))
        messages = cur.fetchall()
        return jsonify(messages)
    finally:
        cur.close()
        conn.close()


@app.route("/send_group_message", methods=["POST"])
@token_required
def send_group_message():
    data = request.get_json()
    group_id = data.get("group_id")
    message = data.get("message")
    message_type = data.get("message_type", "text")
    sender_id = request.user_id

    if not group_id or not message:
        return jsonify({"error": "Missing fields"}), 400

    conn, cur = get_ict_cursor()
    try:
        cur.execute("""
            INSERT INTO group_messages (group_id, sender_id, message, message_type)
            VALUES (%s, %s, %s, %s)
        """, (group_id, sender_id, message, message_type))
        conn.commit()
        msg_id = cur.lastrowid
        return jsonify({"success": True, "message_id": msg_id})
    finally:
        cur.close()
        conn.close()



if __name__ == '__main__':
    logger.info("Starting Flask-SocketIO application")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)