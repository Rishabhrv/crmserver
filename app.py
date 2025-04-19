from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import jwt
import datetime
import config
import pytz
import logging

# Configure logging
logging.basicConfig(
    filename='flask.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

# Enable CORS for Streamlit app domains
CORS(app, resources={
    r"/validate_token": {"origins": ["https://newcrm.agvolumes.com", "https://usercrm.agvolumes.com", "http://127.0.0.1:8504"]},
    r"/user_details": {"origins": ["https://newcrm.agvolumes.com", "https://usercrm.agvolumes.com", "http://127.0.0.1:8504"]},
    r"/logout": {"origins": ["https://newcrm.agvolumes.com", "https://usercrm.agvolumes.com", "http://127.0.0.1:8504"]}
})

# App-based redirect URLs
APP_REDIRECTS = {
    'main': 'https://newcrm.agvolumes.com',
    'operations': 'https://usercrm.agvolumes.com',
    'admin': 'https://newcrm.agvolumes.com'
}

TOKEN_BLACKLIST = set()

@app.route('/')
def index():
    logger.info("Accessing root endpoint")
    if 'email' in session:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.info(f"Login attempt: {request.method}")
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        logger.debug(f"Login attempt for email: {email}")
        
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            
            if user and user[2] == password:
                session['email'] = user[1]
                
                # Fetch user details to determine role
                cur = mysql.connection.cursor()
                cur.execute("SELECT role, app FROM users WHERE id = %s", (user[0],))
                user_details = cur.fetchone()
                cur.close()
                
                role = user_details[0].lower()
                app = user_details[1].lower() if user_details[1] else ''
                logger.debug(f"User role: {role}, app: {app}")
                
                # Time restriction for 'user' role
                if role == 'user':
                    ist = pytz.timezone('Asia/Kolkata')
                    current_time = datetime.datetime.now(ist)
                    current_hour = current_time.hour
                    logger.debug(f"Current IST hour: {current_hour}")
                    
                    if not (9 <= current_hour < 18):
                        flash('Users can only log in between 9 AM and 6 PM IST', 'error')
                        logger.warning(f"Login denied for {email}: Outside allowed hours")
                        return redirect(url_for('login'))
                
                # Create JWT token
                token_payload = {
                    'user_id': user[0],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
                }
                token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
                logger.info(f"Generated token for user_id: {user[0]}")
                
                # Determine redirect URL
                if role == 'admin':
                    redirect_url = f"{APP_REDIRECTS['admin']}?token={token}"
                else:
                    if app and app in APP_REDIRECTS:
                        redirect_url = f"{APP_REDIRECTS[app]}?token={token}"
                    else:
                        flash('Invalid app configuration', 'error')
                        logger.error(f"Invalid app configuration for user: {email}")
                        return redirect(url_for('login'))
                
                logger.info(f"Redirecting to: {redirect_url}")
                return redirect(redirect_url)
            else:
                flash('Invalid email or password', 'error')
                logger.warning(f"Failed login attempt for email: {email}")
                return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in login: {str(e)}", exc_info=True)
            flash('An error occurred during login', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/validate_token', methods=['POST'])
def validate_token():
    logger.info("Received validate_token request")
    try:
        if not request.is_json:
            logger.warning("Request is not JSON")
            return jsonify({'valid': False, 'error': 'Request must be JSON'}), 400
        token = request.json.get('token')
        if not token:
            logger.warning("Token missing in request")
            return jsonify({'valid': False, 'error': 'Token missing'}), 400
        if token in TOKEN_BLACKLIST:
            logger.warning("Token is blacklisted")
            return jsonify({'valid': False, 'error': 'Token invalidated'}), 401
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        logger.info(f"Token validated for user_id: {decoded['user_id']}")
        return jsonify({
            'valid': True,
            'user_id': decoded['user_id']
        })
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Error in validate_token: {str(e)}", exc_info=True)
        return jsonify({'valid': False, 'error': 'Server error'}), 500

@app.route('/user_details', methods=['POST'])
def user_details():
    logger.info("Received user_details request")
    try:
        if not request.is_json:
            logger.warning("Request is not JSON")
            return jsonify({'valid': False, 'error': 'Request must be JSON'}), 400
        token = request.json.get('token')
        if not token:
            logger.warning("Token missing in request")
            return jsonify({'valid': False, 'error': 'Token missing'}), 400
        if token in TOKEN_BLACKLIST:
            logger.warning("Token is blacklisted")
            return jsonify({'valid': False, 'error': 'Token invalidated'}), 401
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded['user_id']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, role, app, access, start_date, FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        
        if not user:
            logger.warning(f"User not found for user_id: {user_id}")
            return jsonify({'valid': False, 'error': 'User not found'}), 404
        
        access_list = []
        if user[2] == 'main':
            access_list = [acc.strip() for acc in user[3].split(',') if acc.strip()] if user[3] else []
        elif user[2] == 'operations':
            access_list = [user[3]] if user[3] else []
        
        start_date = user[4].isoformat() if user[4] else None
        logger.info(f"User details fetched for user_id: {user_id}")
        return jsonify({
            'valid': True,
            'email': user[0],
            'role': user[1].lower(),
            'app': user[2].lower() if user[2] else '',
            'access': access_list,
            'start_date': start_date
        })
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Error in user_details: {str(e)}", exc_info=True)
        return jsonify({'valid': False, 'error': 'Server error'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    logger.info("Received logout request")
    try:
        if not request.is_json:
            logger.warning("Request is not JSON")
            return jsonify({'success': False, 'error': 'Request must be JSON'}), 400
        token = request.json.get('token')
        if token:
            TOKEN_BLACKLIST.add(token)
            logger.info("Token blacklisted")
        session.pop('email', None)
        logger.info("User logged out")
        return jsonify({'success': True, 'redirect': url_for('login', _external=True)}), 200
    except Exception as e:
        logger.error(f"Error in logout: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': 'Server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)