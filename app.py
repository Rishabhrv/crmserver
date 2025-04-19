from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import jwt
import datetime
import config
import pytz

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
CORS(app, resources={r"/validate_token": {"origins": ["https://newcrm.agvolumes.com", "https://usercrm.agvolumes.com"]},
                     r"/user_details": {"origins": ["https://newcrm.agvolumes.com", "https://usercrm.agvolumes.com"]},
                     r"/logout": {"origins": ["https://newcrm.agvolumes.com", "https://usercrm.agvolumes.com"]}})

# # App-based redirect URLs
# APP_REDIRECTS = {
#     'main': 'http://localhost:8502',
#     'operations': 'http://localhost:8501',
#     'admin': 'http://localhost:8502'
# }

# App-based redirect URLs
APP_REDIRECTS = {
    'main': 'https://newcrm.agvolumes.com',
    'operations': 'https://usercrm.agvolumes.com',
    'admin': 'https://newcrm.agvolumes.com'
}

TOKEN_BLACKLIST = set()

@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
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
            
            # Time restriction for 'user' role
            if role == 'user':
                # Get current time in IST
                ist = pytz.timezone('Asia/Kolkata')
                current_time = datetime.datetime.now(ist)
                current_hour = current_time.hour
                
                # Check if current time is between 9 AM and 6 PM (18:00)
                if not (9 <= current_hour < 18):
                    flash('Users can only log in between 9 AM and 6 PM IST', 'error')
                    return redirect(url_for('login'))
            
            # Create JWT token with only user_id
            token_payload = {
                'user_id': user[0],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
            }
            
            token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
            
            # Determine redirect URL
            if role == 'admin':
                redirect_url = f"{APP_REDIRECTS['admin']}?token={token}"
            else:
                if app and app in APP_REDIRECTS:
                    redirect_url = f"{APP_REDIRECTS[app]}?token={token}"
                else:
                    flash('Invalid app configuration', 'error')
                    return redirect(url_for('login'))
            
            return redirect(redirect_url)
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/validate_token', methods=['POST'])
def validate_token():
    if not request.is_json:
        return jsonify({'valid': False, 'error': 'Request must be JSON'}), 400
    token = request.json.get('token')
    if not token:
        return jsonify({'valid': False, 'error': 'Token missing'}), 400
    if token in TOKEN_BLACKLIST:
        return jsonify({'valid': False, 'error': 'Token invalidated'}), 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({
            'valid': True,
            'user_id': decoded['user_id']
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

@app.route('/user_details', methods=['POST'])
def user_details():
    if not request.is_json:
        return jsonify({'valid': False, 'error': 'Request must be JSON'}), 400
    token = request.json.get('token')
    if not token:
        return jsonify({'valid': False, 'error': 'Token missing'}), 400
    if token in TOKEN_BLACKLIST:
        return jsonify({'valid': False, 'error': 'Token invalidated'}), 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded['user_id']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, role, app, access, start_date, end_date FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        
        if not user:
            return jsonify({'valid': False, 'error': 'User not found'}), 404
        
        # Process access based on app
        access_list = []
        if user[2] == 'main':
            access_list = [acc.strip() for acc in user[3].split(',') if acc.strip()] if user[3] else []
        elif user[2] == 'operations':
            access_list = [user[3]] if user[3] else []
        
        # Handle nullable start_date and end_date
        start_date = user[4].isoformat() if user[4] else None
        
        return jsonify({
            'valid': True,
            'email': user[0],
            'role': user[1].lower(),
            'app': user[2].lower() if user[2] else '',
            'access': access_list,
            'start_date': start_date
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Request must be JSON'}), 400
    token = request.json.get('token')
    if token:
        TOKEN_BLACKLIST.add(token)
    session.pop('email', None)
    return jsonify({'success': True, 'redirect': url_for('login', _external=True)}), 200

if __name__ == '__main__':
    app.run(debug=True)