from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
import jwt
import datetime
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# MySQL configurations
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB

mysql = MySQL(app)

# JWT secret key (must match in Streamlit apps)
JWT_SECRET = config.JWT_SECRET

# Role-based Streamlit app URLs (replace with actual Streamlit app URLs)
ROLE_REDIRECTS = {
    'admin': 'https://usercrm.agvolumes.com',
    'writer': 'https://usercrm.agvolumes.com',
    'proofreader': 'https://usercrm.agvolumes.com',
    'formatter': 'https://usercrm.agvolumes.com',
    'cover_designer': 'https://usercrm.agvolumes.com'
}

TOKEN_BLACKLIST = set()

@app.route('/')
def index():
    if 'email' in session:
        role = session.get('role')
        return redirect(ROLE_REDIRECTS.get(role, '/login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, password, role FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        
        if user and user[1] == password:
            session['email'] = user[0]
            session['role'] = user[2]
            token = jwt.encode({
                'email': user[0],
                'role': user[2].lower(),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, JWT_SECRET, algorithm='HS256')
            redirect_url = f"{ROLE_REDIRECTS.get(user[2], '/login')}?token={token}"
            return redirect(redirect_url)
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/validate_token', methods=['POST'])
def validate_token():
    token = request.json.get('token')
    if token in TOKEN_BLACKLIST:
        return jsonify({'valid': False, 'error': 'Token invalidated'}), 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({'valid': True, 'email': decoded['email'], 'role': decoded['role'].lower()})
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    # Optional: Blacklist the token if provided
    token = request.json.get('token')
    if token:
        TOKEN_BLACKLIST.add(token)
    session.pop('email', None)
    session.pop('role', None)
    return jsonify({'success': True, 'redirect': url_for('login', _external=True)}), 200

if __name__ == '__main__':
    app.run(debug=True)