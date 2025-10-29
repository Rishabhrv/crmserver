@st.dialog("Authentication Failed", dismissible=False)
def error_dialog(error_message):
    st.error(error_message)
    if st.link_button("Login:material/open_in_new:", url=FLASK_LOGIN_URL, type="tertiary"):
        clear_auth_session()
        st.stop()

def validate_token():
    # Check if token and user details are cached and not near expiry
    current_time = time.time()
    if ('token' in st.session_state and 
        'user_details' in st.session_state and 
        'exp' in st.session_state and 
        st.session_state.exp > current_time + 300):  # 5-minute buffer
        logger.info("Using cached token validation")
        return

    # Token fetching
    if 'token' not in st.session_state:
        token = st.query_params.get("token")
        if not token:
            logger.error("No token provided")
            error_dialog("Access denied: Please log in first.")
        st.session_state.token = token if isinstance(token, str) else token[0]

    token = st.session_state.token

    try:
        # Local JWT validation
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if 'user_id' not in decoded or 'exp' not in decoded:
            raise jwt.InvalidTokenError("Missing user_id or exp")

        # Server-side validation and user details
        response = requests.post(FLASK_AUTH_URL, json={"token": token}, timeout=3)
        if response.status_code != 200 or not response.json().get('valid'):
            error = response.json().get('error', 'Invalid token')
            logger.error(f"Auth failed: {error}")
            raise jwt.InvalidTokenError(error)

        user_details = response.json().get('user_details', {})
        role = user_details.get('role', '').lower()
        app = user_details.get('app', '').lower()
        access = user_details.get('access', [])
        email = user_details.get('email', '')
        start_date = user_details.get('start_date', '')
        username = user_details.get('username', '')
        level = user_details.get('level', None)
        report_to = user_details.get('report_to', None)
        associate_id = user_details.get('associate_id', None)
        designation = user_details.get('designation', None)

        # Convert access to list if it's a string or None
        if isinstance(access, str):
            access = [access] if access else []
        elif access is None:
            access = []

        # Role and access validation
        if role not in VALID_ROLES:
            logger.error(f"Invalid role: {role}")
            raise jwt.InvalidTokenError(f"Invalid role '{role}'")
        if role != 'admin':
            if app not in VALID_APPS.values():
                logger.error(f"Invalid app: {app}")
                raise jwt.InvalidTokenError(f"Invalid app '{app}'")
            if app == 'main':
                valid_access = set(ACCESS_TO_BUTTON.keys())
                if not all(acc in valid_access for acc in access):
                    logger.error(f"Invalid access for main app: {access}")
                    raise jwt.InvalidTokenError(f"Invalid access for main app: {access}")
            elif app == 'operations':
                valid_access = {"writer", "proofreader", "formatter", "cover_designer"}
                if not (len(access) == 1 and access[0] in valid_access):
                    logger.error(f"Invalid access for operations app: {access}")
                    raise jwt.InvalidTokenError(f"Invalid access for operations app: {access}")
            elif app == 'ijisem':
                valid_access = {"Full Access"}
                if not (len(access) == 1 and access[0] in valid_access):
                    logger.error(f"Invalid access for ijisem app: {access}")
                    raise jwt.InvalidTokenError(f"Invalid access for ijisem app: {access}")

        # Cache user details
        st.session_state.user_id = decoded['user_id']
        st.session_state.email = email
        st.session_state.role = role
        st.session_state.app = app
        st.session_state.access = access
        st.session_state.start_date = start_date
        st.session_state.username = username
        st.session_state.exp = decoded['exp']
        st.session_state.level = level
        st.session_state.report_to = report_to
        st.session_state.associate_id = associate_id
        st.session_state.designation = designation
        logger.info(f"Token validated successfully for user: {email}")

    except jwt.ExpiredSignatureError as e:
        logger.error(f"Token expired: {str(e)}", exc_info=True)
        error_dialog("Access denied: Token expired. Please log in again.")
    except jwt.InvalidSignatureError as e:
        logger.error(f"Invalid token signature: {str(e)}", exc_info=True)
        error_dialog("Access denied: Invalid token signature. Please log in again.")
    except jwt.DecodeError as e:
        logger.error(f"Token decoding failed: {str(e)}", exc_info=True)
        error_dialog("Access denied: Token decoding failed. Please log in again.")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}", exc_info=True)
        error_dialog(f"Access denied: {str(e)}. Please log in again.")
    except requests.RequestException as e:
        logger.error(f"Request to Flask failed: {str(e)}", exc_info=True)
        error_dialog(f"Access denied: Unable to contact authentication server.")
    except Exception as e:
        logger.error(f"Unexpected error in validate_token: {str(e)}", exc_info=True)
        error_dialog(f"Unexpected error in validate_token: {str(e)}")