from dotenv import load_dotenv
import os
import json

load_dotenv()

def get_list_env(key: str):
    value = os.getenv(key)
    if not value:
        raise ValueError(f"Missing environment variable: {key}")
    return [item.strip() for item in value.split(",")]

# MySQL Configuration for booktracker database
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DB = os.getenv("MYSQL_DB")

# MySQL Configuration for ict database
MYSQL_ICT_HOST = os.getenv("MYSQL_ICT_HOST")
MYSQL_ICT_USER = os.getenv("MYSQL_ICT_USER")
MYSQL_ICT_PASSWORD = os.getenv("MYSQL_ICT_PASSWORD")
MYSQL_ICT_DB = os.getenv("MYSQL_ICT_DB")


# Flask Secret Key
SECRET_KEY = os.getenv("SECRET_KEY")  

# JWT Secret Key
JWT_SECRET = os.getenv("JWT_SECRET")  

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
APP_REDIRECTS = json.loads(os.getenv("APP_REDIRECTS", "{}"))

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
GROUP_UPLOAD_FOLDER = os.getenv("GROUP_UPLOAD_FOLDER")

SOCKET_CORS_ORIGINS = get_list_env("SOCKET_CORS_ORIGINS")
FLASK_CORS_ORIGINS = get_list_env("FLASK_CORS_ORIGINS")

APP_REDIRECTS = {
    "main": os.getenv("APP_REDIRECT_MAIN"),
    "operations": os.getenv("APP_REDIRECT_OPERATIONS"),
    "admin": os.getenv("APP_REDIRECT_ADMIN"),
    "tasks": os.getenv("APP_REDIRECT_TASKS"),
    "ijisem": os.getenv("APP_REDIRECT_IJISEM"),
    "sales": os.getenv("APP_REDIRECT_SALES")
}