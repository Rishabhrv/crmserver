from dotenv import load_dotenv
import os
import json

load_dotenv()

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