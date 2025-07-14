from fastapi import FastAPI, UploadFile, File, Request, Body, HTTPException, Depends, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
import tempfile
import json
import os
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
import secrets # For generating secure tokens
import hashlib # For hashing tokens before storing
from pathlib import Path
# For email sending
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend"))
# Assuming 'extract.py' is in the same directory
from extract import process_base64_image, PROMPT # Import PROMPT directly from extract

app = FastAPI()
# Adjust this path to your actual frontend directory
# Assuming 'frontend' folder is at the same level as main.py

# --- Authentication Configuration ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# IMPORTANT: CHANGE THESE IN PRODUCTION!
# It's highly recommended to use environment variables for SECRET_KEY in production
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key") # Default for development, change this!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # For session tokens
REFRESH_TOKEN_EXPIRE_HOURS = 24 * 7 # For refresh tokens (1 week)
EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES = 60 # For email verification

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory store for demonstration purposes.
# In a real application, use a database (SQL, NoSQL, Redis etc.)
users_db = {} # { "username": {"password": "hashed_password", "email": "...", "is_verified": bool, "refresh_token_hash": "..."}}
email_verification_tokens = {} # { "token_hash": {"username": "...", "expires_at": datetime}}
image_counts = {} # { "username" | "unauthenticated_ip": count }

# --- Email Configuration ---
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", EMAIL_USERNAME) # Use username as sender by default
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com") # e.g., smtp.gmail.com for Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT", 587)) # 587 for TLS, 465 for SSL

# Ensure these environment variables are set
if not SECRET_KEY or SECRET_KEY == "your-super-secret-key":
    print("WARNING: SECRET_KEY not set or using default. Please set SECRET_KEY environment variable in production.")
if not EMAIL_USERNAME or not EMAIL_PASSWORD:
    print("WARNING: Email credentials (EMAIL_USERNAME, EMAIL_PASSWORD) not set. Email verification will not work.")
if not os.getenv("GEMINI_API_KEY"):
    print("WARNING: GEMINI_API_KEY environment variable is not set. Gemini API calls may fail.")


# --- Helper Functions for Auth ---
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    refresh_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    # Hash and store refresh token for invalidation purposes
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    return refresh_token, refresh_token_hash

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = {"username": username}
    except JWTError:
        raise credentials_exception
    user = users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_verified_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_verified"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User not verified. Please check your email for a verification link."
        )
    return current_user

def generate_email_verification_token(username: str):
    token = secrets.token_urlsafe(32) # Generate a random, URL-safe token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(minutes=EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
    email_verification_tokens[token_hash] = {"username": username, "expires_at": expires_at}
    return token

def send_verification_email(recipient_email: str, username: str, verification_token: str):
    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        print(f"Skipping email to {recipient_email}: Email credentials not set.")
        return

    subject = "Verify your Email for Gem ANPR"
    # IMPORTANT: Replace example.com with your actual domain where the FastAPI app is hosted
    verification_link = f"http://localhost:8000/verify-email?token={verification_token}" # Adjust this URL for production
    body = f"""
    <html>
        <body>
            <p>Hello {username},</p>
            <p>Thank you for registering with Gem ANPR!</p>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{verification_link}" style="display: inline-block; padding: 10px 20px; background-color: #007BFF; color: white; text-decoration: none; border-radius: 5px;">Verify Email Address</a></p>
            <p>This link will expire in {EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES} minutes.</p>
            <p>If you did not register for this service, please ignore this email.</p>
            <p>Best regards,<br>The Gem ANPR Team</p>
        </body>
    </html>
    """

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls() # Secure the connection
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"Verification email sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send verification email to {recipient_email}: {e}")
        # In a real app, you might want to log this error or queue for retry

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/register")
async def register(request: Request, username: str = Body(...), email: str = Body(...), password: str = Body(...)):
    if username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    if any(user_data["email"] == email for user_data in users_db.values()):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(password)
    users_db[username] = {
        "email": email,
        "password": hashed_password,
        "is_verified": False,
        "refresh_token_hash": None, # Will be set upon login
        "image_count": 0 # Initialize image count for registered users
    }

    # Generate and send verification email
    verification_token = generate_email_verification_token(username)
    send_verification_email(email, username, verification_token)

    return {"message": "Registration successful. Please check your email to verify your account."}

@app.get("/verify-email")
async def verify_email(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_data = email_verification_tokens.get(token_hash)

    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link.")

    if datetime.utcnow() > token_data["expires_at"]:
        del email_verification_tokens[token_hash] # Clean up expired token
        raise HTTPException(status_code=400, detail="Verification link has expired.")

    username = token_data["username"]
    if username in users_db:
        users_db[username]["is_verified"] = True
        del email_verification_tokens[token_hash] # Token consumed
        return HTMLResponse(content="<h1>Email Verified Successfully!</h1><p>You can now log in.</p>", status_code=200)
    else:
        raise HTTPException(status_code=404, detail="User not found.")

@app.post("/token")
async def login(request: Request, username: str = Body(...), password: str = Body(...)):
    user = users_db.get(username)
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    if not user.get("is_verified"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified. Please check your email.")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["email"], "username": username}, expires_delta=access_token_expires)

    refresh_token, refresh_token_hash = create_refresh_token(data={"sub": user["email"], "username": username},
                                                             expires_delta=timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS))
    user["refresh_token_hash"] = refresh_token_hash # Store hashed refresh token

    response = JSONResponse(content={
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
        "username": username,
        "email": user["email"],
        "is_verified": user["is_verified"],
        "image_count": user["image_count"] # Provide current image count
    })
    return response

@app.post("/refresh-token")
async def refresh_token(request: Request, refresh_token: str = Body(...)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        email: str = payload.get("sub") # email is used as sub in payload
        if username is None or email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = users_db.get(username)
    if user is None or user["refresh_token_hash"] != hashlib.sha256(refresh_token.encode()).hexdigest():
        raise credentials_exception # Token not found or hash mismatch

    if datetime.utcnow() > datetime.fromtimestamp(payload.get("exp")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Create new access and refresh tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(data={"sub": email, "username": username}, expires_delta=access_token_expires)

    new_refresh_token, new_refresh_token_hash = create_refresh_token(data={"sub": email, "username": username},
                                                                     expires_delta=timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS))
    user["refresh_token_hash"] = new_refresh_token_hash # Update stored hashed refresh token

    return JSONResponse(content={
        "access_token": new_access_token,
        "token_type": "bearer",
        "refresh_token": new_refresh_token
    })


@app.post("/image-upload")
async def upload_image_api(file: UploadFile = File(...), current_user: dict = Depends(get_current_verified_user)):
    """
    API endpoint to process an uploaded image file (requires authentication).
    Uses the process_base64_image from extract.py
    """
    try:
        username = current_user["username"]
        image_counts[username] = image_counts.get(username, 0) + 1 # Increment count for authenticated users
        users_db[username]["image_count"] = image_counts[username] # Update in user DB

        contents = await file.read()
        # Convert bytes to base64 string
        base64_encoded_image = base64.b64encode(contents).decode('utf-8')
        mime_type = file.content_type if file.content_type else "image/jpeg" # Default if not provided
        # Prepend data URI scheme
        base64_str_with_header = f"data:{mime_type};base64,{base64_encoded_image}"

        result = process_base64_image(base64_str_with_header, PROMPT)

        return {"text": result, "image_count": users_db[username]["image_count"]}

    except HTTPException as he:
        raise he # Re-raise FastAPI HTTPExceptions
    except Exception as e:
        print(f"Error in image-upload: {e}")
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

@app.post("/base64-process")
async def process_base64_image_api(data: dict = Body(...), current_user: dict = Depends(get_current_verified_user)):
    """
    API endpoint to process a Base64 encoded image string (requires authentication).
    Uses the process_base64_image from extract.py
    """
    try:
        username = current_user["username"]
        image_counts[username] = image_counts.get(username, 0) + 1 # Increment count for authenticated users
        users_db[username]["image_count"] = image_counts[username] # Update in user DB

        base64_str = data.get("base64_str")
        if not base64_str:
            raise HTTPException(status_code=400, detail="base64_str key not found in the JSON body.")

        result = process_base64_image(base64_str, PROMPT)

        return {"text": result, "image_count": users_db[username]["image_count"]}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 string: {str(ve)}")
    except HTTPException as he:
        raise he # Re-raise FastAPI HTTPExceptions
    except Exception as e:
        print(f"Error in base64-process: {e}")
        raise HTTPException(status_code=500, detail=f"Base64 processing failed: {str(e)}")


@app.post("/image-upload-free")
async def upload_image_api_unauthenticated(request: Request, file: UploadFile = File(...)):
    """
    API endpoint to process an uploaded image file.
    Does NOT require authentication.
    """
    try:
        client_ip = request.client.host if request.client else "unknown_ip"
        image_counts[client_ip] = image_counts.get(client_ip, 0) + 1 # Increment count for unauthenticated IP

        contents = await file.read()
        base64_encoded_image = base64.b64encode(contents).decode('utf-8')
        mime_type = file.content_type if file.content_type else "image/jpeg"
        base64_str_with_header = f"data:{mime_type};base64,{base64_encoded_image}"

        result = process_base64_image(base64_str_with_header, PROMPT)

        return {"text": result, "image_count": image_counts[client_ip]} # Return current count
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error in image-upload-free: {e}")
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

@app.post("/base64-free")
async def base64_image_api_unauthenticated(request: Request, data: dict = Body(...)):
    """
    API endpoint to process a Base64 encoded image string.
    Does NOT require authentication.
    """
    try:
        client_ip = request.client.host if request.client else "unknown_ip"
        image_counts[client_ip] = image_counts.get(client_ip, 0) + 1 # Increment count for unauthenticated IP

        base64_str = data.get("base64_str")
        if not base64_str:
            raise HTTPException(status_code=400, detail="base64_str key not found in the JSON body.")

        result = process_base64_image(base64_str, PROMPT)

        return {"text": result, "image_count": image_counts[client_ip]} # Return current count
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 string: {str(ve)}")
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error in base64-free: {e}")
        raise HTTPException(status_code=500, detail=f"Base64 processing failed: {str(e)}")


@app.get("/get-image-count")
async def get_image_count_api(current_user: dict = Depends(get_current_user)):
    """
    Get the image count for the authenticated user.
    """
    username = current_user["username"]
    return {"image_count": users_db[username]["image_count"]}

@app.get("/get-image-count-unauthenticated")
async def get_image_count_unauthenticated_api(request: Request):
    """
    Get the image count for the current unauthenticated user (based on IP).
    """
    client_ip = request.client.host if request.client else "unknown_ip"
    return {"image_count": image_counts.get(client_ip, 0)}

@app.post("/request-password-reset")
async def request_password_reset(email: str = Body(...)):
    user_found = None
    username_found = None
    for username, user_data in users_db.items():
        if user_data["email"] == email:
            user_found = user_data
            username_found = username
            break

    if not user_found:
        raise HTTPException(status_code=404, detail="Email not found.")

    # Generate a unique token for password reset
    reset_token = secrets.token_urlsafe(32)
    # Store the hashed token with an expiry (e.g., 1 hour)
    reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
    users_db[username_found]["reset_token_hash"] = reset_token_hash
    users_db[username_found]["reset_token_expires"] = datetime.utcnow() + timedelta(minutes=60)

    # Send reset email
    reset_link = f"http://localhost:8000/reset-password-form?token={reset_token}" # Adjust for production domain
    send_password_reset_email(email, username_found, reset_link)

    return {"message": "If an account with that email exists, a password reset link has been sent."}

def send_password_reset_email(recipient_email: str, username: str, reset_link: str):
    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        print(f"Skipping password reset email to {recipient_email}: Email credentials not set.")
        return

    subject = "Password Reset Request for Gem ANPR"
    body = f"""
    <html>
        <body>
            <p>Hello {username},</p>
            <p>We received a request to reset the password for your Gem ANPR account.</p>
            <p>Please click the link below to reset your password:</p>
            <p><a href="{reset_link}" style="display: inline-block; padding: 10px 20px; background-color: #007BFF; color: white; text-decoration: none; border-radius: 5px;">Reset Your Password</a></p>
            <p>This link is valid for 60 minutes.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <p>Best regards,<br>The Gem ANPR Team</p>
        </body>
    </html>
    """
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"Password reset email sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send password reset email to {recipient_email}: {e}")

@app.get("/reset-password-form", response_class=HTMLResponse)
async def reset_password_form(request: Request, token: str):
    # This endpoint simply serves the HTML form for password reset
    # The actual password update will happen via a POST request to /reset-password
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@app.post("/reset-password")
async def reset_password(token: str = Body(...), new_password: str = Body(...)):
    user_found = None
    username_found = None
    for username, user_data in users_db.items():
        if user_data.get("reset_token_hash") == hashlib.sha256(token.encode()).hexdigest():
            user_found = user_data
            username_found = username
            break

    if not user_found:
        raise HTTPException(status_code=400, detail="Invalid or expired password reset token.")

    if datetime.utcnow() > user_found.get("reset_token_expires"):
        # Clear expired token data
        users_db[username_found]["reset_token_hash"] = None
        users_db[username_found]["reset_token_expires"] = None
        raise HTTPException(status_code=400, detail="Password reset token has expired.")

    # Update password and clear token data
    users_db[username_found]["password"] = hash_password(new_password)
    users_db[username_found]["reset_token_hash"] = None
    users_db[username_found]["reset_token_expires"] = None

    return {"message": "Your password has been successfully reset."}

@app.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    if username in users_db:
        users_db[username]["refresh_token_hash"] = None # Invalidate refresh token
    return {"message": "Logged out successfully."}

