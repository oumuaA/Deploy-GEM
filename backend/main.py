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

# For email sending
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# For rate limiting (install with: pip install fastapi-limiter redis)
from redis import asyncio as aioredis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

# Assuming these are available and correctly configured in your environment
# Make sure 'extract.py' and your YOLO model ('best3.pt') are in the correct paths
from extract import process_base64_image, yolo_detect_send
from ultralytics import YOLO
import google.generativeai as genai

app = FastAPI()
# Adjust this path to your actual frontend directory
templates = Jinja2Templates(directory="/home/pegasus/Documents/VisionLLM/frontend")

# --- Authentication Configuration ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# IMPORTANT: CHANGE THESE IN PRODUCTION!
# It's highly recommended to use environment variables for SECRET_KEY in production
SECRET_KEY = os.environ.get("SECRET_KEY", "YOUR_VERY_STRONG_AND_RANDOM_SECRET_KEY_HERE_CHANGE_THIS_NOW")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # Tokens expire after 24 hours
VERIFICATION_TOKEN_EXPIRE_MINUTES = 60 * 24 # Email verification link valid for 24 hours
RESET_TOKEN_EXPIRE_MINUTES = 15 # Password reset link valid for 15 minutes

USERS_FILE = "users.json"
# Placeholder for blacklisted tokens (for logout/password change invalidation)
TOKEN_BLACKLIST_FILE = "token_blacklist.json"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Global variable to hold the Redis connection instance
redis_client_instance = None

# --- Redis for Rate Limiting ---
@app.on_event("startup")
async def startup_event():
    """Initializes Redis connection and FastAPILimiter on application startup."""
    global redis_client_instance # Declare intent to modify global variable
    try:
        # Attempt to connect to Redis
        temp_redis_client = aioredis.from_url("redis://localhost", encoding="utf8", decode_responses=True)
        
        # Ping Redis to ensure connection is active and responsive
        await temp_redis_client.ping()
        print("Successfully connected to Redis.")
        
        # If connection is successful, assign it to the global variable
        redis_client_instance = temp_redis_client

        # Initialize FastAPILimiter only if Redis connection is successful
        await FastAPILimiter.init(redis_client_instance)
        print("FastAPILimiter initialized successfully.")
    except Exception as e:
        print(f"Error connecting to Redis or initializing FastAPILimiter: {e}")
        print("Rate limiting will be disabled due to Redis connection failure.")
        redis_client_instance = None # Ensure it's None if initialization fails

# --- Helper Functions for User Management ---

def load_users():
    """Loads users from the users.json file. Initializes an empty dict if file doesn't exist."""
    if not os.path.exists(USERS_FILE):
        # Create an empty users.json file if it doesn't exist
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)
        return {}
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Handle case where users.json is empty or corrupted
        print(f"Warning: {USERS_FILE} is empty or corrupted. Initializing with empty users.")
        return {}

def save_users(users):
    """Saves users to the users.json file."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def load_token_blacklist():
    """Loads blacklisted tokens."""
    if not os.path.exists(TOKEN_BLACKLIST_FILE):
        with open(TOKEN_BLACKLIST_FILE, "w") as f:
            json.dump({}, f)
        return {}
    try:
        with open(TOKEN_BLACKLIST_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Warning: {TOKEN_BLACKLIST_FILE} is empty or corrupted. Initializing with empty blacklist.")
        return {}

def save_token_blacklist(blacklist):
    """Saves blacklisted tokens."""
    with open(TOKEN_BLACKLIST_FILE, "w") as f:
        json.dump(blacklist, f, indent=4)

def is_token_blacklisted(token: str):
    """Checks if a token is in the blacklist."""
    blacklist = load_token_blacklist()
    # Hash the token to store/check its hash, not the token itself directly in plaintext
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token_hash in blacklist

def add_token_to_blacklist(token: str):
    """Adds a token to the blacklist."""
    blacklist = load_token_blacklist()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    blacklist[token_hash] = datetime.utcnow().isoformat() # Store when it was blacklisted
    save_token_blacklist(blacklist)

def verify_password(plain_password, hashed_password):
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Hashes a plain password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire.timestamp()}) # Store as Unix timestamp
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Email Sending Function (Requires Configuration!) ---
async def send_email(to_email: str, subject: str, body: str):
    """
    Sends an email using SMTP.
    
    ####################################################################################################
    ### --- START: YOU MUST CONFIGURE THESE EMAIL DETAILS ---
    ###
    ### THESE VALUES ARE PLACEHOLDERS. For email sending to work, you need to:
    ###
    ### 1.  SMTP_SERVER: Replace "smtp.gmail.com" with the OUTGOING MAIL SERVER (SMTP) address
    ###     for the email account you want to SEND EMAILS FROM.
    ###     -   Example for Gmail: "smtp.gmail.com"
    ###     -   Example for Outlook/Hotmail: "smtp.office365.com"
    ###     -   For other providers, search "YOUR_EMAIL_PROVIDER SMTP settings".
    ###
    ### 2.  SMTP_PORT: Replace 587 with the correct port for your SMTP server.
    ###     -   Common for TLS (recommended): 587
    ###     -   Common for SSL: 465 (if using 465, the code will use smtplib.SMTP_SSL)
    ###
    ### 3.  SENDER_EMAIL: Replace "your_email@example.com" with the ACTUAL, FULL EMAIL ADDRESS
    ###     you are using to send emails FROM. This is the account that will log into the SMTP server.
    ###
    ### 4.  SENDER_PASSWORD: Replace "your_email_password" with the ACTUAL PASSWORD for the
    ###     SENDER_EMAIL account.
    ###     -   CRITICAL FOR GMAIL WITH 2-FACTOR AUTHENTICATION (2FA): You CANNOT use your
    ###         regular Gmail password here. You MUST generate an "App Password" from your
    ###         Google Account security settings (myaccount.google.com -> Security -> App passwords).
    ###         It will be a 16-character code. Use THAT code here.
    ###     -   For other providers with 2FA, check their documentation for app-specific passwords.
    ###
    ### If these are not configured correctly, emails WILL NOT be sent, and you will continue
    ### to see "Username and Password not accepted" errors if the server is reached,
    ### or other connection errors if the server/port is wrong.
    ####################################################################################################
    """
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "your_email@example.com") # <--- CHANGE THIS LINE
    SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "your_email_password") # <--- CHANGE THIS LINE
    # --- END: YOU MUST CONFIGURE THESE EMAIL DETAILS ---

    if SENDER_EMAIL == "your_email@example.com" or SENDER_PASSWORD == "your_email_password":
        print("\n" * 3) # Add some space for visibility
        print("!" * 80)
        print("!!! WARNING: EMAIL SENDING IS NOT CONFIGURED !!!")
        print("!!! Please update SENDER_EMAIL and SENDER_PASSWORD in main.py or environment variables. !!!")
        print("!!! Emails WILL NOT be sent until this is done. !!!")
        print("!" * 80)
        print(f"--- Faking Email Send (No real email sent) ---")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"Body:\n{body}")
        print(f"---------------------------------------------")
        print("\n" * 3)
        return

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        print(f"Attempting to send email to {to_email} from {SENDER_EMAIL}...")
        # Use SMTP_SSL for port 465, or SMTP with starttls for port 587
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls() # Secure the connection

        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, to_email, text)
        server.quit()
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        # Log the full traceback for debugging
        import traceback
        traceback.print_exc()

# --- Token Generation and Hashing for Storage ---
def generate_secure_token(length: int = 32):
    """Generates a secure random token."""
    return secrets.token_urlsafe(length)

def hash_token(token: str):
    """Hashes a token for secure storage (e.g., verification or reset tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()

# --- Dependency to get current user (with token blacklist check) ---
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get the current authenticated user's email, username, and image_count from the token."""
    if is_token_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        username: str = payload.get("username")
        image_count: int = payload.get("image_count", 0)

        if email is None or username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials (missing email or username)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        users = load_users()
        user_data = users.get(email)

        if not user_data or user_data.get("username") != username:
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or credentials mismatch",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # This is the crucial check for email verification
        if not user_data.get("is_verified", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not verified. Please check your email and verify your account to log in and use protected features.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {"email": email, "username": username, "image_count": image_count}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials or token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

# --- FastAPI App Initialization ---
# Adjust these paths to your actual model files
# Ensure these files exist and are accessible from where your FastAPI app runs
try:
    yolo_model = YOLO("/home/pegasus/Documents/VisionLLM/best3.pt")
    print("YOLO model loaded successfully.")
except Exception as e:
    print(f"Error loading YOLO model: {e}. Please ensure 'best3.pt' path is correct.")
    yolo_model = None # Set to None if loading fails to prevent further errors

try:
    gemini_model = genai.GenerativeModel(model_name="gemini-2.0-flash-lite")
    print("Gemini model loaded successfully.")
except Exception as e:
    print(f"Error loading Gemini model: {e}. Ensure 'google-generativeai' is configured.")
    gemini_model = None # Set to None if loading fails

PROMPT = "What is written on the vehicle number plate? Give me in one line, or in the given yellow image."

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    """Serves the main HTML page. This endpoint does NOT require authentication."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/register", dependencies=[Depends(RateLimiter(times=5, seconds=60))]) # 5 requests per minute
async def register_user(user_data: dict = Body(...)):
    """
    Registers a new user and sends an email verification link.
    Expects JSON: {"email": "user@example.com", "password": "password", "username": "JohnDoe"}
    """
    email = user_data.get("email")
    password = user_data.get("password")
    username = user_data.get("username") # Corrected: user_data.get("username") instead of user.get("username")

    if not email or not password or not username:
        raise HTTPException(status_code=400, detail="Email, username, and password are required.")
    
    if len(password) < 8: # Basic password policy
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    users = load_users()
    if email in users:
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    hashed_password = get_password_hash(password)
    verification_token = generate_secure_token()
    hashed_verification_token = hash_token(verification_token)
    token_expiry = (datetime.utcnow() + timedelta(minutes=VERIFICATION_TOKEN_EXPIRE_MINUTES)).isoformat()

    users[email] = {
        "hashed_password": hashed_password,
        "username": username,
        "image_count": 0,
        "is_verified": False,
        "verification_token": hashed_verification_token,
        "verification_token_expiry": token_expiry
    }
    save_users(users)

    verification_link = f"http://localhost:8000/verify-email?token={verification_token}&email={email}"
    await send_email(
        to_email=email,
        subject="Verify your account for Gem ANPR",
        body=f"Hi {username},\n\nThank you for registering with Gem ANPR! Please click on the following link to verify your account:\n\n{verification_link}\n\nThis link will expire in {VERIFICATION_TOKEN_EXPIRE_MINUTES} minutes.\n\nIf you did not register for this service, please ignore this email."
    )

    return {"message": "User registered successfully! Please check your email to verify your account."}

@app.get("/verify-email")
async def verify_email(token: str, email: str):
    """
    Endpoint for email verification.
    This endpoint should be accessed by clicking the link in the verification email.
    """
    users = load_users()
    user_info = users.get(email)

    if not user_info:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if user_info.get("is_verified"):
        return JSONResponse(status_code=200, content={"message": "Email already verified."})

    stored_hashed_token = user_info.get("verification_token")
    stored_expiry = user_info.get("verification_token_expiry")

    if not stored_hashed_token or not stored_expiry:
        raise HTTPException(status_code=400, detail="Invalid verification link or token missing.")
    
    # Compare the hash of the provided token with the stored hash
    if hash_token(token) != stored_hashed_token:
        raise HTTPException(status_code=400, detail="Invalid verification token.")

    # Check if the token has expired
    if datetime.utcnow() > datetime.fromisoformat(stored_expiry):
        raise HTTPException(status_code=400, detail="Verification token has expired. Please register again to get a new link.")
    
    user_info["is_verified"] = True
    # Clear the verification token and expiry after successful verification for security
    user_info["verification_token"] = None
    user_info["verification_token_expiry"] = None
    save_users(users)

    return JSONResponse(status_code=200, content={"message": "Email verified successfully! You can now log in."})

@app.post("/login", dependencies=[Depends(RateLimiter(times=5, seconds=60))]) # 5 requests per minute
async def login_for_access_token(user_data: dict = Body(...)):
    """
    Authenticates a user and returns an access token.
    Expects JSON: {"email": "user@example.com", "password": "password"}
    """
    email = user_data.get("email")
    password = user_data.get("password")

    users = load_users()
    user_info = users.get(email)

    if not user_info or not verify_password(password, user_info["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # This check is crucial: only verified users can log in
    if not user_info.get("is_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not verified. Please check your email and verify your account.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email, "username": user_info["username"], "image_count": user_info.get("image_count", 0)},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "email": email,
        "username": user_info["username"],
        "image_count": user_info.get("image_count", 0)
    }

@app.post("/logout")
async def logout(current_user: dict = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    """
    Logs out the current user by blacklisting their access token.
    Requires authentication to ensure a valid token is being blacklisted.
    """
    add_token_to_blacklist(token)
    return {"message": "Successfully logged out."}

@app.post("/forgot-password", dependencies=[Depends(RateLimiter(times=2, seconds=300))]) # 2 requests per 5 minutes
async def forgot_password(email_data: dict = Body(...)):
    """
    Initiates the password recovery process. Sends a reset link to the user's email.
    Expects JSON: {"email": "user@example.com"}
    """
    email = email_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required.")

    users = load_users()
    user_info = users.get(email)

    if not user_info:
        # For security, always return a generic message to prevent email enumeration attacks.
        print(f"Attempted password reset for non-existent email: {email}")
        return {"message": "If an account with that email exists, a password reset link has been sent."}
    
    reset_token = generate_secure_token()
    hashed_reset_token = hash_token(reset_token)
    token_expiry = (datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)).isoformat()

    user_info["reset_token"] = hashed_reset_token
    user_info["reset_token_expiry"] = token_expiry
    save_users(users)

    reset_link = f"http://localhost:8000/reset-password?token={reset_token}&email={email}"
    await send_email(
        to_email=email,
        subject="Password Reset for Gem ANPR",
        body=f"Hi {user_info['username']},\n\nYou have requested a password reset. Please click on the following link to reset your password:\n\n{reset_link}\n\nThis link will expire in {RESET_TOKEN_EXPIRE_MINUTES} minutes.\n\nIf you did not request this, please ignore this email."
    )
    return {"message": "If an account with that email exists, a password reset link has been sent."}

@app.post("/reset-password", dependencies=[Depends(RateLimiter(times=5, seconds=60))]) # 5 requests per minute
async def reset_password(reset_data: dict = Body(...)):
    """
    Resets the user's password using a valid reset token.
    Expects JSON: {"email": "user@example.com", "token": "...", "new_password": "..."}
    """
    email = reset_data.get("email")
    token = reset_data.get("token")
    new_password = reset_data.get("new_password")

    if not all([email, token, new_password]):
        raise HTTPException(status_code=400, detail="Email, token, and new password are required.")
    
    if len(new_password) < 8: # Basic password policy
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters long.")


    users = load_users()
    user_info = users.get(email)

    if not user_info:
        raise HTTPException(status_code=404, detail="User not found.")
    
    stored_hashed_token = user_info.get("reset_token")
    stored_expiry = user_info.get("reset_token_expiry")

    if not stored_hashed_token or not stored_expiry:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link. Please request a new one.")
    
    # Compare the hash of the provided token with the stored hash
    if hash_token(token) != stored_hashed_token:
        raise HTTPException(status_code=400, detail="Invalid reset token.")

    # Check if the token has expired
    if datetime.utcnow() > datetime.fromisoformat(stored_expiry):
        raise HTTPException(status_code=400, detail="Reset token has expired. Please request a new link.")
    
    user_info["hashed_password"] = get_password_hash(new_password)
    # Clear the reset token and expiry after successful reset for security
    user_info["reset_token"] = None
    user_info["reset_token_expiry"] = None
    save_users(users)

    return {"message": "Password reset successfully!"}


# --- PROTECTED ENDPOINTS (require authentication) ---
@app.post("/upload", dependencies=[Depends(get_current_user), Depends(RateLimiter(times=100, minutes=1))])
async def upload_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """
    Endpoint to upload an image file and process it for license plate detection.
    Requires authentication.
    """
    if yolo_model is None or gemini_model is None:
        raise HTTPException(status_code=5_00, detail="AI models not loaded. Cannot process image.")

    current_user_email = current_user["email"]
    current_username = current_user["username"]
    
    try:
        print(f"User '{current_username}' ({current_user_email}) uploading image.")

        contents = await file.read()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        results = yolo_detect_send(tmp_path, yolo_model, gemini_model, PROMPT)
        
        users = load_users()
        if current_user_email in users:
            users[current_user_email]["image_count"] = users[current_user_email].get("image_count", 0) + 1
            save_users(users)
            updated_image_count = users[current_user_email]["image_count"]
        else:
            # This case should ideally not happen if get_current_user works correctly
            updated_image_count = current_user.get("image_count", 0) + 1 

        return {"plates": results, "image_count": updated_image_count}

    except Exception as e:
        raise HTTPException(status_code=5_00, detail=f"Image upload failed: {str(e)}")

@app.post("/base64", dependencies=[Depends(get_current_user), Depends(RateLimiter(times=100, minutes=1))])
async def base64_image_api(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    """
    API endpoint to process a Base64 encoded image string.
    Expects a JSON body with a 'base64_str' key.
    Requires authentication.
    """
    if yolo_model is None or gemini_model is None:
        raise HTTPException(status_code=5_00, detail="AI models not loaded. Cannot process image.")

    current_user_email = current_user["email"]
    current_username = current_user["username"]

    try:
        print(f"User '{current_username}' ({current_user_email}) processing Base64 image.")

        base64_str = data.get("base64_str")
        if not base64_str:
            raise HTTPException(status_code=400, detail="base64_str key not found in the JSON body.")

        result = process_base64_image(base64_str, PROMPT)

        users = load_users()
        if current_user_email in users:
            users[current_user_email]["image_count"] = users[current_user_email].get("image_count", 0) + 1
            save_users(users)
            updated_image_count = users[current_user_email]["image_count"]
        else:
            updated_image_count = current_user.get("image_count", 0) + 1 

        return {"text": result, "image_count": updated_image_count}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=5_00, detail=f"Internal server error: {str(e)}")

# --- UNPROTECTED ENDPOINTS (for free trial) ---
@app.post("/upload-free", dependencies=[Depends(RateLimiter(times=5, hours=1))]) # 5 free uploads per hour
async def upload_image_unauthenticated(file: UploadFile = File(...)):
    """
    Endpoint to upload an image file and process it for license plate detection.
    Does NOT require authentication (for free trial).
    """
    if yolo_model is None or gemini_model is None:
        raise HTTPException(status_code=5_00, detail="AI models not loaded. Cannot process image.")

    try:
        print("Unauthenticated user uploading image (free trial).")
        contents = await file.read()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        results = yolo_detect_send(tmp_path, yolo_model, gemini_model, PROMPT)
        return {"plates": results}

    except Exception as e:
        raise HTTPException(status_code=5_00, detail=f"Image upload failed: {str(e)}")

@app.post("/base64-free", dependencies=[Depends(RateLimiter(times=5, hours=1))]) # 5 free base64 processes per hour
async def base64_image_api_unauthenticated(data: dict = Body(...)):
    """
    API endpoint to process a Base64 encoded image string.
    Does NOT require authentication (for free trial).
    """
    if yolo_model is None or gemini_model is None:
        raise HTTPException(status_code=5_00, detail="AI models not loaded. Cannot process image.")

    try:
        print("Unauthenticated user processing Base64 image (free trial).")
        base64_str = data.get("base64_str")
        if not base64_str:
            raise HTTPException(status_code=400, detail="base64_str key not found in the JSON body.")

        result = process_base64_image(base64_str, PROMPT)
        return {"text": result}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=5_00, detail=f"Internal server error: {str(e)}")
