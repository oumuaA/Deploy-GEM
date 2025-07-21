from fastapi import FastAPI, UploadFile, File, Request, Body, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pathlib import Path
from dotenv import load_dotenv
import tempfile
import secrets
import os
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# 🔐 Auth setup
security = HTTPBasic()
ALLOWED_USERS = {
    "user1": "pass1",
    "user2": "pass2",
    "user3": "pass3",
    "user4": "pass4",
    "user5": "pass5"
}

# 🧠 Track user upload counts + reset time
user_upload_count = {}
user_reset_time = {}

# 📦 App instance with global auth
app = FastAPI()

# 🌐 HTML Templates (optional)
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend"))

# 🧠 Import from your extractor
from extract import process_base64_image, process_image_file, PROMPT

# 📊 Global count
total_images_processed = 0

# ✅ Auth logic
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = credentials.username in ALLOWED_USERS
    correct_password = (
        correct_username and
        secrets.compare_digest(credentials.password, ALLOWED_USERS[credentials.username])
    )
    if not correct_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# 📅 Reset check
def check_and_reset_user_limit(username):
    now = datetime.utcnow()
    reset_time = user_reset_time.get(username)

    if reset_time is None or now >= reset_time:
        user_upload_count[username] = 0
        user_reset_time[username] = now + timedelta(days=1)

# 🏠 Root route
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# 🖼️ File upload endpoint
@app.post("/upload")
async def upload_image_api(file: UploadFile = File(...), username: str = Depends(authenticate)):
    global total_images_processed

    check_and_reset_user_limit(username)

    if user_upload_count.get(username, 0) >= 15:
        return JSONResponse(
            status_code=429,
            content={
                "status_code": 429,
                "status_message": "❌ Your limit is full. Try again later or contact admin.",
                "text": None,
                "total_processed": total_images_processed
            }
        )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file.filename.split('.')[-1]}") as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name

        result_text = process_image_file(tmp_path, PROMPT)
        user_upload_count[username] = user_upload_count.get(username, 0) + 1
        total_images_processed += 1

        return {
            "status_code": 200,
            "status_message": "Success",
            "text": result_text,
            "total_processed": total_images_processed
        }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status_code": 500,
                "status_message": f"Image upload failed: {str(e)}",
                "text": None,
                "total_processed": total_images_processed
            }
        )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

# 🧬 Base64 upload endpoint
@app.post("/base64")
async def process_base64_image_api(data: dict = Body(...), username: str = Depends(authenticate)):
    global total_images_processed

    check_and_reset_user_limit(username)

    if user_upload_count.get(username, 0) >= 15:
        return JSONResponse(
            status_code=429,
            content={
                "status_code": 429,
                "status_message": "❌ Your limit is full. Try again later or contact admin.",
                "text": None,
                "total_processed": total_images_processed
            }
        )

    try:
        base64_str = data.get("base64_str")
        if not base64_str:
            return JSONResponse(
                status_code=400,
                content={
                    "status_code": 400,
                    "status_message": "Bad Request: Missing `base64_str` key",
                    "text": None,
                    "total_processed": total_images_processed
                }
            )

        result_text = process_base64_image(base64_str, PROMPT)
        user_upload_count[username] = user_upload_count.get(username, 0) + 1
        total_images_processed += 1

        return {
            "status_code": 200,
            "status_message": "Success",
            "text": result_text,
            "total_processed": total_images_processed
        }

    except ValueError as ve:
        return JSONResponse(
            status_code=400,
            content={
                "status_code": 400,
                "status_message": f"Invalid Base64 string: {str(ve)}",
                "text": None,
                "total_processed": total_images_processed
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status_code": 500,
                "status_message": f"Internal Server Error: {str(e)}",
                "text": None,
                "total_processed": total_images_processed
            }
        )
