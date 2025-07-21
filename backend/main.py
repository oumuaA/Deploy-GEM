from fastapi import FastAPI, UploadFile, File, Request, Body, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pathlib import Path
from dotenv import load_dotenv
import tempfile
import secrets
import os

# Load environment variables
load_dotenv()

# Create FastAPI app with global Basic Auth applied
security = HTTPBasic()
ALLOWED_USERS = {
    "user1": "pass1",
    "user2": "pass2",
    "user3": "pass3",
    "user4": "pass4",
    "user5": "pass5"
}

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

app = FastAPI(dependencies=[Depends(authenticate)])

# Set up HTML templating
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend"))

# Import from extract.py
from extract import process_base64_image, process_image_file, PROMPT

# Counter
total_images_processed = 0

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/upload")
async def upload_image_api(file: UploadFile = File(...)):
    global total_images_processed

    tmp_path = None
    try:
        # Save uploaded file to temp
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file.filename.split('.')[-1]}") as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name

        # Process with Gemini
        result_text = process_image_file(tmp_path, PROMPT)
        total_images_processed += 1

        return {
            "status_code": 200,
            "status_message": "Success",
            "text": result_text,
            "total_processed": total_images_processed
        }

    except Exception as e:
        print(f"Error processing uploaded image: {e}")
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.post("/base64")
async def process_base64_image_api(data: dict = Body(...)):
    global total_images_processed

    try:
        base64_str = data.get("base64_str")
        if not base64_str:
            return JSONResponse(
                status_code=400,
                content={
                    "status_code": 400,
                    "status_message": "Bad Request: Missing `base64_str` key",
                },
            )

        result_text = process_base64_image(base64_str, PROMPT)
        total_images_processed += 1

        return JSONResponse(
            status_code=200,
            content={
                "status_code": 200,
                "status_message": "Success",
                "text": result_text,
                "total_processed": total_images_processed
            }
        )

    except ValueError as ve:
        return JSONResponse(
            status_code=400,
            content={
                "status_code": 400,
                "status_message": f"Invalid Base64 string: {str(ve)}"
            }
        )

    except Exception as e:
        print(f"Error processing Base64 string: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status_code": 500,
                "status_message": f"Internal Server Error: {str(e)}"
            }
        )
