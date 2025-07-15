from fastapi import FastAPI, UploadFile, File, Request, Body, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import tempfile
import os
from dotenv import load_dotenv
from pathlib import Path

# Import functions and PROMPT from extract.py
from extract import process_base64_image, process_image_file, PROMPT

app = FastAPI()

# Load environment variables
load_dotenv()

# Adjust this path to your actual frontend directory
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend"))
# Assuming 'frontend' folder is at the same level as main.py

# Simple in-memory counter for demonstration (resets on server restart)
total_images_processed = 0

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serves the main HTML page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def upload_image_api(file: UploadFile = File(...)):
    """
    API endpoint to process an uploaded image file.
    This endpoint is unauthenticated.
    """
    global total_images_processed # Declare global to modify the counter

    tmp_path = None
    try:
        # Save the uploaded file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file.filename.split('.')[-1]}") as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name

        # Process the image file using the function from extract.py
        result_text = process_image_file(tmp_path, PROMPT)

        total_images_processed += 1 # Increment global counter
        return {"text": result_text, "total_processed": total_images_processed}
    except Exception as e:
        print(f"Error processing uploaded image: {e}")
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")
    finally:
        # Clean up the temporary file
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.post("/base64")
async def process_base64_image_api(data: dict = Body(...)):
    """
    API endpoint to process a Base64 encoded image string.
    This endpoint is unauthenticated and accepts JSON with 'base64_str'.
    """
    global total_images_processed # Declare global to modify the counter

    try:
        base64_str = data.get("base64_str")
        if not base64_str:
            raise HTTPException(status_code=400, detail="`base64_str` key not found in the JSON body.")

        # Process the Base64 string using the function from extract.py
        result_text = process_base64_image(base64_str, PROMPT)

        total_images_processed += 1 # Increment global counter
        return {"text": result_text, "total_processed": total_images_processed}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 string: {str(ve)}")
    except Exception as e:
        print(f"Error processing Base64 string: {e}")
        raise HTTPException(status_code=500, detail=f"Base64 processing failed: {str(e)}")

