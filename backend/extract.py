import base64
from PIL import Image
import google.generativeai as genai
from dotenv import load_dotenv
import mimetypes
import os

load_dotenv()

# Configure the Gemini model using API key from environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("WARNING: GEMINI_API_KEY environment variable is not set. Gemini API calls may fail.")
    # In a production setting, you might want to raise an error here
genai.configure(api_key=GEMINI_API_KEY)

Google_model = genai.GenerativeModel(model_name='gemini-2.0-flash-lite')
PROMPT = "What is written on the vehicle number plate? Give me in one line, or in the given image."

def process_base64_image(base64_str, prompt):
    """
    Processes a Base64 encoded image string using the Gemini model.
    """
    try:
        if not base64_str.startswith("data:"):
            raise ValueError("Invalid base64 string format. Expected 'data:image/jpeg;base64,...' or similar.")

        header, base64_data = base64_str.split(",", 1)
        mime_type = header.split(";")[0].replace("data:", "")

        # Prepare the image part for Gemini
        image_input = {
            "inline_data": {
                "mime_type": mime_type,
                "data": base64_data
            }
        }

        # Send to Gemini
        response = Google_model.generate_content([prompt, image_input])
        return response.text.strip() # Return only the text content, stripped of whitespace

    except Exception as e:
        print(f"Error processing base64 image: {str(e)}")
        raise e # Re-raise for FastAPI to catch and return as HTTP error

def process_image_file(image_file_path, prompt):
    """
    Processes an image file (given its path) using the Gemini model.
    """
    try:
        # Open the image file using PIL (Pillow)
        image = Image.open(image_file_path)

        # Send the image directly to Gemini
        response = Google_model.generate_content([prompt, image])
        return response.text.strip() # Return only the text content, stripped of whitespace

    except Exception as e:
        print(f"Error processing image file: {str(e)}")
        raise e # Re-raise for FastAPI to catch and return as HTTP error
