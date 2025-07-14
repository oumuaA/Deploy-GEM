import cv2
import base64
from ultralytics import YOLO
from PIL import Image
import google.generativeai as genai
from dotenv import load_dotenv
import mimetypes

load_dotenv()

yolo_model = YOLO("/home/pegasus/Documents/VisionLLM/best3.pt")
Google_model = genai.GenerativeModel(model_name='gemini-2.0-flash-lite')
PROMPT = "What is written on the vehicle number plate? Give me in one line, or in the given image."


def process_base64_image(base64_str, prompt):
    try:
        if not base64_str.startswith("data:"):
            raise ValueError("Invalid base64 string format")

        header, base64_data = base64_str.split(",", 1)
        mime_type = header.split(";")[0].replace("data:", "")

        # prepare the image part
        image_input = {
            "inline_data": {
                "mime_type": mime_type,
                "data": base64_data
            }
        }

        # send to Gemini
        response = Google_model.generate_content([prompt, image_input])
        return response.text

    except Exception as e:
        return f"❌ Error: {str(e)}"


def yolo_detect_send(image_path, yolo_model, gemini_model, PROMPT):
    yolo_image = cv2.imread(image_path)
    if yolo_image is None:
        raise ValueError('❌ No image detected. Check the path.')

    result = yolo_model.predict(yolo_image, conf=0.1)
    output = []

    for r in result:
        boxes = r.boxes.xyxy.cpu().numpy().astype(int)
        for i, (x1, y1, x2, y2) in enumerate(boxes):
            crop = yolo_image[y1:y2, x1:x2]
            if crop.size == 0:
                continue

            cropped_pil = Image.fromarray(cv2.cvtColor(crop, cv2.COLOR_BGR2RGB))

            try:
                response = gemini_model.generate_content([PROMPT, cropped_pil])
                text = response.text.strip()
            except Exception as e:
                text = f"Error from Gemini: {str(e)}"

            output.append({
                "plate_number": i + 1,
                "text": text
            })

    cv2.destroyAllWindows()
    return output


def upload_IMG(image_path, prompt):
    image = Image.open(image_path)
    response = Google_model.generate_content([prompt, image])
    return response.text.strip()
