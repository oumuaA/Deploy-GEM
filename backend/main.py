from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "✅ FastAPI is working on Vercel!"}

handler = Mangum(app)
