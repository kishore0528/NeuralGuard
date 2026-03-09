from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import api.database as database
import json
import os

SETTINGS_FILE = "settings.json"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Call init_db on startup
    await database.init_db()
    # Ensure settings.json exists
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w") as f:
            json.dump({"whitelist": ["127.0.0.1", "100.86.74.99"], "threshold": 0.85}, f)
    yield

app = FastAPI(title="NeuralGuard API", lifespan=lifespan)

# CORS Middleware to allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/alerts")
async def get_alerts():
    """Returns the most recent alerts from the database."""
    alerts = await database.get_recent_alerts()
    return {"alerts": alerts}

@app.get("/settings")
async def get_settings():
    """Reads and returns settings.json."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"whitelist": [], "threshold": 0.85}

@app.post("/settings")
async def update_settings(new_settings: dict = Body(...)):
    """Receives a JSON body and overwrites settings.json."""
    with open(SETTINGS_FILE, "w") as f:
        json.dump(new_settings, f, indent=4)
    return {"status": "success", "message": "Settings updated"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
