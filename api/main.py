from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import api.database as database

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Call init_db on startup
    await database.init_db()
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
