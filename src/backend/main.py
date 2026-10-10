"""Root forwarder for main FastAPI application."""

from netmind.src.backend.main import *  # noqa: F401, F403
from netmind.src.backend.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.backend.main:app", host="0.0.0.0", port=8000, reload=True)
