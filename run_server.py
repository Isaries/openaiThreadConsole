from waitress import serve
from app import app
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting production server on http://127.0.0.1:{port}")
    serve(app, host="0.0.0.0", port=port)
