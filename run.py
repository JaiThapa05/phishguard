from waitress import serve
from app import app

if __name__ == "__main__":
    print("PhishGuard production server starting...")

    serve(
        app,
        host="0.0.0.0",
        port=8000,
        threads=4
    )