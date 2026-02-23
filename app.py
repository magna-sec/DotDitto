"""
DotDitto — app.py
Entry point: creates the Flask app, registers routes, and starts the server.
"""
from flask import Flask

from routes import bp
from session_store import load_session_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

app.register_blueprint(bp)


if __name__ == "__main__":
    load_session_file()
    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║   ··  D o t D i t t o  ··            ║")
    print("  ║   NTDS Dump Analyzer                  ║")
    print("  ║                                       ║")
    print("  ║   http://localhost:5000               ║")
    print("  ╚══════════════════════════════════════╝")
    print()
    app.run(debug=False, host="127.0.0.1", port=5000)
