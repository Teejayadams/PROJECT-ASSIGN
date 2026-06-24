import os
import runpy

# Path to the existing Flask app file (filename contains spaces/commas)
APP_FILE = os.path.join(os.path.dirname(__file__), "from flask import Flask, render_template.py")

_globals = runpy.run_path(APP_FILE)
app = _globals.get("app")
if app is None:
    raise RuntimeError(f"No Flask `app` object found in {APP_FILE}")

# Expose both names commonly used by WSGI servers
application = app

if __name__ == "__main__":
    # Run with Waitress for production-like serving on Windows
    try:
        from waitress import serve
    except Exception:
        raise RuntimeError("waitress is required to run this file. Install with: pip install waitress")
    port = int(os.environ.get("PORT", "8080"))
    serve(application, host="0.0.0.0", port=port)
