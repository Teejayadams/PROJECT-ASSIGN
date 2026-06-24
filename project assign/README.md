# Running the app with a production WSGI server

Install dependencies:

```
python -m pip install -r requirements.txt
```

Run with Waitress (recommended on Windows):

```
# option 1: run the module directly
python wsgi.py

# option 2: use the waitress CLI
waitress-serve --port=8080 wsgi:application
```

On Linux you can also use Gunicorn (install separately) and point it at `wsgi:application`.

Notes:
- The project file containing the Flask `app` has an unusual filename: `from flask import Flask, render_template.py`. The `wsgi.py` loader handles that filename automatically.
- Configure `PORT` env var to change the listen port.