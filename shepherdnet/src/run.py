#!/usr/bin/env python3

from app import create_app

DEBUG = False
THREADED = True

app = create_app()

if __name__ == "__main__":
    app.run(debug=DEBUG, threaded=THREADED)