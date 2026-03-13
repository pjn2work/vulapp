#!/usr/bin/env python
"""Entry point to run the vulnerable Flask application."""
from vulapp.app import app

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
