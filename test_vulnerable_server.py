#!/usr/bin/env python3
"""
Simple vulnerable web server for testing the XSS scanner.
This server intentionally has XSS vulnerabilities for proof-of-concept.
"""

from flask import Flask, request
import sys

app = Flask(__name__)

@app.route('/search')
def search():
    """Vulnerable search endpoint - reflects user input directly in HTML"""
    query = request.args.get('q', 'default')
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Result</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <script>
            console.log("Search term: {query}");
        </script>
    </body>
    </html>
    """

@app.route('/feedback')
def feedback():
    """Vulnerable feedback endpoint - reflects in attribute"""
    message = request.args.get('msg', 'no message')
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Feedback</title></head>
    <body>
        <h1>Feedback Form</h1>
        <input type="text" placeholder="{message}" />
        <p>Message: {message}</p>
    </body>
    </html>
    """

@app.route('/')
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Test Server</title></head>
    <body>
        <h1>XSS Scanner Test Server</h1>
        <p>This server has intentional XSS vulnerabilities for testing</p>
        <ul>
            <li><a href="/search?q=test">/search?q=test (Vulnerable)</a></li>
            <li><a href="/feedback?msg=hello">/feedback?msg=hello (Vulnerable)</a></li>
        </ul>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("[*] Starting vulnerable test server on http://127.0.0.1:5000")
    print("[!] This server has intentional XSS vulnerabilities for testing")
    print("[+] Test endpoints:")
    print("    - http://127.0.0.1:5000/search?q=YOUR_PAYLOAD")
    print("    - http://127.0.0.1:5000/feedback?msg=YOUR_PAYLOAD")
    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True)
