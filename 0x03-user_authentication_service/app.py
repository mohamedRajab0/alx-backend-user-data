#!/usr/bin/env python3

import bcrypt
from flask import Flask, jsonify, request, abort, make_response, redirect  # Import make_response and redirect from flask
from auth import Auth
from db import DB


AUTH = Auth()
db = DB()
app = Flask(__name__)

@app.route("/", methods=['GET'])
def index():
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=['GET', 'POST'])  # Moved before app.run()
def user():
    email = request.form.get("email")
    password = request.form.get("password")
    
    try:
        user = AUTH.register_user(email, password)  # Use the AUTH instance
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    return jsonify({"email": f"{email}", "message": "user created"})


@app.route('/sessions', methods=['POST'])
def login():
    try:
        # Extract email and password from form data
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            abort(401)

        # Create an instance of DB and find the user by email
        user = db.find_user_by(email=email)

        if user is None:
            # If the user is not found, abort with 401 Unauthorized
            abort(401)

        # Check if the provided password matches the stored hash
        pass_byte = password.encode('utf-8')

        # No need to encode hashed_password, bcrypt expects it as bytes
        if not bcrypt.checkpw(pass_byte, user.hashed_password):
            abort(401)

        # Create a session for the user
        session_id = AUTH.create_session(email)
        # Create the response with session ID as a cookie
        response = make_response(jsonify({"email": email, "message": "logged in"}))
        response.set_cookie("session_id", session_id)
        return response

    except ValueError as e:
        abort(401)
    except Exception as e:
        print(f"Internal Server Error: {e}")
        abort(500)
@app.route('/sessions', methods=['DELETE'])
def logout():
    """Logout the user by destroying their session."""
    # Retrieve the session_id from the cookie
    session_id = request.cookies.get('session_id')

    if not session_id:
        # If there is no session_id, respond with 403 Forbidden
        abort(403)

    # Find the user associated with the session_id
    user = db.find_user_by(session_id=session_id)

    if user is None:
        # If the user is not found, respond with 403 Forbidden
        abort(403)

    # Destroy the user's session
    Auth.destroy_session(user.id)

    # Redirect to the root (GET /)
    return redirect('/')
@app.route('/profile', methods=['GET'])
def profile():
    """Return the profile of the logged-in user."""
    # Retrieve the session_id from the cookie
    session_id = request.cookies.get('session_id')

    if not session_id:
        # If there is no session_id, respond with 403 Forbidden
        abort(403)

    # Find the user associated with the session_id
    user = db.find_user_by(session_id=session_id)

    if user is None:
        # If the user is not found, respond with 403 Forbidden
        abort(403)

    # Respond with the user's email and a 200 OK status
    return jsonify({"email": user.email}), 200
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # 'port' should be an integer
