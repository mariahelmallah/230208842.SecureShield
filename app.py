from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import json
import jwt
import datetime
from functools import wraps
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey123'
bcrypt = Bcrypt(app)

# 🔥 Logging setup
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 🔒 Blacklist
blacklist = []

# 🔐 Token Middleware
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({"message": "Token is missing"}), 401

        try:
            parts = auth_header.split()

            if len(parts) != 2 or parts[0] != "Bearer":
                return jsonify({"message": "Invalid token format"}), 401

            token = parts[1]

            # 🔥 check blacklist
            if token in blacklist:
                return jsonify({"message": "Token is revoked"}), 401

            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data

        except Exception as e:
            logging.error("Invalid token used")
            return jsonify({"message": "Token is invalid"}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# 📂 Load users
def load_users():
    try:
        with open('users.json', 'r') as file:
            return json.load(file)
    except:
        return []

# 💾 Save users
def save_users(users):
    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)

# 🏠 Home
@app.route('/')
def home():
    return "SecureShield API is running!"

# 👤 Profile
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        "message": "Welcome!",
        "user": current_user
    })

# 🗑️ Delete User (Admin only)
@app.route('/user/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):

    if current_user['role'] != 'Admin':
        logging.warning(f"Unauthorized DELETE attempt by {current_user['username']}")
        return jsonify({"message": "Access denied"}), 403

    users = load_users()

    new_users = [user for user in users if user['id'] != id]

    if len(users) == len(new_users):
        return jsonify({"message": "User not found"}), 404

    save_users(new_users)

    logging.info(f"Admin {current_user['username']} deleted user {id}")

    return jsonify({"message": "User deleted successfully"}), 200

# 🔐 Register
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'User')

    users = load_users()

    for user in users:
        if user['username'] == username:
            return jsonify({"message": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = {
        "id": len(users) + 1,
        "username": username,
        "password": hashed_password,
        "role": role
    }

    users.append(new_user)
    save_users(users)

    logging.info(f"New user registered: {username}")

    return jsonify({"message": "User registered successfully!"}), 201

# 🔐 Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    users = load_users()

    for user in users:
        if user['username'] == username:

            if bcrypt.check_password_hash(user['password'], password):

                token = jwt.encode({
                    'username': user['username'],
                    'role': user['role'],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }, app.config['SECRET_KEY'], algorithm='HS256')

                logging.info(f"User {username} logged in")

                return jsonify({"token": token}), 200

            else:
                logging.warning(f"Wrong password for {username}")
                return jsonify({"message": "Wrong password"}), 401

    logging.warning(f"Login attempt for non-existing user {username}")
    return jsonify({"message": "User not found"}), 404

# 🔓 Logout (Blacklist)
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):

    auth_header = request.headers.get('Authorization')
    token = auth_header.split()[1]

    blacklist.append(token)

    logging.info(f"User {current_user['username']} logged out")

    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True)