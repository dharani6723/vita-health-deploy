from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os

# === Import model utilities ===
from model.model_utils import (
    load_vitamin_model,
    load_class_indices,
    load_mapping,
    predict_vitamin_deficiency
)

# === Configuration ===
app = Flask(__name__)
CORS(app)
SECRET_KEY = os.environ.get("VITAMIN_SECRET_KEY", "vitamin_secret_key")
DB_PATH = os.path.join(os.path.dirname(__file__), "db.sqlite3")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# === Load Model Once on Startup ===
MODEL_PATH = os.path.join("model", "vitamin_deficiency_model.h5")
JSON_PATH = os.path.join("model", "class_indices.json")
CSV_PATH = os.path.join("model", "vitamin_deficiency_data.csv")

model = load_vitamin_model(MODEL_PATH)
class_indices = load_class_indices(JSON_PATH)
mapping = load_mapping(CSV_PATH)

# === Database Utility ===
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# === Init DB ===
def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT,
            lastname TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    # User vitamins table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_vitamins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            vitamin TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Vitamin progress table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vitamin_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_vitamin_id INTEGER,
            day_index INTEGER,
            completed INTEGER DEFAULT 0,
            FOREIGN KEY(user_vitamin_id) REFERENCES user_vitamins(id)
        )
    """)

    conn.commit()
    conn.close()

init_db()

# === Helper: decode token ===
def decode_token(request):
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    elif auth_header:
        token = auth_header
    if not token:
        return None, jsonify({"message": "No token provided"}), 403
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({"message": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"message": "Invalid token"}), 401

# === Register Route ===
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    firstname = data.get("firstname")
    lastname = data.get("lastname")
    email = data.get("email")
    password = data.get("password")

    if not firstname or not lastname or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    hashed_password = generate_password_hash(password)
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)",
            (firstname, lastname, email, hashed_password),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully!"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "User already exists"}), 400

# === Login Route ===
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"message": "User not found"}), 400
    if not check_password_hash(row["password"], password):
        return jsonify({"message": "Invalid password"}), 401

    payload = {
        "id": row["id"],
        "email": row["email"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return jsonify({
        "message": "Login successful",
        "token": token,
        "firstname": row["firstname"],
        "lastname": row["lastname"],
        "email": row["email"]
    })

# === Profile Route ===
@app.route("/profile", methods=["GET"])
def profile():
    decoded, error_response, status = decode_token(request)
    if error_response:
        return error_response, status

    user_id = decoded["id"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, firstname, lastname, email FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": row["id"],
        "firstname": row["firstname"],
        "lastname": row["lastname"],
        "email": row["email"]
    })

# === Save Detected Vitamin ===
@app.route("/save_vitamin", methods=["POST"])
def save_vitamin():
    data = request.get_json() or {}
    vitamin = data.get("vitamin")
    decoded, error_response, status = decode_token(request)
    if error_response:
        return error_response, status
    user_id = decoded["id"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM user_vitamins WHERE user_id = ? AND vitamin = ?", (user_id, vitamin))
    existing = cur.fetchone()

    if existing:
        vitamin_id = existing["id"]
    else:
        cur.execute("INSERT INTO user_vitamins (user_id, vitamin) VALUES (?, ?)", (user_id, vitamin))
        vitamin_id = cur.lastrowid
        for i in range(7):
            cur.execute("INSERT INTO vitamin_progress (user_vitamin_id, day_index) VALUES (?, ?)", (vitamin_id, i))

    conn.commit()
    conn.close()
    return jsonify({"message": "Vitamin saved successfully", "vitamin_id": vitamin_id})

# === Get User Vitamins & Progress ===
@app.route("/user_vitamins", methods=["GET"])
def get_user_vitamins():
    decoded, error_response, status = decode_token(request)
    if error_response:
        return error_response, status
    user_id = decoded["id"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM user_vitamins WHERE user_id = ?", (user_id,))
    vitamins = [dict(v) for v in cur.fetchall()]

    for v in vitamins:
        cur.execute("SELECT day_index, completed FROM vitamin_progress WHERE user_vitamin_id = ?", (v["id"],))
        v["progress"] = [dict(p) for p in cur.fetchall()]

    conn.close()
    return jsonify(vitamins)

# === Delete Vitamin ===
@app.route("/delete_vitamin/<int:vitamin_id>", methods=["DELETE"])
def delete_vitamin(vitamin_id):
    decoded, error_response, status = decode_token(request)
    if error_response:
        return error_response, status

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM vitamin_progress WHERE user_vitamin_id = ?", (vitamin_id,))
    cur.execute("DELETE FROM user_vitamins WHERE id = ?", (vitamin_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Vitamin deleted successfully"})

# === Prediction Route ===
@app.route("/predict", methods=["POST"])
def predict():
    if "image" not in request.files:
        return jsonify({"message": "No image uploaded"}), 400
    img = request.files["image"]
    save_path = os.path.join(UPLOAD_FOLDER, img.filename)
    img.save(save_path)

    try:
        result = predict_vitamin_deficiency(model, class_indices, mapping, save_path)
        return jsonify({
            "predicted_disease": result["predicted_disease"],
            "vitamin_deficiency": result["mapped_deficiency"],
            "confidence": float(result["confidence"])
        })
    except Exception as e:
        return jsonify({"message": f"Prediction error: {str(e)}"}), 500

@app.route("/", methods=["GET"])
def home():
    return "✅ Flask backend for Vitamin Detection running successfully!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
