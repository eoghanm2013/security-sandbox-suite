import os
import pickle
import base64
import subprocess
import urllib.request

import psycopg2
import redis
from flask import Flask, request, render_template, redirect, jsonify, session

# SAST finding: hardcoded credentials
DB_HOST = os.environ.get("DATABASE_URL", "postgresql://petshop:petshop123@localhost:5432/petshop")
SECRET_KEY = "BITS_AND_BYTES_SUPER_SECRET_KEY_2024"  # SAST finding: hardcoded secret
INTERNAL_API_TOKEN = "sk_live_dd_internal_api_token_never_commit"  # SAST finding

app = Flask(__name__)
app.secret_key = SECRET_KEY

TRACER_NAME = "dd-trace-py"
TRACER_VERSION = "2.6.0"


@app.before_request
def set_prefix():
    request.prefix = request.headers.get("X-Forwarded-Prefix", "")


@app.context_processor
def inject_prefix():
    return {"prefix": getattr(request, "prefix", "")}


def get_db():
    return psycopg2.connect(DB_HOST)


def get_redis():
    url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    return redis.from_url(url)


def query_db(sql, params=None, fetchone=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params)
    columns = [desc[0] for desc in cur.description] if cur.description else []
    if fetchone:
        row = cur.fetchone()
        result = dict(zip(columns, row)) if row else None
    else:
        result = [dict(zip(columns, row)) for row in cur.fetchall()]
    conn.close()
    return result


def exec_db(sql, params=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    conn.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    products = query_db("SELECT * FROM products ORDER BY id")
    return render_template("index.html", products=products, tracer=TRACER_NAME, version=TRACER_VERSION)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # VULNERABLE: SQL Injection via string concatenation
        sql = f"SELECT * FROM products WHERE name ILIKE '%{q}%' OR description ILIKE '%{q}%'"
        try:
            results = query_db(sql)
        except Exception as e:
            return render_template("search.html", q=q, results=[], error=str(e),
                                   tracer=TRACER_NAME, version=TRACER_VERSION)
    return render_template("search.html", q=q, results=results,
                           tracer=TRACER_NAME, version=TRACER_VERSION)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: SQL Injection via string formatting
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user = query_db(sql, fetchone=True)
            if user:
                session["user"] = user["username"]
                session["role"] = user["role"]
                return redirect(request.prefix + "/")
            else:
                error = "Invalid username or password"
        except Exception as e:
            error = str(e)
    return render_template("login.html", error=error, tracer=TRACER_NAME, version=TRACER_VERSION)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(request.prefix + "/")


@app.route("/product/<product_id>")
def product_detail(product_id):
    # VULNERABLE: SQL Injection (numeric, no quotes)
    sql = f"SELECT * FROM products WHERE id = {product_id}"
    try:
        product = query_db(sql, fetchone=True)
    except Exception as e:
        return render_template("error.html", error=str(e), tracer=TRACER_NAME, version=TRACER_VERSION), 400
    if not product:
        return render_template("error.html", error="Product not found", tracer=TRACER_NAME, version=TRACER_VERSION), 404
    reviews = query_db("SELECT * FROM reviews WHERE product_id = %s ORDER BY created_at DESC", (product["id"],))
    return render_template("product.html", product=product, reviews=reviews,
                           tracer=TRACER_NAME, version=TRACER_VERSION)


@app.route("/review", methods=["POST"])
def add_review():
    product_id = request.form.get("product_id")
    username = request.form.get("username", "anonymous")
    rating = request.form.get("rating", "5")
    body = request.form.get("body", "")
    # VULNERABLE: Stored XSS (body is stored and rendered without sanitization)
    exec_db(
        "INSERT INTO reviews (product_id, username, rating, body) VALUES (%s, %s, %s, %s)",
        (product_id, username, rating, body)
    )
    return redirect(f"{request.prefix}/product/{product_id}")


@app.route("/profile/<username>")
def profile(username):
    # VULNERABLE: Reflected XSS (username rendered directly in page)
    user = query_db("SELECT * FROM users WHERE username = %s", (username,), fetchone=True)
    return render_template("profile.html", username=username, user=user,
                           tracer=TRACER_NAME, version=TRACER_VERSION)


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "No file provided"}), 400
    # VULNERABLE: Path Traversal (user-controlled filename)
    filename = request.form.get("filename", uploaded.filename)
    save_path = os.path.join("/tmp/uploads", filename)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    uploaded.save(save_path)
    return jsonify({"message": f"Saved to {save_path}", "filename": filename})


@app.route("/webhook", methods=["POST"])
def webhook():
    url = request.form.get("url") or request.json.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    # VULNERABLE: SSRF (fetches arbitrary user-provided URL)
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        data = resp.read().decode("utf-8", errors="replace")[:2000]
        return jsonify({"status": resp.status, "body": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/export")
def export():
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "file parameter required"}), 400
    # VULNERABLE: Command Injection via shell=True
    try:
        result = subprocess.check_output(f"cat /tmp/uploads/{filename}", shell=True, timeout=5)
        return result, 200, {"Content-Type": "text/plain"}
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504


@app.route("/cart/restore", methods=["POST"])
def cart_restore():
    data = request.form.get("cart_data") or request.json.get("cart_data", "")
    if not data:
        return jsonify({"error": "cart_data required"}), 400
    # VULNERABLE: Insecure Deserialization (pickle)
    try:
        cart = pickle.loads(base64.b64decode(data))
        return jsonify({"cart": str(cart)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "petshop-python", "tracer": TRACER_NAME})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=False)
