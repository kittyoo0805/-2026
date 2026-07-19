from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)

# 安全修复：强随机密钥
app.config["SECRET_KEY"] = secrets.token_hex(32)

# 安全修复：Cookie 安全属性（内网测试临时关掉 Secure）
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True   # 上 HTTPS 后再开

# 安全修复：隐藏 Werkzeug 版本号
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "WebServer"
    return response

# 安全修复：密码哈希存储
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username)
    return render_template("index.html", user=user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 安全修复：哈希验证
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            return render_template("index.html", user=user)

        error = "用户名或密码错误"
        return render_template("login.html", error=error)

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # 安全修复：关闭 debug
    app.run(debug=False, host="0.0.0.0", port=5000)
