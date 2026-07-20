import os
import sqlite3
import secrets
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 安全修复：强随机密钥
app.config["SECRET_KEY"] = secrets.token_hex(32)

# 安全修复：Cookie 安全属性
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# 安全修复：隐藏 Werkzeug 版本号
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "WebServer"
    return response


# ==================== 原有用户字典（登录用） ====================
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


# ==================== SQLite 数据库 ====================
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（明文密码，用于后续 SQL 注入演示）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成")


# ==================== 原有路由（保持功能不变） ====================

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


# ==================== 新增：注册功能（SQL 字符串拼接，不安全） ====================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # ✅ 安全修复：使用参数化查询，防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] 执行注册: username={username}, email={email}, phone={phone}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            print(f"[DB] 用户 {username} 注册成功")
            # 注册成功后跳转到登录页，传递成功消息
            return render_template("login.html", success="注册成功，请登录")
        except sqlite3.IntegrityError:
            error = f"用户名 '{username}' 已存在"
            return render_template("register.html", error=error)
        except Exception as e:
            error = f"注册失败: {e}"
            return render_template("register.html", error=error)
        finally:
            conn.close()

    return render_template("register.html")


# ==================== 新增：搜索功能（SQL 字符串拼接，不安全） ====================

@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()

    if not keyword:
        return render_template("index.html", user=USERS.get(session.get("username")),
                               search_results=[], search_keyword="")

    # ✅ 安全修复：使用参数化查询，防止 SQL 注入
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f"%{keyword}%"
    print(f"[SQL] 执行搜索: keyword={keyword}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(sql, (like_pattern, like_pattern))
        rows = c.fetchall()
        # 转换为字典列表
        results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
        print(f"[DB] 搜索结果: {len(results)} 条")
    except Exception as e:
        print(f"[DB] 搜索出错: {e}")
        results = []
    finally:
        conn.close()

    return render_template("index.html", user=USERS.get(session.get("username")),
                           search_results=results, search_keyword=keyword)


if __name__ == "__main__":
    init_db()
    # 安全修复：关闭 debug
    app.run(debug=False, host="0.0.0.0", port=5000)
