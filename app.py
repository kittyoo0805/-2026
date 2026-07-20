import os
import sqlite3
import time
import secrets
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ==================== 安全配置 ====================

# 修复1：强随机密钥，防止 Session 伪造
app.config["SECRET_KEY"] = secrets.token_hex(32)

# 修复2：Cookie 安全属性
app.config["SESSION_COOKIE_HTTPONLY"] = True     # 禁止 JS 读取 Cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # 防止 CSRF
# app.config["SESSION_COOKIE_SECURE"] = True      # 上 HTTPS 后开启

# 修复3：隐藏服务器指纹信息
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"                         # 防止点击劫持
    response.headers["X-Content-Type-Options"] = "nosniff"               # 禁止 MIME 嗅探
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"  # 防止 XSS
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "WebServer"                             # 隐藏版本号
    return response


# ==================== 用户数据库（内存字典，用于登录验证） ====================

# 修复4：密码哈希存储，而非明文
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


# ==================== SQLite 数据库（注册、搜索用） ====================

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
    # 插入默认用户
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


# ==================== 登录限流（防止暴力破解） ====================

# 修复5：内存计数器限流
LOGIN_LIMIT: dict[str, list[float]] = {}   # {ip: [timestamp1, timestamp2, ...]}


def check_login_limit(ip: str, max_attempts: int = 5, window: int = 60) -> bool:
    """检查 IP 在 window 秒内是否超过 max_attempts 次失败尝试"""
    now = time.time()
    if ip not in LOGIN_LIMIT:
        LOGIN_LIMIT[ip] = []
    # 清理过期记录
    LOGIN_LIMIT[ip] = [t for t in LOGIN_LIMIT[ip] if now - t < window]
    if len(LOGIN_LIMIT[ip]) >= max_attempts:
        return False
    return True


def record_failed_login(ip: str):
    """记录一次失败的登录尝试"""
    LOGIN_LIMIT.setdefault(ip, [])
    LOGIN_LIMIT[ip].append(time.time())


# ==================== 路由：首页 ====================

@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username)

    # 如果带搜索参数，调用搜索功能
    keyword = request.args.get("keyword", "").strip()
    search_results = []
    search_keyword = ""

    if keyword and username:
        # 修复6：参数化查询，防止 SQL 注入
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        print(f"[SQL] 执行搜索: keyword={keyword}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (like_pattern, like_pattern))
            rows = c.fetchall()
            search_results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
        except Exception as e:
            print(f"[DB] 搜索出错: {e}")
        finally:
            conn.close()
        search_keyword = keyword

    return render_template("index.html", user=user,
                           search_results=search_results, search_keyword=search_keyword)


# ==================== 路由：登录 ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"

        # 限流检查
        if not check_login_limit(client_ip):
            return render_template("login.html", error="登录尝试过于频繁，请 60 秒后再试"), 429

        # 修复4：哈希验证，而非明文比对
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            return render_template("index.html", user=user)

        record_failed_login(client_ip)
        success = request.args.get("success", "")
        error = "用户名或密码错误"
        return render_template("login.html", error=error, success=success)

    success = request.args.get("success", "")
    return render_template("login.html", success=success)


# ==================== 路由：注册 ====================

# 修复7：使用参数化查询注册 SQL，而非字符串拼接
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 参数化查询，防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] 执行注册: username={username}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            return redirect(url_for("login", success="注册成功，请登录"))
        except sqlite3.IntegrityError:
            error = f"用户名 '{username}' 已存在"
            return render_template("register.html", error=error)
        except Exception as e:
            error = f"注册失败: {e}"
            return render_template("register.html", error=error)
        finally:
            conn.close()

    return render_template("register.html")


# ==================== 路由：登出 ====================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ==================== 启动 ====================

if __name__ == "__main__":
    init_db()
    # 修复8：关闭 Debug 模式，防止远程代码执行
    app.run(debug=False, host="0.0.0.0", port=5000)
